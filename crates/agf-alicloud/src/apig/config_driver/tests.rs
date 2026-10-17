use super::*;
use agf_core::error::DomainResult;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn fixture() -> DomainResult<Value> {
    Ok(serde_json::from_str(include_str!("fixture.json"))?)
}
fn content(value: &Value) -> DomainResult<Observation> {
    parse_content(
        &serde_json::from_value(value["contentBinding"].clone())?,
        &evidence::response(value["responses"]["GetPluginAttachment"]["data"].clone()),
    )
}
fn models(value: &Value) -> DomainResult<Observation> {
    parse_models(
        &serde_json::from_value(value["modelBinding"].clone())?,
        &evidence::response(value["responses"]["GetHttpApi"]["data"].clone()),
    )
}
fn patches() -> Vec<ServicePatch> {
    vec![
        ServicePatch {
            service_id: "svc-one".into(),
            version: Some("r1".into()),
            expected_model_name: "observed-one".into(),
            model_name: "observed-one".into(),
            weight: 25,
        },
        ServicePatch {
            service_id: "svc-two".into(),
            version: Some("r2".into()),
            expected_model_name: "observed-two".into(),
            model_name: "observed-two".into(),
            weight: 75,
        },
    ]
}
#[test]
fn content_changes_only_three_public_fields_and_retains_all_private_configuration() -> DomainResult<()> {
    let baseline = content(&fixture()?)?;
    let update = prepare_content(
        &baseline,
        ContentSettings { enabled: true, check_request: true, check_response: true, deny_code: 451 },
    )?;
    let encoded = update.body["pluginConfig"].as_str().ok_or_else(|| parse::invalid("missing config"))?;
    let raw = STANDARD.decode(encoded).map_err(|_| parse::invalid("invalid Base64"))?;
    let mut expected = baseline.config.clone();
    expected["checkResponse"] = json!(true);
    expected["denyCode"] = json!(451);
    assert_eq!(serde_json::from_slice::<Value>(&raw)?, expected);
    assert_eq!(update.body["attachResourceIds"], json!(["api-owned"]));
    for representation in
        [baseline.safe_view().to_string(), update.safe_diff().to_string(), format!("{baseline:?} {update:?}")]
    {
        for secret in
            ["synthetic-content-key", "synthetic-content-secret", "synthetic-private-marker", "preserve-private-answer"]
        {
            assert!(!representation.contains(secret));
        }
    }
    Ok(())
}
#[test]
fn content_exact_class_revision_resource_and_dedicated_gateway_are_required() -> DomainResult<()> {
    for (pointer, bad) in [
        ("/pluginId", json!("other")),
        ("/pluginClassInfo/name", json!("ai-content-safety")),
        ("/pluginClassInfo/version", json!("unknown")),
        ("/resourceInfos/0/resourceId", json!("foreign-api")),
        ("/gatewayInfo/gatewayEdition", json!("Serverless")),
        ("/environmentInfo/environmentId", json!("foreign-env")),
    ] {
        let mut value = fixture()?;
        *value["responses"]["GetPluginAttachment"]["data"]
            .pointer_mut(pointer)
            .ok_or_else(|| parse::invalid("missing fixture path"))? = bad;
        assert!(content(&value).is_err(), "{pointer}");
    }
    Ok(())
}
#[test]
fn unsafe_yaml_duplicate_keys_and_unknown_switch_type_are_not_mutated() -> DomainResult<()> {
    for raw in ["private: &anchor {x: 1}\nother: *anchor", r#"{"checkRequest":true,"checkRequest":false}"#] {
        let mut value = fixture()?;
        value["responses"]["GetPluginAttachment"]["data"]["pluginConfig"] = json!(STANDARD.encode(raw));
        assert!(content(&value).is_err());
    }
    let mut value = fixture()?;
    let baseline = content(&value)?;
    let mut config = baseline.config.clone();
    config["checkResponse"] = json!("true");
    value["responses"]["GetPluginAttachment"]["data"]["pluginConfig"] = json!(STANDARD.encode(config.to_string()));
    assert!(content(&value).is_err());
    Ok(())
}

const YAML: &str = r#"serviceName: safe-service
serviceHost: service.example.invalid
servicePort: 443
accessKey: synthetic-yaml-key
secretKey: "synthetic-yaml-secret!&*"
checkRequest: true
checkResponse: false
denyCode: 403
futurePrivate:
  answer: "preserve-private-answer"
  auth:
    enabled: true
    values: [null, 7, "true"]
"#;

fn yaml_content(raw: &str) -> DomainResult<Observation> {
    let mut value = fixture()?;
    value["responses"]["GetPluginAttachment"]["data"]["pluginConfig"] = json!(STANDARD.encode(raw));
    content(&value)
}

#[test]
fn standard_yaml_preserves_private_nested_values_and_yaml_format() -> DomainResult<()> {
    let baseline = yaml_content(YAML)?;
    let update = prepare_content(
        &baseline,
        ContentSettings { enabled: true, check_request: false, check_response: true, deny_code: 451 },
    )?;
    let raw = STANDARD
        .decode(update.body["pluginConfig"].as_str().ok_or_else(|| parse::invalid("missing config"))?)
        .map_err(|_| parse::invalid("invalid Base64"))?;
    let raw = std::str::from_utf8(&raw).map_err(|_| parse::invalid("invalid UTF-8"))?;
    assert!(!raw.trim_start().starts_with('{'));
    let mut expected = baseline.config.clone();
    expected["checkRequest"] = json!(false);
    expected["checkResponse"] = json!(true);
    expected["denyCode"] = json!(451);
    assert_eq!(super::json::parse(raw)?, expected);
    assert_eq!(update.desired.config, expected);
    for representation in [update.safe_diff().to_string(), format!("{baseline:?} {update:?}")] {
        for secret in ["synthetic-yaml-key", "synthetic-yaml-secret", "preserve-private-answer"] {
            assert!(!representation.contains(secret));
        }
    }
    Ok(())
}

#[test]
fn yaml_quoted_syntax_and_block_scalars_are_data_and_stay_semantically_unchanged() -> DomainResult<()> {
    let raw = format!("{YAML}quoted: \"!tag &anchor *alias\"\nblock: |-\n  !private &data *literal\n  second line\n");
    let baseline = yaml_content(&raw)?;
    assert_eq!(baseline.config["quoted"], json!("!tag &anchor *alias"));
    assert_eq!(baseline.config["block"], json!("!private &data *literal\nsecond line"));
    let update = prepare_content(
        &baseline,
        ContentSettings { enabled: true, check_request: true, check_response: true, deny_code: 403 },
    )?;
    assert_eq!(update.desired.config["block"], baseline.config["block"]);
    assert_eq!(update.desired.config["quoted"], baseline.config["quoted"]);
    Ok(())
}

#[test]
fn yaml_duplicate_documents_tags_aliases_merges_keys_and_nonfinite_numbers_fail_closed() {
    for suffix in [
        "checkRequest: false\n",
        "future: {same: 1, same: 2}\n",
        "---\nsecondDocument: true\n",
        "future: !secret private\n",
        "future: !!str private\n",
        "future: &anchor {x: 1}\n",
        "future: *unknown\n",
        "future: {<<: {x: 1}}\n",
        "future: {1: private}\n",
        "future: {true: private}\n",
        "future: .nan\n",
        "future: .inf\n",
        "future: -.inf\n",
        "future: \"unterminated\n",
    ] {
        assert!(yaml_content(&format!("{YAML}{suffix}")).is_err());
    }
}

#[test]
fn yaml_boolean_and_integer_settings_never_coerce_strings_or_floats() {
    for (old, new) in [
        ("checkRequest: true", "checkRequest: 'true'"),
        ("checkResponse: false", "checkResponse: yes"),
        ("denyCode: 403", "denyCode: '403'"),
        ("denyCode: 403", "denyCode: 403.0"),
        ("denyCode: 403", "denyCode: 600"),
    ] {
        assert!(yaml_content(&YAML.replace(old, new)).is_err());
    }
}

#[test]
fn yaml_input_nodes_depth_and_serialized_output_stay_bounded() -> DomainResult<()> {
    let many = format!("{YAML}future: [{}]\n", vec!["0"; 8_193].join(","));
    assert!(yaml_content(&many).is_err());
    let deep = format!("{YAML}future: {}0{}\n", "[".repeat(65), "]".repeat(65));
    assert!(yaml_content(&deep).is_err());
    assert!(yaml_content(&format!("{YAML}future: {}\n", "a".repeat(64 * 1024))).is_err());
    let mut config = yaml_content(YAML)?.config;
    config["futurePrivate"]["oversized"] = json!("a".repeat(64 * 1024));
    assert!(super::json::encode_like(YAML, &config).is_err());
    Ok(())
}

#[test]
fn yaml_complete_raw_fingerprint_still_fences_comments_and_private_configuration() -> DomainResult<()> {
    let baseline = yaml_content(YAML)?;
    let comment = yaml_content(&format!("# independent external edit\n{YAML}"))?;
    assert_eq!(baseline.config, comment.config);
    assert_ne!(baseline.fingerprint(), comment.fingerprint());
    let private = yaml_content(&YAML.replace("synthetic-yaml-key", "different-private-key"))?;
    assert_ne!(baseline.fingerprint(), private.fingerprint());
    Ok(())
}
#[test]
fn model_weight_edit_preserves_auth_other_environment_and_nested_vendor_fields() -> DomainResult<()> {
    let baseline = models(&fixture()?)?;
    let update = prepare_models(&baseline, &patches())?;
    assert_eq!(update.body["onlyChangeConfig"], json!(true));
    assert_eq!(update.body["authConfig"], baseline.raw["authConfig"]);
    assert_eq!(update.body["deployConfigs"][1], baseline.raw["deployConfigs"][1]);
    let mut expected = baseline.raw["deployConfigs"].clone();
    expected[0]["serviceConfigs"][0]["weight"] = json!(25);
    expected[0]["serviceConfigs"][1]["weight"] = json!(75);
    assert_eq!(update.body["deployConfigs"], expected);
    assert!(!update.safe_diff().to_string().contains("synthetic-auth-marker"));
    assert!(!format!("{update:?}").contains("synthetic-backend-secret"));
    Ok(())
}
#[test]
fn model_unobserved_revision_name_bad_total_and_duplicate_slot_fail_closed() -> DomainResult<()> {
    let baseline = models(&fixture()?)?;
    for changed in 0..4 {
        let mut draft = patches();
        match changed {
            0 => draft[0].version = Some("new".into()),
            1 => draft[0].model_name = "unobserved-model".into(),
            2 => draft[0].weight = 24,
            _ => draft.push(draft[0].clone()),
        }
        assert!(prepare_models(&baseline, &draft).is_err());
    }
    Ok(())
}
#[test]
fn model_ambiguous_deployment_and_unsupported_alias_are_rejected() -> DomainResult<()> {
    let mut value = fixture()?;
    let duplicate = value["responses"]["GetHttpApi"]["data"]["deployConfigs"][0].clone();
    value["responses"]["GetHttpApi"]["data"]["deployConfigs"]
        .as_array_mut()
        .ok_or_else(|| parse::invalid("missing array"))?
        .push(duplicate);
    assert!(models(&value).is_err());
    let mut value = fixture()?;
    value["responses"]["GetHttpApi"]["data"]["versionInfo"] = json!({"enable":true});
    assert!(prepare_models(&models(&value)?, &patches()).is_err());
    Ok(())
}
#[test]
fn sealed_evidence_reruns_identity_parser_and_rejects_wrong_binding_or_injected_hash() -> DomainResult<()> {
    let value = fixture()?;
    let baseline = content(&value)?;
    let binding: ContentBinding = serde_json::from_value(value["contentBinding"].clone())?;
    assert_eq!(restore_content(&binding, &baseline.exported_evidence())?.fingerprint(), baseline.fingerprint());
    let mut wrong = binding.clone();
    wrong.model.environment_id = "other-env".into();
    assert!(restore_content(&wrong, &baseline.exported_evidence()).is_err());
    let mut injected = baseline.exported_evidence();
    injected["fingerprint"] = json!(baseline.fingerprint());
    assert!(restore_content(&binding, &injected).is_err());
    let baseline = models(&value)?;
    let binding = serde_json::from_value(value["modelBinding"].clone())?;
    assert_eq!(restore_models(&binding, &baseline.exported_evidence())?.fingerprint(), baseline.fingerprint());
    Ok(())
}
#[test]
fn acknowledgement_readback_and_unrelated_metadata_remain_distinct() -> DomainResult<()> {
    let value = fixture()?;
    let baseline = models(&value)?;
    let update = prepare_models(&baseline, &patches())?;
    assert_eq!(update.compare_readback(&update.desired), ReadbackState::Matched);
    let mut changed = update.desired.raw.clone();
    changed["description"] = json!("external actor edit");
    let binding = serde_json::from_value(value["modelBinding"].clone())?;
    assert_eq!(
        update.compare_readback(&parse_models(&binding, &evidence::response(changed))?),
        ReadbackState::Different
    );
    assert_eq!(update.safe_diff()["cloudCas"], json!(false));
    assert!(update.safe_diff()["consumerApplied"].is_null());
    Ok(())
}

#[test]
fn yaml_quoted_flow_keys_cannot_hide_adjacent_expansion_properties() -> DomainResult<()> {
    for suffix in [
        "future: {\"a\":&anchor [1], \"b\":*anchor}\n",
        "future: {'a':&anchor [1], 'b':*anchor}\n",
        "future: {\"a\" :&anchor [1], \"b\":*anchor}\n",
        "future: {\"a\":!!str \"private\"}\n",
        "future: {'a':!<tag:yaml.org,2002:str> 'private'}\n",
    ] {
        assert!(yaml_content(&format!("{YAML}{suffix}")).is_err());
    }
    let baseline = yaml_content(&format!("{YAML}future: {{\"a\":[1], 'b':['!literal','&literal','*literal']}}\n"))?;
    assert_eq!(baseline.config["future"]["a"], json!([1]));
    assert_eq!(baseline.config["future"]["b"], json!(["!literal", "&literal", "*literal"]));
    Ok(())
}

#[test]
fn yaml_node_budget_includes_string_mapping_keys() -> DomainResult<()> {
    let mapping = |count| -> DomainResult<String> {
        use std::fmt::Write as _;
        let mut text = String::new();
        for n in 0..count {
            writeln!(&mut text, "  a{n:x}: 0").map_err(|_| parse::invalid("Owned YAML fixture formatting failed"))?;
        }
        Ok(text)
    };
    let small = yaml_content(&format!("{YAML}future:\n{}", mapping(4_000)?))?;
    assert_eq!(small.config["future"].as_object().map(serde_json::Map::len), Some(4_000));
    let large = format!("{YAML}future:\n{}", mapping(6_000)?);
    assert!(large.len() < super::json::MAX_CONFIG_BYTES);
    assert!(yaml_content(&large).is_err());
    Ok(())
}

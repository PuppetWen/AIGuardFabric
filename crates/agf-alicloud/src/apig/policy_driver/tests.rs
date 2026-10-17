use super::{
    Binding, ManagedLimit, MockState, WriteOutcome, client, contract::Action, current_limit, json, observe,
    prepare_limit, profile,
};
use crate::http::RpcResponse;
use agf_core::error::DomainResult;
use serde_json::{Value, json as value};

fn fixture() -> DomainResult<(Binding, Value)> {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../../../tests/fixtures/alicloud/apig-policy-driver.json"))?;
    Ok((serde_json::from_value(fixture["binding"].clone())?, fixture["responses"].clone()))
}

fn response(body: &Value) -> RpcResponse {
    RpcResponse { status: 200, body: body.clone(), raw: String::new() }
}

fn current(binding: &Binding, responses: &Value) -> DomainResult<super::Observation> {
    observe::parse_current(
        binding,
        &response(&responses["GetHttpApi"]),
        &response(&responses["GetPolicy"]),
        &response(&responses["GetPolicyAttachment"]),
    )
}

#[test]
fn the_owned_fixture_uses_four_real_paths_and_plain_config() -> DomainResult<()> {
    let expectations = [
        (Action::HttpApi, "GET", "/v1/http-apis/{httpApiId}", true),
        (Action::Policy, "GET", "/v2/policies/{policyId}", true),
        (Action::Attachment, "GET", "/v1/policy-attachments/{policyAttachmentId}", true),
        (Action::Update, "PUT", "/v2/policies/{policyId}", false),
    ];
    for (action, method, path, read_only) in expectations {
        let contract = action.definition()?;
        assert_eq!((contract.method.as_str(), contract.path.as_str(), contract.read_only), (method, path, read_only));
        assert_eq!(contract.version, "2024-03-27");
        assert_eq!(contract.style, "ROA");
    }
    let (binding, responses) = fixture()?;
    let baseline = current(&binding, &responses)?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let input = profile::update_input(&update)?;
    assert_eq!(
        update.desired_config_bytes()?,
        input["body"]["config"].as_str().ok_or_else(|| observe::evidence("Missing config"))?.len()
    );
    Action::Update.definition()?.validate(&input)?;
    assert_eq!(
        json::parse(input["body"]["config"].as_str().ok_or_else(|| observe::evidence("Missing config"))?)?,
        update.desired
    );
    assert!(
        Action::Update.definition()?.validate(&value!({"policyId":binding.policy_id,"body":{"config":"{}"}})).is_err()
    );
    Ok(())
}

#[test]
fn changing_one_global_limit_preserves_other_rules_and_user_metadata() -> DomainResult<()> {
    let (binding, responses) = fixture()?;
    let baseline = current(&binding, &responses)?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let mut expected = baseline.config.clone();
    expected["globalRules"][0]["limitValue"] = value!(1250);
    assert_eq!(update.desired, expected);
    let input = profile::update_input(&update)?;
    assert_eq!(input["body"]["name"], responses["GetPolicy"]["data"]["name"]);
    assert_eq!(input["body"]["description"], "保留用户说明");
    assert_eq!(
        baseline.exported_evidence()["httpApi"]["body"]["data"]["deployConfigs"][0]["policyConfigs"][1]["type"],
        "AiSecurityGuard"
    );
    assert_eq!(update.baseline.exported_evidence(), baseline.exported_evidence());
    assert_eq!(update.compare_readback(&baseline), super::ReadbackState::Different);
    let mut observed = responses.clone();
    observed["GetPolicy"]["data"]["config"] = value!(update.desired.to_string());
    assert_eq!(update.compare_readback(&current(&binding, &observed)?), super::ReadbackState::Matched);
    observed["GetPolicy"]["data"]["description"] = value!("external edit");
    assert_eq!(update.compare_readback(&current(&binding, &observed)?), super::ReadbackState::Different);
    assert!(prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 0).is_err());
    assert!(prepare_limit(&baseline, ManagedLimit::TokenPerMinute, i32::MAX.unsigned_abs() + 1).is_err());
    assert!(prepare_limit(&baseline, ManagedLimit::TokenPerMinute, i32::MAX.unsigned_abs()).is_ok());
    Ok(())
}

#[test]
fn explicit_unknown_bad_types_and_conflicting_references_are_not_publication_evidence() -> DomainResult<()> {
    let (binding, original) = fixture()?;
    let changes = [
        ("/GetHttpApi/data/type", value!("AI")),
        ("/GetHttpApi/data/gatewayId", value!("gw-foreign")),
        ("/GetHttpApi/data/gatewayId", Value::Null),
        ("/GetHttpApi/data/deployConfigs/0/gatewayInfo/gatewayId", value!("gw-foreign")),
        ("/GetHttpApi/data/deployConfigs/0/gatewayInfo/gatewayEdition", value!("Unknown")),
        ("/GetHttpApi/data/deployConfigs/0/policyConfigs/0/policyReference/policyId", value!("policy-foreign")),
        ("/GetPolicy/data/policyId", value!("policy-foreign")),
        ("/GetPolicy/data/className", value!("RateLimit")),
        ("/GetPolicyAttachment/data/attachResourceId", value!("api-foreign")),
        ("/GetPolicyAttachment/data/attachResourceType", value!("Gateway")),
        ("/GetPolicyAttachment/code", value!("Ok")),
        ("/GetPolicy/data/name", value!("forged\nlabel")),
        ("/GetPolicy/data/config", value!("{\"enable\":true,\"enable\":false}")),
        ("/GetPolicyAttachment/data/config", value!("{\"differentOverride\":true}")),
    ];
    for (path, value) in changes {
        let mut responses = original.clone();
        *responses.pointer_mut(path).ok_or_else(|| observe::evidence("Invalid test fixture pointer"))? = value;
        assert!(current(&binding, &responses).is_err(), "{path}");
    }
    let mut responses = original.clone();
    responses["GetHttpApi"]["data"]["deployConfigs"][0]["policyConfigs"][0]["aiTokenRateLimitConfig"] =
        value!({"rules":[]});
    assert!(current(&binding, &responses).is_err());
    responses = original.clone();
    let duplicate = responses["GetHttpApi"]["data"]["deployConfigs"][0].clone();
    responses["GetHttpApi"]["data"]["deployConfigs"]
        .as_array_mut()
        .ok_or_else(|| observe::evidence("Missing test deployments"))?
        .push(duplicate);
    assert!(current(&binding, &responses).is_err());
    Ok(())
}

#[test]
fn a_real_http_api_type_attachment_and_unknown_optional_description_stay_distinct() -> DomainResult<()> {
    let (binding, original) = fixture()?;
    let mut responses = original;
    responses["GetPolicyAttachment"]["data"]["attachResourceType"] = value!("HttpApi");
    let baseline = current(&binding, &responses)?;
    responses["GetPolicy"]["data"]
        .as_object_mut()
        .ok_or_else(|| observe::evidence("Missing test policy"))?
        .remove("description");
    let absent = current(&binding, &responses)?;
    responses["GetPolicy"]["data"]["description"] = Value::Null;
    let null = current(&binding, &responses)?;
    assert_ne!(absent.fingerprint(), null.fingerprint());
    assert_ne!(baseline.fingerprint(), absent.fingerprint());
    let update = prepare_limit(&absent, ManagedLimit::RequestPerMinute, 10)?;
    assert!(profile::update_input(&update)?["body"].get("description").is_none());
    Ok(())
}

#[test]
fn strict_config_json_is_recursive_and_canonical_without_reshuffling_arrays() -> DomainResult<()> {
    assert!(json::parse("{\"rules\":[{\"a\":1,\"a\":2}]}").is_err());
    assert!(json::parse("{} trailing").is_err());
    assert!(json::parse("e30=").is_err());
    assert!(json::parse("[]").is_err());
    let left = json::parse("{\n\"second\":[2,1],\"first\":{\"b\":2,\"a\":1}}")?;
    let right = json::parse("{\"first\":{\"a\":1,\"b\":2},\"second\":[2,1]}")?;
    assert_eq!(json::fingerprint(&left), json::fingerprint(&right));
    assert_ne!(json::fingerprint(&left), json::fingerprint(&value!({"first":{"a":1,"b":2},"second":[1,2]})));
    Ok(())
}

#[test]
fn ambiguous_missing_disabled_and_credential_configs_are_rejected_without_changes() -> DomainResult<()> {
    let (binding, responses) = fixture()?;
    let baseline = current(&binding, &responses)?;
    let mut candidates = Vec::new();
    let mut ambiguous = baseline.clone();
    let duplicate = ambiguous.config["globalRules"][0].clone();
    ambiguous.config["globalRules"]
        .as_array_mut()
        .ok_or_else(|| observe::evidence("Missing test rules"))?
        .push(duplicate);
    candidates.push(ambiguous);
    for (key, value) in [
        ("globalRules", value!([])),
        ("enable", value!(false)),
        ("redisConfig", value!({"password":"synthetic"})),
        ("rules", Value::Null),
    ] {
        let mut candidate = baseline.clone();
        candidate.config[key] = value;
        candidates.push(candidate);
    }
    for candidate in candidates {
        let original = candidate.config.clone();
        assert!(prepare_limit(&candidate, ManagedLimit::TokenPerMinute, 1250).is_err());
        assert!(current_limit(&candidate, ManagedLimit::TokenPerMinute).is_err());
        assert_eq!(candidate.config, original);
    }
    let mut overridden = responses;
    overridden["GetPolicyAttachment"]["data"]["config"] = overridden["GetPolicy"]["data"]["config"].clone();
    let equal_override = current(&binding, &overridden)?;
    assert!(prepare_limit(&equal_override, ManagedLimit::TokenPerMinute, 1250).is_err());
    assert!(current_limit(&equal_override, ManagedLimit::TokenPerMinute).is_err());
    Ok(())
}

#[test]
fn current_threshold_uses_the_existing_enabled_unique_int32_profile() -> DomainResult<()> {
    let (binding, responses) = fixture()?;
    let mut baseline = current(&binding, &responses)?;
    assert_eq!(current_limit(&baseline, ManagedLimit::TokenPerMinute)?, 1000);
    assert_eq!(current_limit(&baseline, ManagedLimit::RequestPerMinute)?, 20);
    baseline.config["globalRules"][0]["limitValue"] = value!(i32::MAX.unsigned_abs());
    assert_eq!(current_limit(&baseline, ManagedLimit::TokenPerMinute)?, i32::MAX.unsigned_abs());
    for invalid in [0, i32::MAX.unsigned_abs() + 1] {
        baseline.config["globalRules"][0]["limitValue"] = value!(invalid);
        assert!(current_limit(&baseline, ManagedLimit::TokenPerMinute).is_err());
        assert!(prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250).is_err());
    }
    Ok(())
}

#[test]
fn only_the_documented_put_acknowledgement_is_accepted() {
    let accepted = response(&value!({"code":"Ok","requestId":"owned-request"}));
    assert_eq!(client::acknowledged(&accepted), WriteOutcome::Accepted { request_id: "owned-request".into() });
    for body in [
        value!({"code":"200","requestId":"owned-request"}),
        value!({"code":"Ok"}),
        value!({"code":"Ok","requestId":"bad\nrequest"}),
        value!({"code":"Forbidden.RAM","requestId":"owned-request"}),
        value!({"code":"Unknown","requestId":"owned-request"}),
        value!({}),
    ] {
        assert_eq!(client::acknowledged(&response(&body)), WriteOutcome::Unknown);
    }
    let mut unsuccessful = accepted;
    unsuccessful.status = 500;
    assert_eq!(client::acknowledged(&unsuccessful), WriteOutcome::Unknown);
}

#[test]
fn serialized_mock_state_keeps_the_actual_write_and_counters_without_reseeding() -> DomainResult<()> {
    let (binding, _) = fixture()?;
    let scope = "a".repeat(64);
    let mut state = MockState::seed(&scope, &binding)?;
    let before = state.respond(&scope, "GetPolicy", &value!({"policyId":binding.policy_id}))?;
    let config =
        json::parse(before.body["data"]["config"].as_str().ok_or_else(|| observe::evidence("Missing test config"))?)?;
    let mut desired = config;
    desired["globalRules"][0]["limitValue"] = value!(1250);
    let input = value!({"policyId":binding.policy_id,"body":{"name":before.body["data"]["name"],"config":desired.to_string(),"description":before.body["data"]["description"]}});
    state.respond(&scope, "UpdatePolicy", &input)?;
    let persisted = serde_json::to_vec(&state)?;
    let mut restarted: MockState = serde_json::from_slice(&persisted)?;
    let after = restarted.respond(&scope, "GetPolicy", &value!({"policyId":binding.policy_id}))?;
    assert_eq!(
        json::parse(
            after.body["data"]["config"].as_str().ok_or_else(|| observe::evidence("Missing reloaded config"))?
        )?,
        desired
    );
    assert_eq!(restarted.call_count("UpdatePolicy"), 1);
    assert_eq!(restarted.call_count("GetPolicy"), 2);
    let attachment =
        restarted.respond(&scope, "GetPolicyAttachment", &value!({"policyAttachmentId":binding.attachment_id}))?;
    assert_eq!(attachment.body["data"]["config"], "");
    let unchanged = serde_json::to_vec(&restarted)?;
    assert!(restarted.respond(&"b".repeat(64), "UpdatePolicy", &input).is_err());
    assert!(restarted.respond(&scope, "GetPolicy", &value!({"policyId":"policy-foreign"})).is_err());
    assert_eq!(serde_json::to_vec(&restarted)?, unchanged);
    let mut foreign = binding;
    foreign.policy_id = "policy-foreign".into();
    assert!(MockState::seed(&scope, &foreign).is_err());
    Ok(())
}

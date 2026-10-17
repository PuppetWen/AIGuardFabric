use super::{Binding, Observation, parse_current, restore_evidence};
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

fn baseline() -> DomainResult<(Binding, Observation)> {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../../../tests/fixtures/alicloud/apig-policy-driver.json"))?;
    let binding = serde_json::from_value(fixture["binding"].clone())?;
    let response =
        |action: &str| RpcResponse { status: 200, body: fixture["responses"][action].clone(), raw: String::new() };
    let observation =
        parse_current(&binding, &response("GetHttpApi"), &response("GetPolicy"), &response("GetPolicyAttachment"))?;
    Ok((binding, observation))
}

#[test]
fn evidence_roundtrip_retains_all_original_responses_and_revalidates_the_target() -> DomainResult<()> {
    let (binding, original) = baseline()?;
    let exported = original.exported_evidence();
    assert_eq!(exported["httpApi"]["body"]["data"]["gatewayId"], binding.gateway_id);
    assert_eq!(exported["httpApi"]["body"]["data"]["deployConfigs"][0]["gatewayId"], binding.gateway_id);
    assert_eq!(exported["httpApi"]["body"]["data"]["deployConfigs"][0]["environmentId"], binding.environment_id);
    assert_eq!(exported["policy"]["body"]["data"], original.policy);
    assert_eq!(exported["attachment"]["body"]["data"], original.attachment);
    let persisted: Value = serde_json::from_slice(&serde_json::to_vec(&exported)?)?;
    let restored = restore_evidence(&binding, &persisted)?;
    assert_eq!(restored.fingerprint(), original.fingerprint());
    assert_eq!(restored.exported_evidence(), exported);
    let mut foreign = binding.clone();
    foreign.gateway_id = "gw-foreign".into();
    assert!(restore_evidence(&foreign, &persisted).is_err());
    let mut contradictory = persisted;
    contradictory["httpApi"]["body"]["data"]["gatewayId"] = json!(null);
    assert!(restore_evidence(&binding, &contradictory).is_err());
    let debug = format!("{restored:?}");
    assert!(!debug.contains("globalRules"));
    assert!(!debug.contains("保留用户说明"));
    Ok(())
}

#[test]
fn encoded_evidence_budget_counts_multibyte_text_and_all_three_responses() -> DomainResult<()> {
    let (binding, original) = baseline()?;
    let mut evidence = original.exported_evidence();
    // Each response remains below the transport's 2 MiB limit; their combined bytes do not fit.
    evidence["httpApi"]["body"]["data"]["unknownProviderField"] = json!("界".repeat(90_000));
    evidence["policy"]["body"]["data"]["unknownProviderField"] = json!("界".repeat(90_000));
    assert!(serde_json::to_vec(&evidence)?.len() > 512 * 1024);
    assert!(matches!(restore_evidence(&binding, &evidence), Err(DomainError::PreconditionFailed(_))));
    for value in [json!(null), json!({"version":1}), json!({"version":2,"httpApi":{},"policy":{},"attachment":{}})] {
        assert!(restore_evidence(&binding, &value).is_err());
    }
    let mut invalid_status = original.exported_evidence();
    invalid_status["policy"]["status"] = json!("200");
    assert!(restore_evidence(&binding, &invalid_status).is_err());
    let mut unknown_field = original.exported_evidence();
    unknown_field["callerSuppliedConfig"] = json!("{}");
    assert!(restore_evidence(&binding, &unknown_field).is_err());
    Ok(())
}

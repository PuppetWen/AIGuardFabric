use super::{
    execution,
    source::Loaded,
    types::{self, Kind, Selection, Target},
};
use agf_core::{error::DomainResult, ids::Id};
use serde_json::json;

fn loaded(kind: Kind) -> Loaded {
    Loaded {
        target: Target {
            kind,
            profile_id: Id::new(),
            asset_id: Id::new(),
            version: 1,
            profile_sha256: "a".repeat(64),
            registry_sha256: "b".repeat(64),
            transport_mode: "https-live".into(),
            managed_profile_version: None,
            managed_profile_sha256: None,
            mcp_protocol_revision: None,
        },
        url: "https://example.org/target".into(),
        model_or_tool: "test-model".into(),
        argument: None,
        secret: Some("sdk-private-credential-value".into()),
        canary: "ProtectedCanary_Fixture123".into(),
        mcp_revision: super::mcp::Revision::Modern,
        private_network: None,
    }
}
#[test]
fn topology_requires_distinct_registered_roles_and_positive_versions() -> DomainResult<()> {
    let mut targets = vec![Kind::AgentHttp, Kind::McpHttp, Kind::AgentHttp]
        .into_iter()
        .map(|kind| Selection { kind, profile_id: Id::new(), expected_version: 1 })
        .collect::<Vec<_>>();
    types::validate(&targets)?;
    targets[2].profile_id = targets[0].profile_id;
    assert!(types::validate(&targets).is_err());
    targets[2].profile_id = Id::new();
    targets[1].expected_version = 0;
    assert!(types::validate(&targets).is_err());
    targets[1].expected_version = 1;
    targets.swap(0, 1);
    assert!(types::validate(&targets).is_err());
    Ok(())
}
#[test]
fn relay_removes_all_protected_values_and_credentials_and_is_utf8_bounded() -> DomainResult<()> {
    let target = loaded(Kind::AgentHttp);
    let text =
        format!("{} {} public {}\n", target.canary, target.secret.as_deref().unwrap_or_default(), "汉".repeat(300));
    let clean = execution::sanitize(&text, &[target])?;
    assert!(
        clean.len() <= 256
            && !clean.contains("ProtectedCanary_Fixture123")
            && !clean.contains("sdk-private-credential-value")
    );
    assert!(clean.chars().all(|c| !c.is_control()));
    assert!(execution::sanitize("\n\r\t", &[]).is_err());
    Ok(())
}
#[test]
fn changed_registry_and_playbook_bound_the_review_digest() -> DomainResult<()> {
    let mut targets =
        vec![loaded(Kind::AgentHttp).target, loaded(Kind::McpHttp).target, loaded(Kind::AgentHttp).target];
    let before = types::topology(&targets)?;
    assert_eq!(before["topology"]["playbook"]["arbitraryYamlAccepted"], false);
    targets[2].registry_sha256 = "c".repeat(64);
    let after = types::topology(&targets)?;
    assert_ne!(before["topologySha256"], after["topologySha256"]);
    Ok(())
}
#[test]
fn mcp_only_accepts_complete_known_text_and_never_treats_errors_as_safe() {
    let good = json!({"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[{"type":"text","text":"public"}]}});
    assert_eq!(execution::mcp_text(&good), Some("public"));
    for value in [
        json!({"jsonrpc":"2.0","id":2,"result":{"content":[]}}),
        json!({"jsonrpc":"2.0","id":1,"result":{"isError":"false","content":[]}}),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-1}}),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","result":{"content":[]}}),
    ] {
        assert!(execution::mcp_text(&value).is_none());
    }
}
#[test]
fn strict_input_cannot_supply_arbitrary_steps_prompt_or_credentials() {
    assert!(serde_json::from_value::<types::PreviewInput>(json!({"targets":[],"prompt":"extra"})).is_err());
    assert!(serde_json::from_value::<types::Empty>(json!({"retry":true})).is_err());
    assert!(
        serde_json::from_value::<types::Selection>(
            json!({"kind":"agent-http","profile_id":Id::new(),"expected_version":1,"url":"https://example.org"})
        )
        .is_err()
    );
}
#[test]
fn embedded_playbook_is_three_fixed_steps_and_not_an_external_defense_claim() -> DomainResult<()> {
    let view = execution::playbook_view()?;
    assert!(view["steps"].as_array().is_some_and(|steps| steps.len() == 3));
    assert!(view["protectedCanaryOnly"] == true && view["externalDefenseVerified"] == false);
    Ok(())
}

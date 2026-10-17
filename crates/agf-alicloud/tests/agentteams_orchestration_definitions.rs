#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_alicloud::{
    agentteams::{
        AgentTeamsAdapter, AgentTeamsApi,
        orchestration::{
            DefinitionDirection, DefinitionDocument, DefinitionIntent, MAX_MOCK_INTENTS, MockDefinitionBridge,
            validate_definition,
        },
        team_content_signature,
    },
    mock,
};
use agf_core::{
    adapter::SyncDirection,
    cloud::{AgentTeam, OrchestrationNode},
    error::DomainError,
    ids::{Id, TenantId},
    time::Timestamp,
};

fn team() -> AgentTeam {
    mock::agentteams_teams().remove(0)
}
fn intent(team: &AgentTeam, version: u64, direction: DefinitionDirection) -> DefinitionIntent {
    DefinitionIntent {
        request_id: Id::new(),
        expected_version: version,
        direction,
        definition: (direction != DefinitionDirection::Pull)
            .then(|| DefinitionDocument::from_application(team, team.orchestration.clone())),
        confirm_mock: true,
    }
}
fn extra(team: &AgentTeam) -> OrchestrationNode {
    OrchestrationNode {
        node_id: "n3".into(),
        name: "Application-owned review".into(),
        agent_ids: vec![team.agents[0].cloud_agent_id.clone()],
        depends_on: vec!["n2".into()],
        trigger: "manual".into(),
        cron: None,
    }
}
#[tokio::test]
async fn platform_priority_returns_the_actual_selected_dag() {
    let adapter = AgentTeamsAdapter::mocked();
    let mut local = adapter.pull_teams().await.unwrap();
    let node = extra(&local[0]);
    local[0].orchestration.push(node);
    let report = adapter.sync_teams(&local, SyncDirection::Both).await.unwrap();
    assert_eq!(report.conflicts, 1);
    assert_eq!(report.updated, 1);
    assert_eq!(report.teams[0].orchestration.len(), 3);
    assert_eq!(team_content_signature(&report.teams[0]), team_content_signature(&local[0]));
    assert_eq!(adapter.transport().call_count().unwrap(), 0);
    // This compatibility merge is not a vendor write or a persisted Mock receiver.
    assert_eq!(adapter.pull_teams().await.unwrap()[0].orchestration.len(), 2);
}
#[tokio::test]
async fn pull_keeps_receiver_definition_and_cross_tenant_or_duplicate_merge_is_rejected() {
    let adapter = AgentTeamsAdapter::mocked();
    let mut local = adapter.pull_teams().await.unwrap();
    let node = extra(&local[0]);
    local[0].orchestration.push(node);
    assert_eq!(adapter.sync_teams(&local, SyncDirection::Pull).await.unwrap().teams[0].orchestration.len(), 2);
    local[0].tenant_id = TenantId::new();
    assert!(matches!(adapter.sync_teams(&local, SyncDirection::Both).await, Err(DomainError::Forbidden(_))));
    let mut duplicate = adapter.pull_teams().await.unwrap();
    duplicate.push(duplicate[0].clone());
    assert!(matches!(adapter.sync_teams(&duplicate, SyncDirection::Both).await, Err(DomainError::Validation(_))));
}
#[test]
fn dependencies_assignment_schedule_role_and_exact_asset_identity_change_the_fingerprint() {
    let base = team();
    let mut values = Vec::new();
    let mut changed = base.clone();
    changed.orchestration[1].depends_on.clear();
    values.push(changed);
    let mut changed = base.clone();
    changed.orchestration[0].agent_ids = vec![base.agents[0].cloud_agent_id.clone()];
    assert_ne!(changed.orchestration[0].agent_ids, base.orchestration[0].agent_ids);
    values.push(changed);
    let mut changed = base.clone();
    changed.orchestration[0].cron = Some("0 0 3 * * *".into());
    values.push(changed);
    let mut changed = base.clone();
    changed.roles[0].allowed_tools.push("mcp:new-tool".into());
    values.push(changed);
    let mut changed = base.clone();
    changed.agents[0].asset_id = Some(Id::new());
    values.push(changed);
    let mut changed = base.clone();
    changed.agents[0].models.push("another-model".into());
    values.push(changed);
    let mut changed = base.clone();
    changed.description.push_str(" updated");
    values.push(changed);
    for (index, value) in values.into_iter().enumerate() {
        assert_ne!(team_content_signature(&base), team_content_signature(&value), "definition change {index}");
    }
    let mut reordered = base.clone();
    reordered.agents.reverse();
    reordered.roles.reverse();
    reordered.orchestration.reverse();
    for agent in &mut reordered.agents {
        agent.tools.reverse();
        agent.models.reverse();
        agent.role_names.reverse();
    }
    reordered.updated_at = Timestamp::now().offset_secs(30);
    reordered.synced = !reordered.synced;
    assert_eq!(team_content_signature(&base), team_content_signature(&reordered));
}
#[test]
fn import_rejects_cycles_unknown_workers_stale_inventory_and_unrecognized_node_fields() {
    let team = team();
    let doc = DefinitionDocument::from_application(&team, team.orchestration.clone());
    validate_definition(&doc, &team).unwrap();
    let mut invalid = doc.clone();
    invalid.nodes[0].depends_on = vec![invalid.nodes[1].node_id.clone()];
    assert!(validate_definition(&invalid, &team).is_err());
    let mut invalid = doc.clone();
    invalid.nodes[0].agent_ids = vec!["not-observed-worker".into()];
    assert!(validate_definition(&invalid, &team).is_err());
    let mut changed = team.clone();
    changed.agents[0].asset_id = Some(Id::new());
    assert!(matches!(validate_definition(&doc, &changed), Err(DomainError::Conflict(_))));
    let mut raw = serde_json::to_value(&doc).unwrap();
    raw["nodes"][0]["execute_script"] = serde_json::json!("ignored-business-code");
    assert!(serde_json::from_value::<DefinitionDocument>(raw).is_err());
}
#[test]
fn explicit_mock_push_pull_and_identical_request_replay_preserve_the_original_fact() {
    let mut team = team();
    let bridge = MockDefinitionBridge::new(team.clone()).unwrap();
    let initial = serde_json::to_value(bridge.read().unwrap()).unwrap();
    let node = extra(&team);
    team.orchestration.push(node);
    let publish = intent(&team, 0, DefinitionDirection::Both);
    assert_eq!(bridge.preview(&publish).unwrap().added, vec!["n3"]);
    assert_eq!(serde_json::to_value(bridge.read().unwrap()).unwrap(), initial);
    let receipt = bridge.apply(&publish).unwrap();
    assert_eq!(receipt.result.version, 1);
    assert_eq!(receipt.result.receiver.nodes.len(), 3);
    assert!(!receipt.provider_called);
    assert!(!receipt.result.durable);
    assert_eq!(receipt.result.consumer_applied, None);
    assert_eq!(bridge.apply(&publish).unwrap().body_hash, receipt.body_hash);
    let adopted = bridge.apply(&intent(&team, 1, DefinitionDirection::Pull)).unwrap();
    assert_eq!(adopted.result.version, 2);
    assert_eq!(adopted.result.local.unwrap().nodes.len(), 3);
    // Reading/replaying the old fact neither changes its version nor overwrites current state.
    assert_eq!(bridge.receipt(publish.request_id).unwrap().result.version, 1);
    assert_eq!(bridge.apply(&publish).unwrap().result.version, 1);
    assert_eq!(bridge.read().unwrap().version, 2);
    let mut changed_body = publish.clone();
    changed_body.direction = DefinitionDirection::Push;
    assert!(matches!(bridge.apply(&changed_body), Err(DomainError::Conflict(_))));
}
#[test]
fn rejected_and_capacity_full_intents_do_not_mutate_or_evict_permanent_ids() {
    let team = team();
    let bridge = MockDefinitionBridge::new(team.clone()).unwrap();
    let before = serde_json::to_value(bridge.read().unwrap()).unwrap();
    let mut unconfirmed = intent(&team, 0, DefinitionDirection::Pull);
    unconfirmed.confirm_mock = false;
    assert!(bridge.apply(&unconfirmed).is_err());
    assert_eq!(serde_json::to_value(bridge.read().unwrap()).unwrap(), before);
    let first = intent(&team, 0, DefinitionDirection::Pull);
    bridge.apply(&first).unwrap();
    let mut stale = intent(&team, 0, DefinitionDirection::Pull);
    assert!(matches!(bridge.apply(&stale), Err(DomainError::Conflict(_))));
    for version in 1..MAX_MOCK_INTENTS {
        bridge.apply(&intent(&team, u64::try_from(version).unwrap(), DefinitionDirection::Pull)).unwrap();
    }
    stale.expected_version = u64::try_from(MAX_MOCK_INTENTS).unwrap();
    assert!(matches!(bridge.apply(&stale), Err(DomainError::Validation(_))));
    assert_eq!(bridge.read().unwrap().version, u64::try_from(MAX_MOCK_INTENTS).unwrap());
    assert_eq!(bridge.receipt(first.request_id).unwrap().result.version, 1);
    assert_eq!(bridge.apply(&first).unwrap().result.version, 1);
}

#[test]
fn nil_empty_ambiguous_or_unbounded_inventory_identity_is_rejected_before_bridge_initialization() {
    let base = team();
    let mut invalid = Vec::new();
    let mut value = base.clone();
    value.tenant_id = TenantId::from_id(Id::nil());
    invalid.push(value);
    let mut value = base.clone();
    value.id = Id::nil();
    invalid.push(value);
    let mut value = base.clone();
    value.cloud_team_id.clear();
    invalid.push(value);
    let mut value = base.clone();
    value.cloud_team_id = " Team with leading space".into();
    invalid.push(value);
    let mut value = base.clone();
    value.cloud_team_id = "x".repeat(257);
    invalid.push(value);
    let mut value = base.clone();
    value.agents[0].cloud_agent_id.clear();
    value.orchestration.clear();
    invalid.push(value);
    let mut value = base.clone();
    value.agents[0].cloud_agent_id = "worker\n".into();
    value.orchestration.clear();
    invalid.push(value);
    let mut value = base.clone();
    value.agents[0].cloud_agent_id = "x".repeat(513);
    value.orchestration.clear();
    invalid.push(value);
    let mut value = base.clone();
    value.agents[0].asset_id = Some(Id::nil());
    invalid.push(value);
    let mut value = base.clone();
    let id = Id::new();
    value.agents[0].asset_id = Some(id);
    value.agents[1].asset_id = Some(id);
    invalid.push(value);
    let mut value = base.clone();
    value.agents.push(value.agents[0].clone());
    invalid.push(value);
    for value in invalid {
        let doc = DefinitionDocument::from_application(&value, value.orchestration.clone());
        assert!(validate_definition(&doc, &value).is_err());
        assert!(MockDefinitionBridge::new(value).is_err());
    }
    let mut unmapped = base;
    for agent in &mut unmapped.agents {
        agent.asset_id = None;
    }
    assert!(
        MockDefinitionBridge::new(unmapped).is_ok(),
        "observed unmapped Workers remain legitimate, without inventing an asset"
    );
}

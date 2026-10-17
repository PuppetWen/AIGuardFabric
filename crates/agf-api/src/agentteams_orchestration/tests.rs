use super::*;
use agf_alicloud::agentteams::orchestration::{DefinitionDirection, DefinitionDocument};
use agf_core::{
    agent::OnboardingMode,
    cloud::{AgentTeam, AgentTeamMember, OrchestrationNode},
};

fn current() -> source::Current {
    let tenant = TenantId::new();
    let now = Timestamp::now();
    let team = AgentTeam {
        id: Id::new(),
        tenant_id: tenant,
        cloud_team_id: "owned-team".into(),
        name: "Owned".into(),
        description: String::new(),
        agents: vec![AgentTeamMember {
            cloud_agent_id: "owned-worker".into(),
            name: "Owned worker".into(),
            models: vec![],
            tools: vec![],
            role_names: vec![],
            asset_id: Some(Id::new()),
            status: "observed".into(),
        }],
        roles: vec![],
        orchestration: vec![],
        onboarding: OnboardingMode::ObserveOnly,
        synced: false,
        cloud_updated_at: None,
        created_at: now,
        updated_at: now,
    };
    source::Current {
        source: model::Source {
            tenant,
            configuration_version: 1,
            evidence_hash: "server-evidence".into(),
            region: "owned-region".into(),
            instance_id: "owned-instance".into(),
            inventory_fingerprint: agf_alicloud::agentteams::orchestration::inventory_fingerprint(&team),
        },
        team,
        assets: vec![],
    }
}
fn input(current: &source::Current, version: u64, change: model::Change) -> model::Input {
    model::Input {
        request_id: Id::new(),
        expected_version: version,
        configuration_version: current.source.configuration_version,
        inventory_fingerprint: current.source.inventory_fingerprint.clone(),
        change,
        confirm_application_owned: true,
        confirm_mock_sync: true,
        confirm_source_change: false,
    }
}
fn document(current: &source::Current, name: &str) -> DefinitionDocument {
    DefinitionDocument::from_application(
        &current.team,
        vec![OrchestrationNode {
            node_id: "first".into(),
            name: name.into(),
            agent_ids: vec!["owned-worker".into()],
            depends_on: vec![],
            trigger: "manual".into(),
            cron: None,
        }],
    )
}
#[test]
fn local_and_mock_receiver_are_distinct_and_pull_uses_the_actual_previous_receiver() {
    let current = current();
    let actor = Id::new();
    let mut rows = model::Registry { tenant: Some(current.source.tenant), ..Default::default() };
    let first = input(&current, 0, model::Change::SaveDefinition { definition: document(&current, "Original") });
    let (preview, _) = reducer::prepare(&rows, &current, &first).unwrap();
    assert!(preview.receiver.is_none());
    assert!(rows.records.is_empty());
    reducer::commit(&mut rows, &current, actor, &first).unwrap();
    assert!(rows.records["owned-team"].receiver.is_none());
    reducer::commit(
        &mut rows,
        &current,
        actor,
        &input(&current, 1, model::Change::Sync { direction: DefinitionDirection::Push }),
    )
    .unwrap();
    reducer::commit(
        &mut rows,
        &current,
        actor,
        &input(&current, 2, model::Change::SaveDefinition { definition: document(&current, "New local") }),
    )
    .unwrap();
    assert_eq!(rows.records["owned-team"].receiver.as_ref().unwrap().nodes[0].name, "Original");
    reducer::commit(
        &mut rows,
        &current,
        actor,
        &input(&current, 3, model::Change::Sync { direction: DefinitionDirection::Pull }),
    )
    .unwrap();
    assert_eq!(rows.records["owned-team"].local.as_ref().unwrap().nodes[0].name, "Original");
    assert_eq!(rows.intents.len(), 4);
}
#[test]
fn unknown_receiver_stale_cas_and_wrong_actor_or_purpose_never_mutate_original_facts() {
    let current = current();
    let actor = Id::new();
    let mut rows = model::Registry { tenant: Some(current.source.tenant), ..Default::default() };
    assert!(
        reducer::prepare(
            &rows,
            &current,
            &input(&current, 0, model::Change::Sync { direction: DefinitionDirection::Pull })
        )
        .is_err()
    );
    let first = input(&current, 0, model::Change::SaveDefinition { definition: document(&current, "Original") });
    reducer::commit(&mut rows, &current, actor, &first).unwrap();
    let before = serde_json::to_value(&rows).unwrap();
    assert_eq!(reducer::replay(&rows, actor, "owned-team", &first).unwrap().unwrap().version, 1);
    assert!(reducer::replay(&rows, Id::new(), "owned-team", &first).is_err());
    let mut changed = first.clone();
    changed.change = model::Change::Sync { direction: DefinitionDirection::Push };
    assert!(reducer::replay(&rows, actor, "owned-team", &changed).is_err());
    assert!(reducer::prepare(&rows, &current, &first).is_err());
    assert_eq!(serde_json::to_value(&rows).unwrap(), before);
}
#[test]
fn source_change_requires_new_explicit_definition_and_discards_the_old_receiver() {
    let mut current = current();
    let actor = Id::new();
    let mut rows = model::Registry { tenant: Some(current.source.tenant), ..Default::default() };
    reducer::commit(
        &mut rows,
        &current,
        actor,
        &input(&current, 0, model::Change::SaveDefinition { definition: document(&current, "Original") }),
    )
    .unwrap();
    reducer::commit(
        &mut rows,
        &current,
        actor,
        &input(&current, 1, model::Change::Sync { direction: DefinitionDirection::Push }),
    )
    .unwrap();
    current.source.configuration_version = 2;
    current.source.evidence_hash = "new-source".into();
    assert!(
        reducer::prepare(
            &rows,
            &current,
            &input(&current, 2, model::Change::Sync { direction: DefinitionDirection::Push })
        )
        .is_err()
    );
    let mut explicit =
        input(&current, 2, model::Change::SaveDefinition { definition: document(&current, "Explicit new target") });
    assert!(reducer::prepare(&rows, &current, &explicit).is_err());
    explicit.confirm_source_change = true;
    reducer::commit(&mut rows, &current, actor, &explicit).unwrap();
    assert!(rows.records["owned-team"].receiver.is_none());
    assert_eq!(rows.intents.values().filter(|fact| fact.source.configuration_version == 1).count(), 2);
}
#[test]
fn persisted_null_cannot_be_deserialized_as_an_empty_registry() {
    assert!(serde_json::from_value::<model::Slot>(Value::Null).is_err());
    assert!(serde_json::from_value::<model::Slot>(json!({"secret":null})).is_err());
    assert!(serde_json::to_value(model::Slot::default()).is_err());
}
#[test]
fn permanent_intent_capacity_never_evicts_old_ids_and_foreign_registry_is_rejected() {
    let current = current();
    let actor = Id::new();
    let mut rows = model::Registry { tenant: Some(current.source.tenant), ..Default::default() };
    let first = input(&current, 0, model::Change::SaveDefinition { definition: document(&current, "First") });
    reducer::commit(&mut rows, &current, actor, &first).unwrap();
    for version in 1..MAX_INTENTS {
        let next = input(
            &current,
            u64::try_from(version).unwrap(),
            model::Change::SaveDefinition { definition: document(&current, "Next") },
        );
        reducer::commit(&mut rows, &current, actor, &next).unwrap();
    }
    let before = serde_json::to_value(&rows).unwrap();
    let last = input(
        &current,
        u64::try_from(MAX_INTENTS).unwrap(),
        model::Change::SaveDefinition { definition: document(&current, "Full") },
    );
    assert!(reducer::commit(&mut rows, &current, actor, &last).is_err());
    assert_eq!(serde_json::to_value(&rows).unwrap(), before);
    assert_eq!(reducer::replay(&rows, actor, "owned-team", &first).unwrap().unwrap().version, 1);
    rows.tenant = Some(TenantId::new());
    assert!(reducer::prepare(&rows, &current, &last).is_err());
}

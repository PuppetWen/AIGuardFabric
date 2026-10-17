use super::super::{tests_proof_support as fixture, util};
use super::*;
use agf_alicloud::schedulerx3::managed_jobs::{Change, Kind, MockDeclaration, Readback, SchedulePatch, Selection};
use agf_core::{error::DomainResult, ids::Id};
use serde_json::{Value, json};

fn input(data: &super::super::safe::SafeSnapshot, index: usize, change: Change) -> DomainResult<input::PreviewInput> {
    Ok(input::PreviewInput {
        request_id: Id::new(),
        configuration_version: 1,
        expected_binding_version: 0,
        observation_id: Id::new(),
        change,
        selection: Some(Selection {
            kind: Kind::Report,
            app_id: data.app_id().into(),
            job_id: data.jobs()[index]["id"].as_str().ok_or_else(util::corrupt)?.into(),
            observation_fingerprint: data.fingerprint().into(),
        }),
    })
}
#[test]
fn input_rejects_unknown_fields_nil_identity_null_patch_and_missing_confirmations() -> DomainResult<()> {
    let source = fixture::target()?;
    let data = fixture::fixture(&source)?;
    let mut raw = serde_json::to_value(input(&data, 0, Change::Disable)?)?;
    raw["unexpected"] = json!(true);
    assert!(serde_json::from_value::<input::PreviewInput>(raw).is_err());
    let mut invalid = input(&data, 0, Change::Disable)?;
    invalid.request_id = Id::nil();
    assert!(invalid.validate().is_err());
    assert!(serde_json::from_value::<SchedulePatch>(json!({"calendar":null})).is_err());
    assert!(
        serde_json::from_value::<input::ApplyInput>(
            json!({"preview_id":Id::new(),"preview_fingerprint":"0".repeat(64),
        "confirm_no_cloud_cas":true})
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn active_update_requires_independent_disable_and_preserves_opaque_http_fields() -> DomainResult<()> {
    let source = fixture::target()?;
    let data = fixture::fixture(&source)?;
    let journal = model::Journal::default();
    let change = Change::UpdateSchedule { patch: SchedulePatch { max_attempt: Some(0), ..SchedulePatch::default() } };
    assert!(plan::desired(&input(&data, 1, change.clone())?, &data, &journal, source.scope_id, true).is_err());
    let (before, desired) = plan::desired(&input(&data, 0, change)?, &data, &journal, source.scope_id, true)?;
    assert_eq!(desired["enabled"], false);
    assert_eq!(desired["status"], 0);
    assert_eq!(desired["maxAttempt"], 0);
    assert_eq!(desired["http"], before.as_ref().ok_or_else(util::corrupt)?["http"]);
    assert_eq!(desired["routeStrategy"], data.jobs()[0]["routeStrategy"]);
    Ok(())
}
#[test]
fn mock_create_is_disabled_large_int64_local_only_and_duplicate_kind_is_rejected() -> DomainResult<()> {
    let source = fixture::target()?;
    let data = fixture::fixture(&source)?;
    let declaration = MockDeclaration {
        kind: Kind::Archive,
        name: "owned archive".into(),
        total: 1,
        schedule: SchedulePatch {
            time_type: Some(1),
            time_expression: Some("0 0/5 * * * ?".into()),
            timezone: Some("UTC".into()),
            max_attempt: Some(0),
            attempt_interval: Some(0),
            calendar: Some(String::new()),
        },
    };
    let input = input::PreviewInput {
        request_id: Id::new(),
        configuration_version: 1,
        expected_binding_version: 0,
        observation_id: Id::new(),
        change: Change::CreateDisabled { declaration },
        selection: None,
    };
    let mut journal = model::Journal::default();
    let (before, desired) = plan::desired(&input, &data, &journal, source.scope_id, true)?;
    assert!(before.is_none());
    assert_eq!(desired["id"], "9007199254741007");
    assert_eq!(desired["enabled"], false);
    assert_eq!(desired["http"]["verified"], false);
    assert!(desired["shardCount"].is_null());
    assert!(plan::desired(&input, &data, &journal, source.scope_id, false).is_err());
    journal.definitions.push(model::Definition {
        scope_id: source.scope_id,
        kind: Kind::Archive,
        job_id: "9007199254741007".into(),
        request_id: Id::new(),
        total: 1,
    });
    assert!(plan::desired(&input, &data, &journal, source.scope_id, true).is_err());
    Ok(())
}
#[test]
fn missing_http_status_or_job_never_becomes_a_default_selection() -> DomainResult<()> {
    let source = fixture::target()?;
    let data = fixture::fixture(&source)?;
    for index in [4, 5] {
        assert!(
            plan::desired(
                &input(&data, index, Change::Disable)?,
                &data,
                &model::Journal::default(),
                source.scope_id,
                true
            )
            .is_err()
        );
    }
    let mut selected = input(&data, 0, Change::Enable)?;
    selected.selection.as_mut().ok_or_else(util::corrupt)?.job_id = "9007199254749999".into();
    assert!(plan::desired(&selected, &data, &model::Journal::default(), source.scope_id, true).is_err());
    Ok(())
}
#[test]
fn journal_duplicate_intent_scope_and_unknown_marker_fail_closed() -> DomainResult<()> {
    let source = fixture::target()?;
    let mut journal = model::Journal::default();
    let id = Id::new();
    journal.previews = vec![id, id];
    assert!(model::validate_journal(&journal, source.tenant).is_err());
    journal.previews.clear();
    journal.unknown = vec![
        model::Uncertain {
            resource: model::RiskIdentity::of(&source),
            request_id: id,
            scope_id: source.scope_id,
            expires_at: agf_core::time::Timestamp::now(),
        },
        model::Uncertain {
            resource: model::RiskIdentity::of(&source),
            request_id: Id::new(),
            scope_id: source.scope_id,
            expires_at: agf_core::time::Timestamp::now(),
        },
    ];
    assert!(model::validate_journal(&journal, source.tenant).is_err());
    Ok(())
}
#[test]
fn unknown_write_is_distinct_from_a_matching_independent_readback() -> DomainResult<()> {
    let source = fixture::target()?;
    let data = fixture::fixture(&source)?;
    let change = Change::UpdateSchedule { patch: SchedulePatch { max_attempt: Some(1), ..SchedulePatch::default() } };
    let input = input(&data, 0, change)?;
    let (before, desired) = plan::desired(&input, &data, &model::Journal::default(), source.scope_id, true)?;
    let now = agf_core::time::Timestamp::now();
    let preview = model::Preview {
        tenant: source.tenant,
        id: input.request_id,
        actor: Id::new(),
        input_hash: codec::hash(model::Purpose::Preview, &input)?,
        input,
        target: source,
        created_at: now,
        expires_at: now.offset_secs(120),
        app_id: data.app_id().into(),
        baseline_fingerprint: data.fingerprint().into(),
        before,
        desired,
        fingerprint: "0".repeat(64),
        operation_id: None,
        archived_at: None,
    };
    let write = agf_alicloud::schedulerx3::managed_jobs::WriteEvidence {
        attempted: true,
        status: agf_alicloud::schedulerx3::managed_jobs::WriteStatus::Unknown,
        provider_request_id: None,
        authority_current: false,
        original_deadline_current: false,
    };
    assert_eq!(plan::readback(&preview, &data), Readback::Matched);
    assert_eq!(write.status, agf_alicloud::schedulerx3::managed_jobs::WriteStatus::Unknown);
    let mut changed = data.value().clone();
    changed["jobs"][0]["http"]["fingerprint"] = json!("f".repeat(64));
    let drift = fixture::parse(&preview.target, changed)?;
    assert_eq!(plan::readback(&preview, &drift), Readback::Different);
    let archived = serde_json::to_value(model::PreviewRecord::Archived(Box::new(model::ArchivedPreview {
        tenant: preview.tenant,
        id: preview.id,
        actor: preview.actor,
        input_hash: preview.input_hash,
        target: preview.target,
        fingerprint: preview.fingerprint,
        created_at: now,
        archived_at: now,
        operation_id: None,
    })))?;
    assert!(archived.get("desired").is_none());
    assert!(archived.get("before").is_none());
    assert_eq!(archived["class"], Value::String("archived".into()));
    Ok(())
}

#[test]
fn unknown_risk_identity_ignores_unverified_source_labels_but_is_tenant_cluster_and_app_bound() -> DomainResult<()> {
    let source = fixture::target()?;
    let original = model::RiskIdentity::of(&source);
    let mut changed = source.clone();
    changed.configured_account_id = Some("different-unverified-label".into());
    changed.configuration_version += 1;
    changed.configuration_id = Id::new();
    changed.rpc_origin = "https://changed-scheduler.example.invalid/".into();
    changed.region = "cn-beijing".into();
    changed.mocked = !changed.mocked;
    changed.transport_mode = "live".into();
    changed.scope_id = Id::new();
    assert_eq!(model::RiskIdentity::of(&changed), original);
    changed.cluster_id.push_str("-other");
    assert_ne!(model::RiskIdentity::of(&changed), original);
    changed = source.clone();
    changed.app_name.push_str("-other");
    assert_ne!(model::RiskIdentity::of(&changed), original);
    changed = source;
    changed.tenant = agf_core::ids::TenantId::new();
    assert_ne!(model::RiskIdentity::of(&changed), original);
    Ok(())
}

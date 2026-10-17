//! Local checkpoint and bounded directory tests; no synthetic assertion of provider execution.
use super::{background, background_tenants, codec, maintenance, meter_projection, records::*, tests_fixture};
use crate::{AppState, model_routes::tenant_record_id};
use agf_aigw::meter::CommittedMeterProjection;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::Value;
use std::collections::BTreeMap;

const CHECKPOINT: &str = "gateway-meter-checkpoint-v1";
fn test_state() -> DomainResult<AppState> {
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "gateway-startup-owned-unit-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let data = std::env::var_os("AGF_TEST_DATA_DIR").map_or_else(
        || std::path::PathBuf::from("./target/test-data/gateway-startup"),
        |root| std::path::PathBuf::from(root).join("gateway-startup"),
    );
    env.insert("AGF_DATA_DIR".into(), data.to_string_lossy().into_owned());
    AppState::offline(agf_core::config::from_env_map(&env)?)
}
fn tenant(n: u128) -> TenantId {
    TenantId::from_uuid(uuid::Uuid::from_u128(n))
}

#[test]
fn directory_rejects_nil_duplicates_unsorted_cursor_and_unbounded_pages() -> DomainResult<()> {
    for ids in [vec![tenant(0)], vec![tenant(1), tenant(1)], vec![tenant(2), tenant(1)], (1..35).map(tenant).collect()]
    {
        assert!(background_tenants::validate(ids, None).is_err());
    }
    assert!(background_tenants::validate(vec![tenant(7)], Some(tenant(7))).is_err());
    assert!(background_tenants::validate(vec![tenant(6)], Some(tenant(7))).is_err());
    let next = background_tenants::validate((8..41).map(tenant).collect(), Some(tenant(7)))?;
    assert!(next.more);
    assert_eq!(next.tenants.len(), 32);
    assert_eq!(next.tenants.first(), Some(&tenant(8)));
    assert_eq!(next.tenants.last(), Some(&tenant(39)));
    let last = background_tenants::validate(vec![tenant(40)], Some(tenant(39)))?;
    assert!(!last.more);
    assert_eq!(last.tenants, vec![tenant(40)]);
    Ok(())
}

#[tokio::test]
async fn missing_checkpoint_is_pure_absence_not_an_initialized_or_incomplete_zero() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let before = state.configurations.list::<Value>(tenant, CHECKPOINT).await?;
    meter_projection::hydrate(&state, tenant).await?;
    assert_eq!(state.configurations.list::<Value>(tenant, CHECKPOINT).await?, before);
    assert_eq!(state.meter.snapshot().total.calls, 0);
    assert!(!state.meter.snapshot().committed_projection_incomplete);
    Ok(())
}

#[tokio::test]
async fn checkpoint_restart_and_repeated_hydration_preserve_paid_usage_without_double_counting() -> DomainResult<()> {
    let state = test_state()?;
    let restarted = test_state()?;
    let tenant = TenantId::default_tenant();
    let id = tenant_record_id(tenant);
    let fixture = tests_fixture::fixture(864_100)?;
    let terminal = tests_fixture::write(
        &fixture.fact,
        &fixture.pending,
        fixture.gateway.clone(),
        fixture.runtime.clone(),
        864_100,
    )?
    .fact;
    let usage = fixture.pending.outcome.usage.ok_or_else(|| DomainError::Internal("usage".into()))?;
    let projection = CommittedMeterProjection::new(tenant)?.append(std::slice::from_ref(&usage))?;
    let secret = codec::encode(&state, tenant, id, CHECKPOINT, &projection)?;
    for instance in [&state, &restarted] {
        instance.configurations.put(tenant, CHECKPOINT, id, &secret).await?;
        instance.configurations.put(tenant, "model-usage", usage.id, &usage).await?;
        instance
            .configurations
            .put(tenant, FACT, terminal.attempt, &codec::encode(instance, tenant, terminal.attempt, FACT, &terminal)?)
            .await?;
        let before = instance.configurations.list::<Value>(tenant, CHECKPOINT).await?;
        for _ in 0..2 {
            meter_projection::hydrate(instance, tenant).await?;
        }
        let snapshot = instance.meter.snapshot();
        assert_eq!(snapshot.total.calls, 1);
        assert_eq!(snapshot.total.prompt_tokens, 4);
        assert_eq!(snapshot.total.completion_tokens, 3);
        assert_eq!(snapshot.total.cost_micro, 11);
        assert!(!snapshot.committed_projection_incomplete);
        assert_eq!(instance.configurations.list::<Value>(tenant, CHECKPOINT).await?, before);
    }
    Ok(())
}

#[tokio::test]
async fn foreign_aad_does_not_publish_or_repair_a_checkpoint_and_marks_totals_incomplete() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let foreign = TenantId::new();
    let secret =
        codec::encode(&state, tenant, tenant_record_id(tenant), CHECKPOINT, &CommittedMeterProjection::new(tenant)?)?;
    state.configurations.put(foreign, CHECKPOINT, tenant_record_id(foreign), &secret).await?;
    let before = state.configurations.list::<Value>(foreign, CHECKPOINT).await?;
    assert!(meter_projection::hydrate(&state, foreign).await.is_err());
    assert!(state.meter.snapshot().committed_projection_incomplete);
    assert_eq!(state.meter.snapshot().total.calls, 0);
    assert_eq!(state.configurations.list::<Value>(foreign, CHECKPOINT).await?, before);
    Ok(())
}

#[tokio::test]
async fn due_attempt_scan_is_read_only_bounded_and_does_not_include_future_reservations() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let id = tenant_record_id(tenant);
    let now = Timestamp::now();
    let mut active = ActiveAttempts::default();
    let mut due = Vec::new();
    for _ in 0..20 {
        let id = Id::new();
        active.items.insert(id, now.offset_secs(-1));
        due.push(id);
    }
    for _ in 0..3 {
        active.items.insert(Id::new(), now.offset_secs(3600));
    }
    due.sort();
    state.configurations.put(tenant, ACTIVE, id, &codec::encode(&state, tenant, id, ACTIVE, &active)?).await?;
    let before = state.configurations.list::<Value>(tenant, ACTIVE).await?;
    assert_eq!(maintenance::due_ids(&state, tenant, 4).await?, due[..4]);
    assert_eq!(maintenance::due_ids(&state, tenant, 16).await?, due[..16]);
    assert_eq!(maintenance::due_rotated(&state, tenant, 4, 4).await?, due[4..8]);
    assert_eq!(maintenance::due_rotated(&state, tenant, 4, 18).await?, vec![due[18], due[19], due[0], due[1]]);
    assert!(maintenance::due_ids(&state, tenant, 17).await.is_err());
    assert_eq!(state.configurations.list::<Value>(tenant, ACTIVE).await?, before);
    for _ in 0..490 {
        active.items.insert(Id::new(), now);
    }
    state.configurations.put(tenant, ACTIVE, id, &codec::encode(&state, tenant, id, ACTIVE, &active)?).await?;
    assert!(maintenance::due_ids(&state, tenant, 4).await.is_err());
    Ok(())
}

#[tokio::test]
async fn offline_start_and_shutdown_do_not_create_a_checkpoint_or_background_execution() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let before = state.configurations.list::<Value>(tenant, CHECKPOINT).await?;
    background::start_gateway_maintenance(state.clone()).await.shutdown().await;
    assert_eq!(state.configurations.list::<Value>(tenant, CHECKPOINT).await?, before);
    assert!(!state.meter.snapshot().committed_projection_incomplete);
    assert_eq!(state.meter.snapshot().total.calls, 0);
    Ok(())
}

#[tokio::test]
async fn missing_checkpoint_with_existing_usage_is_incomplete_and_does_not_rewrite_usage() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let usage =
        tests_fixture::fixture(864_100)?.pending.outcome.usage.ok_or_else(|| DomainError::Internal("usage".into()))?;
    state.configurations.put(tenant, "model-usage", usage.id, &usage).await?;
    let before = state.configurations.list::<Value>(tenant, "model-usage").await?;
    assert!(meter_projection::hydrate(&state, tenant).await.is_err());
    assert!(state.meter.snapshot().committed_projection_incomplete);
    assert!(state.configurations.list::<Value>(tenant, CHECKPOINT).await?.is_empty());
    assert_eq!(state.configurations.list::<Value>(tenant, "model-usage").await?, before);
    Ok(())
}

#[tokio::test]
async fn active_checkpoint_with_uncovered_legacy_usage_retains_subtotal_but_is_incomplete() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let fixture = tests_fixture::fixture(864_100)?;
    let usage = fixture.pending.outcome.usage.ok_or_else(|| DomainError::Internal("usage".into()))?;
    let projection = CommittedMeterProjection::new(tenant)?.append(std::slice::from_ref(&usage))?;
    let id = tenant_record_id(tenant);
    state
        .configurations
        .put(tenant, CHECKPOINT, id, &codec::encode(&state, tenant, id, CHECKPOINT, &projection)?)
        .await?;
    state.configurations.put(tenant, "model-usage", usage.id, &usage).await?;
    let before = state.configurations.list::<Value>(tenant, "model-usage").await?;
    assert!(meter_projection::hydrate(&state, tenant).await.is_err());
    assert!(state.meter.snapshot().committed_projection_incomplete);
    assert_eq!(state.meter.snapshot().total.cost_micro, 11);
    assert_eq!(state.configurations.list::<Value>(tenant, "model-usage").await?, before);
    Ok(())
}

#[tokio::test]
async fn numerical_total_equality_does_not_make_unsealed_legacy_usage_atomic_coverage() -> DomainResult<()> {
    let state = test_state()?;
    let tenant = TenantId::default_tenant();
    let fixture = tests_fixture::fixture(864_100)?;
    let row = fixture.pending.outcome.usage.ok_or_else(|| DomainError::Internal("usage".into()))?;
    let projection = CommittedMeterProjection::new(tenant)?.append(std::slice::from_ref(&row))?;
    let witness = super::meter_coverage::Witness {
        checkpoint: None,
        retired_checkpoint: false,
        facts: vec![],
        usages: vec![(row.id, serde_json::to_value(&row)?)],
    };
    assert!(super::meter_coverage::verify(&state, tenant, &projection, &witness).is_err());
    Ok(())
}

use super::{
    KIND,
    configuration::ProfileInput,
    source::{Capture, Source},
    util,
};
use crate::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::time::{Duration, Instant};

fn state() -> DomainResult<AppState> {
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "semantic-profile-owned-unit-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let data = std::env::var_os("AGF_TEST_DATA_DIR").map_or_else(
        || std::path::PathBuf::from("./target/test-data/semantic-profile"),
        |root| std::path::PathBuf::from(root).join("semantic-profile"),
    );
    env.insert("AGF_DATA_DIR".into(), data.to_string_lossy().into_owned());
    AppState::offline(agf_core::config::from_env_map(&env)?)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_mins(1)
}
async fn complete(state: &AppState, tenant: TenantId) -> DomainResult<Box<Source>> {
    match Source::capture(state, tenant, deadline()).await? {
        Capture::Complete(source) => Ok(source),
        Capture::TooMany | Capture::TooLarge => Err(util::corrupt()),
    }
}

#[tokio::test]
async fn full_source_capture_is_pure_and_empty_profile_stays_missing() -> DomainResult<()> {
    let state = state()?;
    let tenant = TenantId::default_tenant();
    let before = state.configurations.list::<Value>(tenant, KIND).await?;
    let source = complete(&state, tenant).await?;
    source.current(&state, deadline()).await?;
    assert!(source.get(KIND, util::record_id(tenant)).is_none());
    assert_eq!(state.configurations.list::<Value>(tenant, KIND).await?, before);
    Ok(())
}

#[tokio::test]
async fn absence_add_remove_and_same_version_content_change_invalidate_whole_set() -> DomainResult<()> {
    let state = state()?;
    let tenant = TenantId::default_tenant();
    let absent = complete(&state, tenant).await?;
    let id = Id::new();
    state.configurations.put(tenant, "case-containment", id, &json!({"id":id,"active":true})).await?;
    assert!(absent.current(&state, deadline()).await.is_err());
    let present = complete(&state, tenant).await?;
    state.configurations.put(tenant, "case-containment", id, &json!({"id":id,"active":false})).await?;
    assert!(present.current(&state, deadline()).await.is_err());
    let changed = complete(&state, tenant).await?;
    state.configurations.delete(tenant, "case-containment", id).await?;
    assert!(changed.current(&state, deadline()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn real_rule_registry_key_and_full_profile_revision_are_actual_fences() -> DomainResult<()> {
    let state = state()?;
    let tenant = TenantId::default_tenant();
    let id = deterministic_id("detection-rules", &tenant.to_string());
    state.configurations.put(tenant, "detection-rules", id, &json!({"entries":{}})).await?;
    let row = ProfileInput { expected_version: 0, enabled: false, settings: None }.apply(tenant, None)?;
    state.configurations.put(tenant, KIND, row.id, &row).await?;
    let source = complete(&state, tenant).await?;
    let fences = source.fences()?;
    let rule = fences.iter().find(|fence| fence.kind() == "detection-rules").ok_or_else(util::corrupt)?;
    assert_eq!(rule.id(), id);
    assert_eq!(rule.version(), 0);
    let profile = fences.iter().find(|fence| fence.kind() == KIND).ok_or_else(util::corrupt)?;
    assert_eq!(profile.version(), 1);
    assert_ne!(id, crate::model_routes::tenant_record_id(tenant));
    Ok(())
}

#[tokio::test]
async fn more_than_32_present_records_refuses_semantic_plan_without_truncating_capture() -> DomainResult<()> {
    let state = state()?;
    let tenant = TenantId::default_tenant();
    for _ in 0..33 {
        let id = Id::new();
        state.configurations.put(tenant, "case-containment", id, &json!({"id":id})).await?;
    }
    assert!(matches!(Source::capture(&state, tenant, deadline()).await?, Capture::TooMany));
    assert_eq!(state.configurations.list::<Value>(tenant, "case-containment").await?.len(), 33);
    let other = TenantId::new();
    let id = Id::new();
    state.configurations.put(other, "case-containment", id, &json!({"id":id,"body":"x".repeat(8*1024*1024)})).await?;
    assert!(matches!(Source::capture(&state, other, deadline()).await?, Capture::TooLarge));
    Ok(())
}

#[tokio::test]
async fn foreign_tenant_record_and_original_expired_deadline_fail_closed() -> DomainResult<()> {
    let state = state()?;
    let tenant = TenantId::default_tenant();
    let id = Id::new();
    state.configurations.put(tenant, "case-containment", id, &json!({"id":id,"tenant":TenantId::new()})).await?;
    assert!(Source::capture(&state, tenant, deadline()).await.is_err());
    assert!(Source::capture(&state, tenant, Instant::now()).await.is_err());
    Ok(())
}

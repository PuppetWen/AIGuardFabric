//! Pure node-health disclosure is separate from tenant Usage and authenticated ledgers.
mod common;
use agf_core::error::{DomainError, DomainResult};
use common::*;
const PATH: &str = "/api/v1/models/usage/projection-status";
#[tokio::test]
async fn projection_status_is_read_only_and_requires_models_read_without_exposing_other_tenant_amounts()
-> DomainResult<()> {
    let h = setup().await;
    let reader =
        h.post("/api/v1/settings/api-keys", json!({"name":"owned-meter-health-reader","scopes":["models:read"]})).await;
    assert_eq!(reader.status, StatusCode::CREATED);
    let denied =
        h.post("/api/v1/settings/api-keys", json!({"name":"owned-meter-health-denied","scopes":["assets:read"]})).await;
    assert_eq!(denied.status, StatusCode::CREATED);
    let token = |response: &Resp| -> DomainResult<String> {
        Ok(format!(
            "Bearer {}",
            response.json()["plaintext"]
                .as_str()
                .ok_or_else(|| DomainError::Internal("owned fixture key missing".into()))?
        ))
    };
    let reader = token(&reader)?;
    let denied = token(&denied)?;
    h.state.meter.mark_committed_projection_incomplete();
    let audit = h.state.store.audit_stats_durable(h.tenant).await?;
    let checkpoint = h.state.configurations.list::<Value>(h.tenant, "gateway-meter-checkpoint-v1").await?;
    let usage = h.state.configurations.list::<Value>(h.tenant, "model-usage").await?;
    for _ in 0..2 {
        let response = h.request_with("GET", PATH, &[("authorization", reader.as_str())], None).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.json(),
            json!({"scope":"node","readOnly":true,"committedProjectionIncomplete":true,
            "committedGroupsMerged":false,"maxUsageRecordsPerTenant":512,"maxFactsPerTenant":512,"maxWitnessBytesPerTenant":8_388_608})
        );
    }
    assert_eq!(
        h.request_with("GET", PATH, &[("authorization", denied.as_str())], None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.request("GET", PATH, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert!(h.get("/api/v1/models/usage/aggregate").await.json().is_array());
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "gateway-meter-checkpoint-v1").await?, checkpoint);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "model-usage").await?, usage);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, audit);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

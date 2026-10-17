//! Stateful, tenant/version/instance/Worker-scoped quota simulation; it never calls a vendor.
use crate::{integration_store::Stored, state::AppState};
use agf_core::{
    error::DomainResult,
    ids::{TenantId, deterministic_id},
};
use serde_json::Value;

pub(crate) async fn response(
    state: &AppState,
    tenant: TenantId,
    config: &Stored,
    action: &str,
    input: &Value,
    mut fixture: Value,
) -> DomainResult<Value> {
    if !matches!(action, "GetWorker" | "UpdateWorker") {
        return Ok(fixture);
    }
    let Some(worker) = input["Name"].as_str() else {
        return Ok(fixture);
    };
    // Unknown resources retain the example identity and cannot pass a bound Worker's identity check.
    if fixture["Data"]["Name"] != worker {
        return Ok(fixture);
    }
    let instance = input["InstanceId"].as_str().unwrap_or_default();
    let id = deterministic_id(
        "agf.worker-quota.mock",
        &format!("{tenant}:{}:{}:{instance}:{worker}", config.id, config.version),
    );
    let kind = "agentteams-worker-quota-mock";
    if action == "UpdateWorker" {
        if let Some(limit) = input.get("LimitConfig") {
            // The public operation permits partial updates. Merge only catalog writable fields;
            // the administrative Worker quota binding itself separately requires token/day.
            let current = state
                .configurations
                .mutate::<Value, _>(tenant, kind, id, |current| {
                    if current.is_null() {
                        *current = fixture["Data"]["LimitConfig"].clone();
                    }
                    for key in ["UsageLimit", "LimitType", "PeriodType"] {
                        if let Some(value) = limit.get(key) {
                            current[key] = value.clone();
                        }
                    }
                    Ok(())
                })
                .await?;
            fixture["Data"]["LimitConfig"] = current;
        }
    } else if let Some(limit) = state.configurations.get::<Value>(tenant, kind, id).await? {
        // Keep read-only vendor observations separate; only configuration changes are simulated.
        for key in ["UsageLimit", "LimitType", "PeriodType"] {
            fixture["Data"]["LimitConfig"][key] = limit[key].clone();
        }
        if let Some(used) = fixture["Data"]["LimitConfig"]["UsedAmount"].as_i64() {
            fixture["Data"]["LimitConfig"]["OverLimit"] =
                Value::Bool(used >= limit["UsageLimit"].as_i64().unwrap_or(i64::MAX));
        }
    }
    Ok(fixture)
}

//! Only guarded observations change quota-drift alerts; they imply no authorization verdict.
use super::{
    context::Resolved,
    contract::{Binding, Drift, Operation},
};
use crate::state::AppState;
use agf_core::{
    alert::Alert,
    enums::{AlertState, Severity},
    error::DomainResult,
    ids::TenantId,
};
use agf_storage::{AlertRepo, TenantTransaction};
use sha2::{Digest, Sha256};

struct Evidence {
    fingerprint: String,
    description: String,
}
enum Decision {
    Keep,
    Aligned,
    Drift(Evidence),
}

fn evidence(row: &Binding, resolved: &Resolved, operation: Option<&Operation>) -> Decision {
    let Some(observation) = row.observation.as_ref() else {
        return Decision::Keep;
    };
    if !observation.preview_usable
        && !operation.is_some_and(|run| {
            run.status == "verified" && run.observation.as_ref().is_some_and(|value| value.id == observation.id)
        })
    {
        return Decision::Keep;
    }
    let cloud = &observation.cloud;
    if cloud.usage_limit == resolved.quota.quota.limit && cloud.limit_type == "token" && cloud.period_type == "day" {
        return Decision::Aligned;
    }
    let input = serde_json::json!([
        row.scope_id,
        row.version,
        resolved.quota.version,
        cloud.usage_limit,
        cloud.limit_type,
        cloud.period_type,
        resolved.quota.quota.limit,
        row.mocked
    ])
    .to_string();
    let fingerprint = format!("{:x}", Sha256::digest(input.as_bytes()));
    let description = format!(
        "quota-drift：Worker {} 的云限制 {}/{}/{} 与平台期望 {}/token/day 不符。\
        平台按 UTC 日计量；云周期、已用量及是否执行独立核对。Mock={}。本告警不推断权限或越权。",
        row.worker_name, cloud.usage_limit, cloud.limit_type, cloud.period_type, resolved.quota.quota.limit, row.mocked
    );
    Decision::Drift(Evidence { fingerprint, description })
}

pub(super) async fn sql(
    tx: &mut TenantTransaction<'_>,
    row: &mut Binding,
    resolved: &Resolved,
    operation: Option<&Operation>,
) -> DomainResult<Option<Alert>> {
    let evidence = match evidence(row, resolved, operation) {
        Decision::Keep => return Ok(None),
        Decision::Aligned => {
            let Some(drift) = row.drift.take() else {
                return Ok(None);
            };
            AlertRepo::set_state(tx, drift.alert_id, AlertState::Closed, None).await?;
            return AlertRepo::get(tx, drift.alert_id).await;
        }
        Decision::Drift(evidence) => evidence,
    };
    if row.drift.as_ref().is_some_and(|drift| drift.fingerprint == evidence.fingerprint) {
        return Ok(None);
    }
    if let Some(drift) = row.drift.take() {
        AlertRepo::set_state(tx, drift.alert_id, AlertState::Closed, None).await?;
    }
    let key = format!("quota-drift:{}:{}:{}", tx.tenant(), row.asset_id, evidence.fingerprint);
    let (id, _) = AlertRepo::upsert_dedup(
        tx,
        &key,
        "Worker 配额限制冲突 (quota-drift)",
        &evidence.description,
        Severity::Medium,
        None,
        &[row.asset_id],
        &[],
        None,
    )
    .await?;
    sqlx::query("UPDATE alerts SET tags=$1 WHERE id=$2")
        .bind(serde_json::json!(["quota-drift", if row.mocked { "mocked" } else { "live" }]))
        .bind(id.as_uuid())
        .execute(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("worker_quota_alert", &error))?;
    row.drift = Some(Drift { fingerprint: evidence.fingerprint, alert_id: id });
    AlertRepo::get(tx, id).await
}

pub(super) fn memory(
    state: &AppState,
    tenant: TenantId,
    row: &mut Binding,
    resolved: &Resolved,
    operation: Option<&Operation>,
) -> DomainResult<()> {
    let evidence = match evidence(row, resolved, operation) {
        Decision::Keep => return Ok(()),
        Decision::Aligned => {
            if let Some(drift) = row.drift.take() {
                state.store.alert_set_state(tenant, drift.alert_id, AlertState::Closed, None)?;
            }
            return Ok(());
        }
        Decision::Drift(evidence) => evidence,
    };
    if row.drift.as_ref().is_some_and(|drift| drift.fingerprint == evidence.fingerprint) {
        return Ok(());
    }
    if let Some(drift) = row.drift.take() {
        state.store.alert_set_state(tenant, drift.alert_id, AlertState::Closed, None)?;
    }
    let key = format!("quota-drift:{tenant}:{}:{}", row.asset_id, evidence.fingerprint);
    let (id, _) = state.store.alert_upsert_dedup(
        tenant,
        &key,
        "Worker 配额限制冲突 (quota-drift)",
        &evidence.description,
        Severity::Medium,
        None,
        &[row.asset_id],
        &[],
    )?;
    if let Some(mut alert) = state.store.alert_get(tenant, id)? {
        alert.tags = vec!["quota-drift".into(), if row.mocked { "mocked" } else { "live" }.into()];
        state.store.hydrate_alert(&alert)?;
    }
    row.drift = Some(Drift { fingerprint: evidence.fingerprint, alert_id: id });
    Ok(())
}

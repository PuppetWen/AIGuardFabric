//! Versioned escalation policy and tenant-scoped enqueue receipts; never expose channel credentials.
use crate::{
    alert_escalation as config, error::ApiResult, middleware::Principal, query::ListQuery, routes::ApiJson,
    state::AppState,
};
use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_storage::map_sqlx_err;
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Value, json};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alerts/escalation-config", get(read).put(save))
        .route("/alerts/escalation-history", get(history))
}

async fn read(State(state): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require(&state, "alerts", "read")?;
    let configuration = config::get(&state, p.tenant).await?;
    let channels: Vec<_> = config::channels(&state, p.tenant)
        .await?
        .into_iter()
        .map(|row| json!({"channel":row.channel,"enabled":row.enabled,"minSeverity":row.min_severity}))
        .collect();
    let health: Option<Value> = state.configurations.get(p.tenant, config::HEALTH, config::id(p.tenant)).await?;
    Ok(Json(json!({"version":configuration.version,"policies":configuration.policies,
        "history":configuration.history,"canWrite":config::can_write(&state,&p),"channels":channels,
        "automaticAvailable":state.store.has_database(),"mockMode":state.config.mock_mode,"health":health})))
}

async fn save(
    State(state): State<AppState>,
    p: Principal,
    ApiJson(input): ApiJson<config::Change>,
) -> ApiResult<Json<Value>> {
    p.require(&state, "alerts", "write")?;
    let saved = config::save(&state, &p, input).await?;
    state
        .audit(
            p.tenant,
            AuditAction::Configure,
            AuditOutcome::Success,
            AppState::audit_actor(&p, "alert-escalation"),
            AuditTarget::new("alert-escalation-policy", Some(config::id(p.tenant).to_string()), None),
            "已保存升级策略；发布者、说明和策略版本已持久化",
        )
        .await?;
    Ok(Json(json!({"version":saved.version,"policies":saved.policies,"history":saved.history})))
}

async fn history(State(state): State<AppState>, p: Principal, query: ListQuery) -> ApiResult<Json<Value>> {
    p.require(&state, "alerts", "read")?;
    let Some(database) = state.store.database() else {
        return Ok(Json(json!({"items":[],"total":0,"page":query.page,"pageSize":query.page_size})));
    };
    let mut tx = database.db().begin_tenant(p.tenant).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM alert_escalation_receipts")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_sqlx_err("count_escalation_history", &e))?;
    let mut rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(r) || jsonb_build_object('title',a.title) FROM alert_escalation_receipts r
         LEFT JOIN alerts a ON a.id=r.alert_id AND a.deleted_at IS NULL
         ORDER BY r.enqueued_at DESC,r.alert_id,r.tier LIMIT $1 OFFSET $2",
    )
    .bind(i64::from(query.page_size))
    .bind(i64::from(query.page - 1) * i64::from(query.page_size))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| map_sqlx_err("list_escalation_history", &e))?;
    tx.commit().await?;
    let deliveries = crate::notification_outbox::history(&state, p.tenant).await?;
    for row in &mut rows {
        let receipts: Vec<_> = row["notification_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|id| {
                deliveries
                    .iter()
                    .find(|d| d["id"] == *id)
                    .map_or_else(|| json!({"id":id,"status":"expired"}), Clone::clone)
            })
            .collect();
        row["notifications"] = json!(receipts);
    }
    Ok(Json(json!({"items":rows,"total":total,"page":query.page,"pageSize":query.page_size})))
}

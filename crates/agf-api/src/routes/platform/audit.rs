//! 审计端点：列表 / 审计链校验 / 统计。

use super::*;
use agf_storage::AuditSelection;

// ===========================================================================
// 审计
// ===========================================================================

/// 审计列表（`GET /api/v1/audit`）。
///
/// # Errors
/// 过滤参数非法。
pub async fn list_audit(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "audit", "read")?;
    let page_size = query
        .filter_i64("limit")?
        .map_or(query.page_size, |limit| u32::try_from(limit.clamp(1, 200)).unwrap_or(200).min(query.page_size));
    let selection = AuditSelection {
        from_sequence: query.filter_i64("from_sequence")?.unwrap_or(0),
        action: query.filter("action").map(str::to_owned),
        outcome: query.filter("outcome").map(str::to_owned),
        actor: query.filter("actor").map(str::to_owned),
        search: query.q.clone(),
        sensitive_only: query.filter_bool("sensitive_only")?.unwrap_or(false),
        page: query.page,
        page_size,
        descending: query.descending(),
    };
    let (entries, total) = state.store.audit_page_durable(principal.tenant, selection).await?;
    let mut page_request = query.to_page_request();
    page_request.page_size = page_size;
    let page = agf_core::pagination::Page::new(entries, total, &page_request);
    Ok(Json(query.render_page(&page)?))
}

/// 哈希链校验报告（`GET /api/v1/audit/verify`）。
///
/// # Errors
/// 权限不足。
pub async fn verify_audit_chain(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "audit", "read")?;
    let anchored = crate::audit_anchor::verify_management(&state, principal.tenant).await?;
    let verification = &anchored.chain;
    let violations: Vec<serde_json::Value> = verification
        .violations
        .iter()
        .map(|v| {
            serde_json::json!({
                "entry_id": v.entry_id,
                "sequence": v.sequence,
                "kind": v.kind,
                "detail": v.detail,
            })
        })
        .collect();
    let (count, tail) = state.store.audit_stats_durable(principal.tenant).await?;
    Ok(Json(serde_json::json!({
        "checked": verification.checked,
        "passed": verification.passed && anchored.anchors_valid,
        "violations": violations,
        "first_sequence": verification.first_sequence,
        "last_sequence": verification.last_sequence,
        "verified_at": verification.verified_at,
        "chain": { "entries": count, "tail_hash": tail.clone(), "source": if state.store.has_database() { "postgres" } else { "memory" } },
        "memory_chain": if state.store.has_database() { serde_json::Value::Null } else { serde_json::json!({ "entries": count, "tail_hash": tail }) },
        "postgres_backed": state.store.has_database(),
        "anchoring": {
            "valid": anchored.anchors_valid,
            "checkpoints_checked": anchored.anchors_checked,
            "unsigned_legacy_checkpoints": anchored.unsigned_legacy_checkpoints,
            "latest": anchored.latest,
            "fully_anchored": anchored.fully_anchored,
            "violations": anchored.violations,
            "durable": state.store.has_database(),
            "initial_checkpoint_required": anchored.anchors_checked == 0,
            "historical_protection": "首个检查点不能证明建立前的历史；仅有签名前缀及保留的外部见证构成锚定保护。",
        },
        "note": if state.store.has_database() { "本报告基于 PostgreSQL 已提交审计链" } else { "离线模式：本报告基于进程内存审计链" },
    })))
}

/// 审计链统计（`GET /api/v1/audit/stats`）。
///
/// # Errors
/// 权限不足。
pub async fn audit_stats(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "audit", "read")?;
    let (count, tail) = state.store.audit_stats_durable(principal.tenant).await?;
    let entries = state.store.audit_chain_durable(principal.tenant, 0, 1_000).await?;
    let mut by_action: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_outcome: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for entry in &entries {
        *by_action.entry(entry.action.as_str().to_string()).or_insert(0) += 1;
        *by_outcome.entry(entry.outcome.as_str().to_string()).or_insert(0) += 1;
    }
    Ok(Json(serde_json::json!({
        "entries": count,
        "tail_hash": tail,
        "sampled": entries.len(),
        "by_action": by_action,
        "by_outcome": by_outcome,
        "genesis_hash": agf_core::audit::GENESIS_HASH,
    })))
}

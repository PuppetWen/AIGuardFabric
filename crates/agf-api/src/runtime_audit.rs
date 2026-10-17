//! 合并当前进程审计与已持久化拦截记录，重启后控制台仍可追溯。
use crate::state::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
};
use agf_runtime::audit::InterceptionRecord;
use std::collections::BTreeMap;
mod integrity;
mod publication;
pub use integrity::RecordIntegrity;

/// 原子提交单条 MCP 策略事实及脱敏管理审计；同编号只接受完全相同的原提交。
///
/// # Errors
/// 身份、记录摘要、原证明、保存预算或事务提交不满足时拒绝。
pub async fn persist(state: &AppState, principal: &crate::Principal, record: &InterceptionRecord) -> DomainResult<()> {
    publication::persist(state, principal, record).await
}

/// 有界核对单条持久事实与管理审计；不把摘要匹配宣称为已验证签名检查点。
///
/// # Errors
/// 权限不足、存储锁或读取失败。
pub async fn integrity(state: &AppState, principal: &crate::Principal, id: Id) -> DomainResult<RecordIntegrity> {
    integrity::read(state, principal, id).await
}

pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<InterceptionRecord>> {
    let mut records: BTreeMap<_, _> = state
        .configurations
        .list::<InterceptionRecord>(tenant, "runtime-interception")
        .await?
        .into_iter()
        .map(|row| (row.id, row))
        .collect();
    for row in state.runtime.audit().by_tenant(tenant) {
        records.insert(row.id, row);
    }
    let mut rows: Vec<_> = records.into_values().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.at));
    Ok(rows)
}

//! MCP 策略事实与脱敏管理审计原子提交；环形缓冲区不作为持久性证明。
use crate::{AppState, Principal, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_runtime::audit::InterceptionRecord;
use agf_storage::configuration::{ConditionalMutation, MutationDecision};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const KIND: &str = "runtime-interception";
pub(super) const PROOF: &str = "_agf_management_audit_v1";
const MAX_RECORD: usize = 64 * 1024;

pub(super) async fn persist(state: &AppState, principal: &Principal, record: &InterceptionRecord) -> DomainResult<()> {
    principal.require(state, "policies", "read").map_err(|error| error.error)?;
    if record.tenant_id != principal.tenant || record.id.is_nil() || record.entry_hash != record.compute_hash() {
        return Err(DomainError::Validation("运行时记录身份或内容摘要不一致".into()));
    }
    let mut value = serde_json::to_value(record)?;
    let bytes = canonical_bytes(&value)?;
    if bytes.len() > MAX_RECORD {
        return Err(DomainError::PreconditionFailed("运行时记录超过 64 KiB 保存预算".into()));
    }
    let hash = hex::encode(Sha256::digest(&bytes));
    let audit = audit(principal, record, &hash);
    value[PROOF] = json!({"record_sha256":hash,"audit_id":audit.id});
    current(state, principal).await?;
    if let Some(db) = state.store.database() {
        let tx = AssetTransaction::begin(db, principal.tenant).await?;
        tx.tenant_enabled().await?;
        tx.configuration_lock(KIND, record.id).await?;
        let previous = tx.runtime_interception(record.id).await?;
        if unchanged(previous.as_ref(), &value)? {
            let saved = tx.runtime_audit_entry(audit.id).await?;
            verify_saved(principal.tenant, record.id, &value, saved.as_ref())?;
            tx.runtime_authorize(state, principal).await?;
            return tx.commit(&state.store).await;
        }
        tx.configure(KIND, record.id, Some(value)).await?;
        tx.audit(audit).await?;
        // 使用原事务读取当前主体及绑定，不能持有连接再向同一池借第二条连接。
        // 这不等于重新验证原 JWT 的等待期 exp。
        tx.runtime_authorize(state, principal).await?;
        tx.commit(&state.store).await?;
    } else {
        state
            .configurations
            .mutate_conditional_audited::<Value, _, _>(
                principal.tenant,
                ConditionalMutation { kind: KIND, id: record.id, guard: None },
                |_, previous| {
                    if unchanged((!previous.is_null()).then_some(&*previous), &value)? {
                        let saved = state.store.runtime_audit_entry(principal.tenant, audit.id)?;
                        verify_saved(principal.tenant, record.id, &value, saved.as_ref())?;
                        return Ok(MutationDecision::Unchanged);
                    }
                    *previous = value;
                    Ok(MutationDecision::Write(Some(Box::new(audit))))
                },
                |entry| state.store.audit_append(entry).map(Some),
            )
            .await?;
    }
    Ok(())
}

async fn current(state: &AppState, principal: &Principal) -> DomainResult<()> {
    let fresh = crate::soar_workflow::Actor::from_principal(principal)?
        .resolve_for(state, principal.tenant, "policies", "read")
        .await?;
    if fresh.subject_id != principal.subject_id
        || fresh.subject_kind != principal.subject_kind
        || fresh.identity_tenant != principal.identity_tenant
        || fresh.agent_id != principal.agent_id
    {
        return Err(DomainError::Forbidden("运行时保存的原主体或绑定 Agent 已改变".into()));
    }
    Ok(())
}

fn unchanged(previous: Option<&Value>, expected: &Value) -> DomainResult<bool> {
    match previous {
        None => Ok(false),
        Some(value) if value == expected => Ok(true),
        // 不为历史无证明记录补造认证，也不覆盖同编号的不同字节。
        Some(_) => Err(DomainError::Conflict("运行时记录编号已有不同内容或缺少原始保存证明".into())),
    }
}

fn verify_saved(tenant: agf_core::ids::TenantId, id: Id, value: &Value, audit: Option<&AuditLog>) -> DomainResult<()> {
    if !super::integrity::inspect(tenant, id, Some(value), audit)?.summary_matches {
        return Err(DomainError::Conflict("运行时记录的原管理审计证明缺失或不一致".into()));
    }
    Ok(())
}

// 明确按键排序，不能依赖 serde_json preserve_order 特性或 PostgreSQL JSONB 的键顺序。
pub(super) fn canonical_bytes(value: &Value) -> DomainResult<Vec<u8>> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    Ok(serde_json::to_vec(&sorted(value))?)
}

pub(super) fn audit_id(tenant: agf_core::ids::TenantId, id: Id) -> Id {
    let digest = Sha256::digest(format!("agf.runtime-interception.audit.v1:{tenant}:{id}"));
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Id::from_uuid(uuid::Uuid::from_bytes(bytes))
}

pub(super) fn summary(record: &InterceptionRecord, hash: &str) -> Value {
    json!({"schema":"agf-runtime-interception-fact-v1","record_id":record.id,
        "record_sha256":hash,"agent_id":record.agent_id,"point":record.intercept_point,
        "action":record.action,"verdict":record.verdict,"enforced":record.enforced})
}

fn audit(principal: &Principal, record: &InterceptionRecord, hash: &str) -> AuditLog {
    let mut actor = AppState::audit_actor(principal, "runtime-mcp-fact");
    // 请求头 User-Agent 与登录会话字段不属于策略事实摘要，不能把客户端任意文本带入此审计。
    actor.user_agent = None;
    actor.session_id = None;
    let mut entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Execute,
        AuditOutcome::Success,
        actor,
        AuditTarget::new("runtime-interception-fact", Some(record.id.to_string()), None),
        "已保存运行时策略决策摘要；不证明上游已执行",
    );
    // 用途域、租户和记录编号派生稳定标识；不接收客户端指定的审计字段。
    entry.id = audit_id(principal.tenant, record.id);
    entry.request_id = Some(record.id.to_string());
    entry.after = Some(summary(record, hash));
    entry
}

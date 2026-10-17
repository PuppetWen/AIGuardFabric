//! 单条事实比对不扫描整条链；签名检查点与外部见证由独立 audit/verify 合同验证。
use super::publication::{KIND, PROOF, audit_id, canonical_bytes, summary};
use crate::{AppState, Principal, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_runtime::audit::InterceptionRecord;
use agf_storage::configuration::{ConditionalMutation, MutationDecision};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

/// 一条已保存记录与管理审计摘要的匹配结果；字段不含原载荷或审计操作者。
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordIntegrity {
    /// 当前认证租户内的记录编号。
    pub record_id: String,
    /// missing-record / missing-proof / mismatch / matched-management-fact。
    pub status: String,
    /// 仅表示本次读取的记录、原证明及管理审计内容相匹配。
    pub summary_matches: bool,
    /// 本入口不执行全链 HMAC 和外部见证校验，始终为 false。
    pub checkpoint_verified: bool,
    /// 用于独立检查签名检查点及外部见证的公开入口。
    pub checkpoint_verification_path: String,
    /// 匹配成功时的规范化完整记录 SHA-256，不含保存证明字段。
    pub record_sha256: Option<String>,
    /// 匹配成功时的管理审计编号。
    pub audit_id: Option<String>,
    /// 可与 audit/verify 检查点序号核对的管理审计序号。
    pub audit_sequence: Option<i64>,
    /// 匹配的管理审计条目哈希；本身不证明全链已锚定。
    pub audit_entry_hash: Option<String>,
}

pub(super) async fn read(state: &AppState, principal: &Principal, id: Id) -> DomainResult<RecordIntegrity> {
    principal.require(state, "policies", "read").map_err(|error| error.error)?;
    let audit = audit_id(principal.tenant, id);
    if let Some(db) = state.store.database() {
        let tx = AssetTransaction::begin(db, principal.tenant).await?;
        tx.tenant_enabled().await?;
        tx.configuration_lock(KIND, id).await?;
        let value = tx.runtime_interception(id).await?;
        let entry = tx.runtime_audit_entry(audit).await?;
        let result = inspect(principal.tenant, id, value.as_ref(), entry.as_ref())?;
        tx.commit(&state.store).await?;
        return Ok(result);
    }
    let mut result = None;
    // Unchanged 在 ConfigStore 内存锁内执行；精确 audit lookup 不重入 ConfigStore。
    state
        .configurations
        .mutate_conditional_audited::<Value, _, _>(
            principal.tenant,
            ConditionalMutation { kind: KIND, id, guard: None },
            |_, stored| {
                let entry = state.store.runtime_audit_entry(principal.tenant, audit)?;
                result = Some(inspect(principal.tenant, id, (!stored.is_null()).then_some(&*stored), entry.as_ref())?);
                Ok(MutationDecision::Unchanged)
            },
            |_| Err(DomainError::Internal("只读完整性检查不得追加审计".into())),
        )
        .await?;
    result.ok_or_else(|| DomainError::Internal("完整性读取未产生结果".into()))
}

pub(super) fn inspect(
    tenant: TenantId,
    id: Id,
    value: Option<&Value>,
    audit: Option<&AuditLog>,
) -> DomainResult<RecordIntegrity> {
    let mut result = RecordIntegrity {
        record_id: id.to_string(),
        status: "missing-record".into(),
        summary_matches: false,
        checkpoint_verified: false,
        checkpoint_verification_path: "/api/v1/audit/verify".into(),
        record_sha256: None,
        audit_id: None,
        audit_sequence: None,
        audit_entry_hash: None,
    };
    let Some(value) = value else { return Ok(result) };
    if value.is_null() {
        result.status = "mismatch".into();
        return Ok(result);
    }
    let Some(proof) = value.get(PROOF) else {
        result.status = "missing-proof".into();
        return Ok(result);
    };
    result.status = "mismatch".into();
    let Ok(record) = serde_json::from_value::<InterceptionRecord>(value.clone()) else { return Ok(result) };
    let mut raw = value.clone();
    let Some(object) = raw.as_object_mut() else { return Ok(result) };
    object.remove(PROOF);
    // 未知字段、被删字段及重新计算过内存链 hash 的内容都不能绕过原提交 SHA。
    if record.id != id || record.tenant_id != tenant || !record.verify() || raw != serde_json::to_value(&record)? {
        return Ok(result);
    }
    let hash = hex::encode(Sha256::digest(canonical_bytes(&raw)?));
    let expected_id = audit_id(tenant, id);
    if *proof != json!({"record_sha256":hash,"audit_id":expected_id}) {
        return Ok(result);
    }
    let Some(entry) = audit else { return Ok(result) };
    if entry.id != expected_id
        || entry.tenant_id != tenant
        || !entry.verify()
        || entry.sequence < 1
        || entry.action != AuditAction::Execute
        || entry.outcome != AuditOutcome::Success
        || entry.target.kind != "runtime-interception-fact"
        || entry.target.id.as_deref() != Some(id.to_string().as_str())
        || entry.request_id.as_deref() != Some(id.to_string().as_str())
        || entry.after != Some(summary(&record, &hash))
    {
        return Ok(result);
    }
    result.status = "matched-management-fact".into();
    result.summary_matches = true;
    result.record_sha256 = Some(hash);
    result.audit_id = Some(entry.id.to_string());
    result.audit_sequence = Some(entry.sequence);
    result.audit_entry_hash = Some(entry.entry_hash.clone());
    Ok(result)
}

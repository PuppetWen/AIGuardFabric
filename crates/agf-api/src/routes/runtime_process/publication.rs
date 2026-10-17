//! 脱敏回执与管理审计一起提交；重复随机标识不能再次授权启动。
use super::*;
use crate::{policy_store::OfflinePublicationProof, store::asset_transaction::AssetTransaction};
use agf_core::audit::AuditLog;
use agf_storage::configuration::OfflineGuardedMutation;

pub(super) async fn commit(
    state: &AppState,
    submission: &Submission,
    receipt: &ProcessReceipt,
    record: &InterceptionRecord,
    audit: AuditLog,
) -> DomainResult<()> {
    submission.current(state).await?;
    if let Some(db) = state.store.database() {
        let tx = AssetTransaction::begin(db, submission.principal.tenant).await?;
        tx.tenant_enabled().await?;
        tx.configuration_lock(KIND, receipt.request_id).await?;
        if tx.configuration::<serde_json::Value>(KIND, receipt.request_id).await?.is_some() {
            return Err(duplicate());
        }
        tx.configure(KIND, receipt.request_id, Some(serde_json::to_value(receipt)?)).await?;
        tx.configure("runtime-interception", record.id, Some(serde_json::to_value(record)?)).await?;
        tx.audit(audit).await?;
        submission.current(state).await?;
        submission.budget()?;
        tx.commit(&state.store).await?;
    } else {
        let authorization = submission.borrowed();
        let proof = OfflinePublicationProof::prepare(state, &authorization).await?;
        state.configurations.mutate_offline_guarded_audited(
            submission.principal.tenant,
            OfflineGuardedMutation {
                kind: KIND,
                id: receipt.request_id,
                guards: &[],
                security: Some(OfflinePublicationProof::security(&authorization)?),
            },
            |_, stored: &mut Option<ProcessReceipt>| {
                if stored.is_some() {
                    return Err(duplicate());
                }
                *stored = Some(receipt.clone());
                Ok(((), audit.clone()))
            },
            |log, locked| {
                proof.check(state, &authorization, locked)?;
                submission.budget()?;
                state.store.audit_append(log)
            },
        )?;
        // 离线模式明确仅存于内存；持久部署使用上面的 SQL 事务，不把内存提交宣称为跨重启持久化。
        state.configurations.put(submission.principal.tenant, "runtime-interception", record.id, record).await?;
    }
    Ok(())
}
fn duplicate() -> DomainError {
    DomainError::Conflict("Original process nonce already committed; do not launch again".into())
}

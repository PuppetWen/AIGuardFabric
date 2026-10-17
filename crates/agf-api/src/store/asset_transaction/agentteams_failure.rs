//! Original immutable task-error evidence is rechecked under the publication transaction.
use super::AssetTransaction;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_ingest::pipeline::{AgentTeamsAuditRecord, agentteams_failure_from_envelope};
use serde_json::Value;

impl AssetTransaction<'_> {
    pub(crate) async fn agentteams_failure_record(&self, id: Id) -> DomainResult<Option<AgentTeamsAuditRecord>> {
        if id.is_nil() {
            return Err(DomainError::Crypto("Original collector UUID is invalid".into()));
        }
        let mut tx = self.transaction(self.tenant).await?;
        let rows: Vec<Value> = sqlx::query_scalar(
            "SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'source_id',source_id,
             'scope_id',scope_id,'binding_id',binding_id,'external_event_id',external_event_id,'content_hash',content_hash,
             'event_time',event_time,'received_at',received_at,'kind',kind,'payload',payload)
             FROM agentteams_audit WHERE tenant_id=$1 AND id=$2 AND kind='task'
             AND payload->>'status'='error' LIMIT 2 FOR SHARE",
        ).bind(self.tenant.as_uuid()).bind(id.as_uuid()).fetch_all(&mut **tx).await
            .map_err(|error| agf_storage::map_sqlx_err("task_handling_original_evidence", &error))?;
        if rows.len() > 1 {
            return Err(DomainError::Crypto("Original collector UUID is duplicated".into()));
        }
        rows.into_iter().next().map(|value| agentteams_failure_from_envelope(value, self.tenant)).transpose()
    }
}

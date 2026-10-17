//! Typed child only; callers cannot borrow a raw SQL executor or choose arbitrary repositories.
use super::*;
use agf_core::risk::Finding;
use agf_storage::FindingRepo;

impl AssetTransaction<'_> {
    pub(crate) async fn multi_target_uuid_reserved(&self, id: Id) -> DomainResult<bool> {
        let mut tx = self.transaction(self.tenant).await?;
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM console_configurations WHERE tenant_id=$1 AND kind='redteam-multi-target-fact' AND id=$2)")
            .bind(self.tenant.as_uuid()).bind(id.as_uuid()).fetch_one(&mut **tx).await
            .map_err(|error|agf_storage::map_sqlx_err("redteam_permanent_uuid",&error))
    }
    pub(crate) async fn multi_target_fact_count(&self) -> DomainResult<u64> {
        let mut tx = self.transaction(self.tenant).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM console_configurations WHERE tenant_id=$1 AND kind='redteam-multi-target-fact'",
        )
        .bind(self.tenant.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("redteam_permanent_fact_count", &error))?;
        u64::try_from(count).map_err(|_| DomainError::Crypto("Permanent fact count is invalid".into()))
    }
    pub(crate) async fn multi_target_registry(&self, kind: &str, id: Id) -> DomainResult<Option<serde_json::Value>> {
        if !["redteam-agent-targets", "redteam-mcp-targets"].contains(&kind)
            || id != crate::model_routes::tenant_record_id(self.tenant)
        {
            return Err(DomainError::Validation(
                "Only the canonical registered red-team target registry is readable here".into(),
            ));
        }
        let mut tx = self.transaction(self.tenant).await?;
        let row:Option<(bool,Option<serde_json::Value>)>=sqlx::query_as(
            "SELECT octet_length(payload::text)<=524288,CASE WHEN octet_length(payload::text)<=524288 THEN payload END FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE")
            .bind(kind).bind(id.as_uuid()).fetch_optional(&mut **tx).await
            .map_err(|error|agf_storage::map_sqlx_err("redteam_registry_bounded",&error))?;
        match row {
            Some((true, Some(value))) => Ok(Some(value)),
            None => Ok(None),
            _ => Err(DomainError::PreconditionFailed("Registered target registry exceeds 512 KiB".into())),
        }
    }
    pub(crate) async fn publish_multi_target_findings(&self, findings: &[Finding]) -> DomainResult<()> {
        if findings.len() > 3 || findings.iter().any(|f| f.tenant_id != self.tenant || f.asset_id.is_none()) {
            return Err(DomainError::Validation("Multi-target finding identity/budget is invalid".into()));
        }
        let mut tx = self.transaction(self.tenant).await?;
        for finding in findings {
            FindingRepo::insert(&mut tx, finding).await?;
        }
        Ok(())
    }
}

//! PostgreSQL is the audit-chain authority when configured; offline mode keeps the memory chain.
use super::*;
use agf_core::audit::{ChainVerification, ChainVerifier, verify_chain};
use agf_storage::{AuditRepo, AuditSelection};

impl ApiStore {
    /// Filter and page the entire tenant chain without truncating before selection.
    pub async fn audit_page_durable(
        &self,
        tenant: TenantId,
        selection: AuditSelection,
    ) -> DomainResult<(Vec<AuditLog>, i64)> {
        if let Some(database) = &self.database {
            return database
                .with_tenant(tenant, move |tx| Box::pin(async move { AuditRepo::list_page(tx, &selection).await }))
                .await;
        }
        let mut rows = self.audit_chain(tenant, selection.from_sequence, i64::MAX)?;
        rows.retain(|entry| selection.matches(entry));
        let total = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        if selection.descending {
            rows.reverse();
        }
        let offset = usize::try_from(selection.offset()).unwrap_or(usize::MAX);
        let size = usize::try_from(selection.page_size).unwrap_or(usize::MAX);
        Ok((rows.into_iter().skip(offset).take(size).collect(), total))
    }

    /// Commit the sealed entry before returning to the request handler.
    pub async fn audit_append_durable(&self, entry: AuditLog) -> DomainResult<AuditLog> {
        let Some(database) = &self.database else { return self.audit_append(entry) };
        let tenant = entry.tenant_id;
        let sealed = database
            .with_tenant(tenant, move |tx| Box::pin(async move { AuditRepo::append_log(tx, entry).await }))
            .await?;
        // The projection is optional: another instance can append between local writes.
        if let Err(error) = self.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交审计写入内存投影失败");
        }
        Ok(sealed)
    }

    /// Read the committed chain, including entries written by other API instances.
    pub async fn audit_chain_durable(
        &self,
        tenant: TenantId,
        from_sequence: i64,
        limit: i64,
    ) -> DomainResult<Vec<AuditLog>> {
        let Some(database) = &self.database else { return self.audit_chain(tenant, from_sequence, limit) };
        database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move { AuditRepo::load_chain(tx, from_sequence, limit).await })
            })
            .await
    }

    /// Return the committed count and tail hash, not the process-local projection.
    pub async fn audit_stats_durable(&self, tenant: TenantId) -> DomainResult<(i64, String)> {
        let Some(database) = &self.database else { return self.audit_stats(tenant) };
        database.with_tenant(tenant, |tx| Box::pin(async move { AuditRepo::chain_stats(tx).await })).await
    }

    /// Verify the whole committed chain in bounded pages, including page boundaries.
    pub async fn audit_verify_durable(&self, tenant: TenantId) -> DomainResult<ChainVerification> {
        let Some(database) = &self.database else {
            return Ok(verify_chain(&self.audit_chain(tenant, 0, i64::MAX)?));
        };
        database
            .with_tenant(tenant, |tx| {
                Box::pin(async move {
                    let mut verifier = ChainVerifier::new();
                    let mut cursor = 0_i64;
                    loop {
                        let rows = AuditRepo::load_chain(tx, cursor, 1_000).await?;
                        if rows.is_empty() {
                            break;
                        }
                        let count = rows.len();
                        for row in &rows {
                            verifier.push(row);
                        }
                        let last = rows.last().map_or(cursor, |row| row.sequence);
                        if count < 1_000 || last == i64::MAX {
                            break;
                        }
                        cursor = last + 1;
                    }
                    Ok(verifier.finish())
                })
            })
            .await
    }
}

//! Bounded, tenant-scoped audit listing. Filters run before pagination.

use super::*;
use crate::db::TenantTransaction;
use agf_core::audit::AuditLog;
use agf_core::error::DomainResult;
use agf_core::ids::TenantId;

use super::row_to_finding::row_to_audit;
use crate::map_sqlx_err;

/// Audit list criteria shared by the PostgreSQL and offline implementations.
#[derive(Debug, Clone, Default)]
pub struct AuditSelection {
    /// Inclusive lower sequence bound.
    pub from_sequence: i64,
    /// Exact action.
    pub action: Option<String>,
    /// Exact outcome.
    pub outcome: Option<String>,
    /// Exact actor name, ignoring case.
    pub actor: Option<String>,
    /// Literal substring across action, actor name, target name/ID and note.
    pub search: Option<String>,
    /// Only grant, export, contain and configure actions.
    pub sensitive_only: bool,
    /// One-based page number.
    pub page: u32,
    /// Maximum rows on one page.
    pub page_size: u32,
    /// Sort by sequence newest first when true.
    pub descending: bool,
}

impl AuditSelection {
    /// Match one in-memory row with the same predicates used by PostgreSQL.
    #[must_use]
    pub fn matches(&self, entry: &AuditLog) -> bool {
        if entry.sequence < self.from_sequence
            || self.action.as_deref().is_some_and(|v| entry.action.as_str() != v)
            || self.outcome.as_deref().is_some_and(|v| entry.outcome.as_str() != v)
            || self.actor.as_deref().is_some_and(|v| !entry.actor.name.eq_ignore_ascii_case(v))
            || (self.sensitive_only && !entry.action.is_sensitive())
        {
            return false;
        }
        self.search.as_ref().is_none_or(|needle| {
            format!(
                "{} {} {} {} {}",
                entry.action.as_str(),
                entry.actor.name,
                entry.target.name.as_deref().unwrap_or_default(),
                entry.target.id.as_deref().unwrap_or_default(),
                entry.note
            )
            .to_lowercase()
            .contains(&needle.to_lowercase())
        })
    }

    /// Zero-based SQL/Rust offset, saturating on very large page numbers.
    #[must_use]
    pub fn offset(&self) -> i64 {
        i64::from(self.page.saturating_sub(1)).saturating_mul(i64::from(self.page_size))
    }
}

const FILTER: &str = " FROM audit_logs WHERE sequence >= $1
    AND ($2::text IS NULL OR action = $2)
    AND ($3::text IS NULL OR outcome = $3)
    AND ($4::text IS NULL OR lower(actor->>'name') = lower($4))
    AND ($5::text IS NULL OR strpos(lower(action || ' ' || coalesce(actor->>'name','') || ' ' || coalesce(target->>'name','') || ' ' || coalesce(target->>'id','') || ' ' || note), lower($5)) > 0)
    AND (NOT $6 OR action IN ('grant','export','contain','configure'))";

impl AuditRepo {
    /// Filter the committed chain before count and page selection.
    ///
    /// # Errors
    /// The PostgreSQL query or row decoding fails.
    pub async fn list_page(
        tx: &mut TenantTransaction<'_>,
        selection: &AuditSelection,
    ) -> DomainResult<(Vec<AuditLog>, i64)> {
        let count_sql = format!("SELECT count(*){FILTER}");
        let total: i64 = sqlx::query_scalar(&count_sql)
            .bind(selection.from_sequence)
            .bind(selection.action.as_deref())
            .bind(selection.outcome.as_deref())
            .bind(selection.actor.as_deref())
            .bind(selection.search.as_deref())
            .bind(selection.sensitive_only)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("count_audit_page", &e))?;
        let direction = if selection.descending { "DESC" } else { "ASC" };
        let page_sql = format!("SELECT *{FILTER} ORDER BY sequence {direction} LIMIT $7 OFFSET $8");
        let rows = sqlx::query(&page_sql)
            .bind(selection.from_sequence)
            .bind(selection.action.as_deref())
            .bind(selection.outcome.as_deref())
            .bind(selection.actor.as_deref())
            .bind(selection.search.as_deref())
            .bind(selection.sensitive_only)
            .bind(i64::from(selection.page_size.clamp(1, 200)))
            .bind(selection.offset())
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("load_audit_page", &e))?;
        let tenant: TenantId = tx.tenant();
        Ok((rows.iter().map(|row| row_to_audit(row, tenant)).collect::<DomainResult<Vec<_>>>()?, total))
    }
}

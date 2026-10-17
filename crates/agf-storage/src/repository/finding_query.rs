//! Complete finding reads, including evidence, filtering and stable SQL pagination.
use super::{FindingFilter, FindingRepo};
use crate::{TenantTransaction, map_sqlx_err};
use agf_core::{
    enums::{RiskDomain, Severity},
    error::DomainResult,
    pagination::{Page, PageRequest},
    risk::{Finding, FindingState},
};

const PAYLOAD: &str = "to_jsonb(f)||jsonb_build_object('evidence',COALESCE(
    (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.code) FROM finding_evidence e WHERE e.finding_id=f.id),'[]'::jsonb))";

impl FindingRepo {
    /// Snapshot reads for reports and aggregations contain retained history and evidence.
    pub async fn all(tx: &mut TenantTransaction<'_>) -> DomainResult<Vec<Finding>> {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT {PAYLOAD} FROM findings f WHERE deleted_at IS NULL ORDER BY last_seen_at DESC,id ASC",
        ))
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("findings_all", &e))?;
        rows.into_iter().map(serde_json::from_value).collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Search retained findings by text, domain, minimum severity and workflow state.
    pub async fn search(
        tx: &mut TenantTransaction<'_>,
        request: &PageRequest,
        filters: &FindingFilter,
    ) -> DomainResult<Page<Finding>> {
        let rank =
            "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END";
        let filter = format!(
            "deleted_at IS NULL AND (cardinality($1::text[])=0 OR domain=ANY($1))
            AND (cardinality($2::text[])=0 OR severity=ANY($2)) AND (cardinality($3::text[])=0 OR state=ANY($3))
            AND ($4::integer IS NULL OR ({rank}) >= $4)
            AND ($5::text IS NULL OR strpos(lower(title||' '||summary||' '||target),lower($5))>0)"
        );
        let minimum = filters.minimum.map(|s| match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        });
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM findings WHERE {filter}"))
            .bind(filters.domains.iter().map(RiskDomain::as_str).collect::<Vec<_>>())
            .bind(filters.severities.iter().map(Severity::as_str).collect::<Vec<_>>())
            .bind(filters.states.iter().map(FindingState::as_str).collect::<Vec<_>>())
            .bind(minimum)
            .bind(&request.q)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("findings_count", &e))?;
        let sort = match request.sort_by.as_deref() {
            Some("severity") => rank,
            Some("title") => "title",
            Some("created_at") => "created_at",
            Some("updated_at") => "updated_at",
            Some("first_seen_at") => "first_seen_at",
            Some("confidence") => "confidence",
            _ => "last_seen_at",
        };
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT {PAYLOAD} FROM findings f WHERE {filter} ORDER BY {sort} {},id ASC LIMIT $6 OFFSET $7",
            request.sort_dir.as_sql(),
        ))
        .bind(filters.domains.iter().map(RiskDomain::as_str).collect::<Vec<_>>())
        .bind(filters.severities.iter().map(Severity::as_str).collect::<Vec<_>>())
        .bind(filters.states.iter().map(FindingState::as_str).collect::<Vec<_>>())
        .bind(minimum)
        .bind(&request.q)
        .bind(request.limit())
        .bind(request.offset())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("findings_search", &e))?;
        let items = rows.into_iter().map(serde_json::from_value).collect::<Result<Vec<Finding>, _>>()?;
        Ok(Page::new(items, total, request))
    }
}

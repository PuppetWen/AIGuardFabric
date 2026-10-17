//! Alert reads use the database for complete history and current multi-instance state.
use super::{AlertFilter, AlertRepo};
use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::{
    alert::Alert,
    enums::{AlertState, Severity},
    error::DomainResult,
    ids::Id,
    pagination::{Page, PageRequest},
};

impl AlertRepo {
    /// Fetch one alert, including closed and suppressed records.
    pub async fn get(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<Option<Alert>> {
        let row: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(a) FROM alerts a WHERE id=$1 AND deleted_at IS NULL")
                .bind(id.as_uuid())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("get_alert", &e))?;
        row.map(serde_json::from_value).transpose().map_err(Into::into)
    }

    /// Tenant-scoped search, filter, sort and pagination over all retained alert states.
    pub async fn list_page(
        tx: &mut TenantTransaction<'_>,
        request: &PageRequest,
        state: Option<AlertState>,
        severity: Option<Severity>,
        active_only: bool,
    ) -> DomainResult<Page<Alert>> {
        Self::list_filtered(
            tx,
            request,
            AlertFilter {
                states: state.into_iter().collect(),
                severities: severity.into_iter().collect(),
                active_only,
                ..Default::default()
            },
        )
        .await
    }

    /// Select and sort all matching alert states before counting and pagination.
    pub async fn list_filtered(
        tx: &mut TenantTransaction<'_>,
        request: &PageRequest,
        selection: AlertFilter,
    ) -> DomainResult<Page<Alert>> {
        let filter = "deleted_at IS NULL AND (cardinality($1::text[])=0 OR state=ANY($1))
            AND (cardinality($2::text[])=0 OR severity=ANY($2))
            AND ($3::text IS NULL OR strpos(lower(concat_ws(' ',id::text,title,description,dedup_key)), lower($3))>0)
            AND (NOT $4 OR state IN ('open','acknowledged','escalated'))
            AND (cardinality($5::text[])=0 OR domain=ANY($5))";
        let state: Vec<_> = selection.states.iter().map(AlertState::as_str).collect();
        let severity: Vec<_> = selection.severities.iter().map(Severity::as_str).collect();
        let domains: Vec<_> = selection.domains.iter().map(agf_core::enums::RiskDomain::as_str).collect();
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM alerts WHERE {filter}"))
            .bind(&state)
            .bind(&severity)
            .bind(&request.q)
            .bind(selection.active_only)
            .bind(&domains)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("count_alerts", &e))?;
        let sort = match request.sort_by.as_deref() {
            Some("created_at") => "created_at",
            Some("updated_at") => "updated_at",
            Some("first_seen_at") => "first_seen_at",
            Some("title") => "title",
            Some("dedup_count") => "dedup_count",
            Some("sla_due_at") => "sla_due_at",
            Some("severity") => {
                "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
            }
            _ => "last_seen_at",
        };
        let sql = format!(
            "SELECT to_jsonb(a) FROM alerts a WHERE {filter} ORDER BY {sort} {} NULLS LAST, id ASC LIMIT $6 OFFSET $7",
            request.sort_dir.as_sql()
        );
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&sql)
            .bind(&state)
            .bind(&severity)
            .bind(&request.q)
            .bind(selection.active_only)
            .bind(&domains)
            .bind(request.limit())
            .bind(request.offset())
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("page_alerts", &e))?;
        let items = rows.into_iter().map(serde_json::from_value).collect::<Result<Vec<Alert>, _>>()?;
        Ok(Page::new(items, total, request))
    }
}

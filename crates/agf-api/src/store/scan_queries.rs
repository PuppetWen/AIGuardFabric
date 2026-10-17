//! Paginated task history avoids loading and locking every historical task on each poll.
use super::*;
use crate::query::ListQuery;

impl ApiStore {
    pub(crate) async fn scan_page_durable(&self, tenant: TenantId, query: &ListQuery) -> DomainResult<Page<ScanJob>> {
        let wanted = query.filter("state").map(ScanJobState::parse).transpose()?;
        let column = match query.sort_by.as_deref() {
            None | Some("created_at") => "created_at",
            Some("name") => "name",
            _ => return Err(DomainError::Validation("Scan sorting supports created_at or name".into())),
        };
        if query.q.as_ref().is_some_and(|q| q.len() > 512) {
            return Err(DomainError::Validation("Scan search exceeds 512 UTF-8 bytes".into()));
        }
        let Some(db) = &self.database else {
            let jobs: Vec<_> = self
                .scan_list_durable(tenant)
                .await?
                .into_iter()
                .filter(|job| wanted.is_none_or(|state| job.state == state))
                .collect();
            return Ok(query.paginate_vec(
                &jobs,
                |job| format!("{} {}", job.id, job.name),
                |job| if column == "name" { job.name.clone() } else { job.created_at.to_rfc3339() },
            ));
        };
        let mut tx = db.db().begin_tenant(tenant).await?;
        let now = Timestamp::now();
        // Only unfinished expired tasks need row locks. A competing completion checks the same deadline.
        sqlx::query(
            "UPDATE scan_jobs SET state='failed',error=$1,finished_at=$2,updated_at=$2,
            result=result||jsonb_build_object('state','failed','error',$1::text,'finished_at',$2::timestamptz)
            WHERE state IN ('queued','running') AND created_at <= $3 AND deleted_at IS NULL",
        )
        .bind(super::scan_records::INTERRUPTED)
        .bind(now.as_datetime())
        .bind(now.offset_secs(-super::scan_records::TIMEOUT_SECONDS).as_datetime())
        .execute(&mut *tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("scan_expire", &e))?;
        let state = wanted.map(|s| if s == ScanJobState::Succeeded { "completed" } else { s.as_str() });
        let filter = "deleted_at IS NULL AND ($1::text IS NULL OR state=$1)
            AND ($2::text IS NULL OR strpos(lower(id::text||' '||name),lower($2))>0)";
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM scan_jobs WHERE {filter}"))
            .bind(state)
            .bind(&query.q)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("scan_page_count", &e))?;
        let request = query.to_page_request();
        let values: Vec<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT result FROM scan_jobs WHERE {filter} ORDER BY {column} {},id ASC LIMIT $3 OFFSET $4",
            query.sort_dir.as_sql()
        ))
        .bind(state)
        .bind(&query.q)
        .bind(request.limit())
        .bind(request.offset())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("scan_page", &e))?;
        let jobs = values.into_iter().map(serde_json::from_value).collect::<Result<Vec<ScanJob>, _>>()?;
        tx.commit().await?;
        Ok(Page::new(jobs, total, &request))
    }
}

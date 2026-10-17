//! SQL pagination and due-work selection keep completed histories out of the polling hot path.
use super::*;
use crate::query::ListQuery;
use agf_core::pagination::{Page, PageRequest};

pub async fn page(state: &AppState, tenant: TenantId, case: Id, query: &ListQuery) -> DomainResult<Page<Run>> {
    let keyword = query.q.clone().unwrap_or_default();
    if keyword.len() > 256 {
        return Err(DomainError::Validation("搜索内容最多 256 字节".into()));
    }
    let Some(db) = state.store.database() else {
        let mut rows: Vec<Run> = state.configurations.list(tenant, KIND).await?;
        rows.retain(|run| run.case_id == case);
        rows.sort_by_key(|run| std::cmp::Reverse((run.created_at, run.id)));
        return Ok(query.paginate_vec(
            &rows,
            |run| format!("{} {} {}", run.playbook.name, run.playbook.key, run.id),
            |run| run.created_at.to_rfc3339(),
        ));
    };
    let req = PageRequest { page: query.page, page_size: query.page_size, ..PageRequest::default() }.normalized();
    let (offset, limit) = (req.offset(), i64::from(req.page_size));
    let ascending = !query.descending();
    let (total, values): (i64, Vec<serde_json::Value>) = db.with_tenant(tenant, move |tx| Box::pin(async move {
        let predicate = "kind='soar-workflow' AND deleted_at IS NULL AND payload->>'case_id'=$1
            AND ($2='' OR strpos(lower(concat(payload#>>'{playbook,name}',' ',payload#>>'{playbook,key}',' ',id::text)),lower($2))>0)";
        let total = sqlx::query_scalar(&format!("SELECT count(*) FROM console_configurations WHERE {predicate}"))
            .bind(case.to_string()).bind(&keyword).fetch_one(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("soar_count", &e))?;
        let order = if ascending { "ASC" } else { "DESC" };
        let values = sqlx::query_scalar(&format!("SELECT payload FROM console_configurations WHERE {predicate} ORDER BY created_at {order},id {order} LIMIT $3 OFFSET $4"))
            .bind(case.to_string()).bind(&keyword).bind(limit).bind(offset).fetch_all(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("soar_page", &e))?;
        Ok((total, values))
    })).await?;
    let items = values.into_iter().map(serde_json::from_value).collect::<Result<Vec<Run>, _>>()?;
    Ok(Page::new(items, total, &req))
}

pub(super) async fn due(state: &AppState, tenant: TenantId, now: Timestamp) -> DomainResult<Vec<Id>> {
    let Some(db) = state.store.database() else {
        let runs: Vec<Run> = state.configurations.list(tenant, KIND).await?;
        return Ok(runs
            .into_iter()
            .filter(|run| {
                if run.status.terminal() {
                    return run.projected_version < run.version;
                }
                match run.status {
                    Status::Review => false,
                    Status::Running => run.lease_until.is_none_or(|at| at <= now),
                    Status::Waiting | Status::Approval => {
                        run.wake_at.is_none_or(|at| at <= now) || run.deadline_at.is_some_and(|at| at <= now)
                    }
                    _ => true,
                }
            })
            .take(32)
            .map(|run| run.id)
            .collect());
    };
    let ids: Vec<uuid::Uuid> = db.with_tenant(tenant, move |tx| Box::pin(async move {
        sqlx::query_scalar("SELECT id FROM console_configurations WHERE kind='soar-workflow' AND deleted_at IS NULL
            AND (payload->>'status' NOT IN ('completed','aborted','cancelled','not-started')
                OR (payload->>'projected_version')::bigint < (payload->>'version')::bigint)
            AND CASE payload->>'status'
                WHEN 'review' THEN false
                WHEN 'queued' THEN true
                WHEN 'running' THEN COALESCE((payload->>'lease_until')::timestamptz <= $1,true)
                WHEN 'waiting' THEN COALESCE((payload->>'wake_at')::timestamptz <= $1,true) OR (payload->>'deadline_at')::timestamptz <= $1
                WHEN 'approval' THEN COALESCE((payload->>'wake_at')::timestamptz <= $1,true) OR (payload->>'deadline_at')::timestamptz <= $1
                ELSE (payload->>'projected_version')::bigint < (payload->>'version')::bigint END
            ORDER BY updated_at,id LIMIT 32")
            .bind(now.as_datetime()).fetch_all(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("soar_due", &e))
    })).await?;
    Ok(ids.into_iter().map(Id::from_uuid).collect())
}

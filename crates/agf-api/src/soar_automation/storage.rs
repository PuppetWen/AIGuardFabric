//! Indexed candidate selection and review history; no moving cursor can lose a late SQL commit.
use super::*;
use crate::query::ListQuery;
use agf_core::pagination::{Page, PageRequest};
use agf_storage::map_sqlx_err;

pub async fn summaries(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Automation>> {
    if let Some(db) = state.store.database() {
        let values: Vec<serde_json::Value> = db.with_tenant(tenant, |tx| Box::pin(async move {
            sqlx::query_scalar("SELECT payload-'history' FROM console_configurations WHERE kind='soar-automation' AND deleted_at IS NULL ORDER BY updated_at DESC,id")
                .fetch_all(&mut **tx).await.map_err(|e| map_sqlx_err("soar_automation_summaries", &e))
        })).await?;
        return values.into_iter().map(serde_json::from_value).collect::<Result<_, _>>().map_err(Into::into);
    }
    let mut rows: Vec<Automation> = state.configurations.list(tenant, KIND).await?;
    for row in &mut rows {
        row.history.clear();
    }
    Ok(rows)
}

pub(super) async fn candidates(state: &AppState, template: &Automation) -> DomainResult<Vec<Alert>> {
    let (tenant, id, since) = (template.tenant_id, template.id, template.since);
    if let Some(db) = state.store.database() {
        let values: Vec<serde_json::Value> = db
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT to_jsonb(a) FROM alerts a LEFT JOIN console_configurations d
                ON d.kind='soar-automation-delivery' AND d.deleted_at IS NULL
                AND d.payload->>'automation_id'=$1 AND d.payload->>'alert_id'=a.id::text
                WHERE (a.created_at >= $2 AND d.id IS NULL) OR d.payload->>'status'='pending'
                ORDER BY a.created_at,a.id LIMIT 32",
                    )
                    .bind(id.to_string())
                    .bind(since.as_datetime())
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|error| map_sqlx_err("soar_trigger_candidates", &error))
                })
            })
            .await?;
        return values.into_iter().map(serde_json::from_value).collect::<Result<_, _>>().map_err(Into::into);
    }
    let saved: Vec<Delivery> = state.configurations.list(tenant, DELIVERY).await?;
    let mut alerts = state.store.alert_list(tenant, None, None)?;
    alerts.sort_by_key(|row| (row.created_at, row.id));
    Ok(alerts
        .into_iter()
        .filter(|alert| {
            saved
                .iter()
                .find(|row| row.automation_id == id && row.alert_id == alert.id)
                .map_or(alert.created_at >= since, |row| row.status == "pending")
        })
        .take(32)
        .collect())
}

pub async fn deliveries(state: &AppState, tenant: TenantId, id: Id, query: &ListQuery) -> DomainResult<Page<Delivery>> {
    let keyword = query.q.clone().unwrap_or_default();
    if keyword.len() > 256 {
        return Err(DomainError::Validation("搜索内容最多 256 字节".into()));
    }
    let Some(db) = state.store.database() else {
        let mut rows: Vec<Delivery> = state.configurations.list(tenant, DELIVERY).await?;
        rows.retain(|row| row.automation_id == id);
        return Ok(query.paginate_vec(
            &rows,
            |row| format!("{} {} {}", row.alert_title, row.status, row.reason),
            |row| row.at.to_rfc3339(),
        ));
    };
    let request = PageRequest { page: query.page, page_size: query.page_size, ..PageRequest::default() }.normalized();
    let (limit, offset) = (i64::from(request.page_size), request.offset());
    let (total, values): (i64, Vec<serde_json::Value>) = db.with_tenant(tenant, move |tx| Box::pin(async move {
        let predicate = "kind='soar-automation-delivery' AND deleted_at IS NULL AND payload->>'automation_id'=$1
            AND ($2='' OR strpos(lower(concat(payload->>'alert_title',' ',payload->>'status',' ',payload->>'reason')),lower($2))>0)";
        let total = sqlx::query_scalar(&format!("SELECT count(*) FROM console_configurations WHERE {predicate}"))
            .bind(id.to_string()).bind(&keyword).fetch_one(&mut **tx).await.map_err(|e| map_sqlx_err("soar_trigger_count", &e))?;
        let rows = sqlx::query_scalar(&format!("SELECT payload FROM console_configurations WHERE {predicate} ORDER BY updated_at DESC,id DESC LIMIT $3 OFFSET $4"))
            .bind(id.to_string()).bind(&keyword).bind(limit).bind(offset).fetch_all(&mut **tx).await.map_err(|e| map_sqlx_err("soar_trigger_history", &e))?;
        Ok((total, rows))
    })).await?;
    let rows = values.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?;
    Ok(Page::new(rows, total, &request))
}

pub(super) async fn write<T: Serialize>(
    tx: &mut agf_storage::TenantTransaction<'_>,
    kind: &str,
    id: Id,
    row: &T,
) -> DomainResult<()> {
    sqlx::query(
        "INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)
        ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
    )
    .bind(tx.tenant().as_uuid())
    .bind(kind)
    .bind(id.as_uuid())
    .bind(serde_json::to_value(row)?)
    .execute(&mut **tx)
    .await
    .map_err(|e| map_sqlx_err("soar_trigger_commit", &e))?;
    Ok(())
}

pub(super) async fn read<T: serde::de::DeserializeOwned>(
    tx: &mut agf_storage::TenantTransaction<'_>,
    kind: &str,
    id: Id,
) -> DomainResult<Option<T>> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT payload FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL")
            .bind(kind)
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("soar_trigger_read", &e))?;
    value.map(serde_json::from_value).transpose().map_err(Into::into)
}

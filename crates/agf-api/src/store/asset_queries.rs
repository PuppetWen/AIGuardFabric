use super::asset_selection::{AssetSelection, EXPOSURE_SQL};
use super::*;
use agf_storage::AssetRepo;
use sqlx::{Postgres, QueryBuilder};

impl ApiStore {
    pub async fn asset_list_all_durable(&self, tenant: TenantId) -> DomainResult<Vec<Asset>> {
        let Some(db) = &self.database else { return self.asset_list_all(tenant) };
        db.with_tenant(tenant, |tx| {
            Box::pin(async move {
                let rows = AssetRepo::list_all(tx, 100_001).await?;
                if rows.len() > 100_000 {
                    return Err(DomainError::PreconditionFailed(
                        "Asset collection exceeds 100000 rows; use paginated inventory".into(),
                    ));
                }
                Ok(rows)
            })
        })
        .await
    }

    pub async fn asset_changes_durable(&self, tenant: TenantId, id: Id, limit: i64) -> DomainResult<Vec<AssetChange>> {
        let Some(db) = &self.database else { return self.asset_changes(tenant, id, limit) };
        db.with_tenant(tenant, move |tx| {
            Box::pin(async move { AssetRepo::list_changes(tx, id, limit.clamp(1, 200)).await })
        })
        .await
    }

    pub(crate) async fn asset_page_durable(
        &self,
        tenant: TenantId,
        request: &PageRequest,
        filter: AssetSelection,
    ) -> DomainResult<Page<Asset>> {
        let numeric_sort =
            super::asset_facet_sql::unsigned(request.sort_by.as_deref().unwrap_or(""), "18446744073709551615");
        let column = match request.sort_by.as_deref() {
            None | Some("name") => "a.name",
            Some("risk_score") => "a.risk_score",
            Some("active_sessions" | "tool_count") => &numeric_sort,
            Some("exposure_score") => "a.exposure_score",
            Some("last_seen_at") => "a.last_seen_at",
            Some("created_at") => "a.created_at",
            Some("updated_at") => "a.updated_at",
            Some("kind") => "a.kind",
            Some("lifecycle") => "a.lifecycle",
            _ => return Err(DomainError::Validation("Unsupported asset sort field".into())),
        };
        if request.q.as_ref().is_some_and(|q| q.len() > 512) {
            return Err(DomainError::Validation("Asset search exceeds 512 bytes".into()));
        }
        let Some(db) = &self.database else {
            let rows = self.asset_list_all(tenant)?.into_iter().filter(|a| filter.matches(a)).collect::<Vec<_>>();
            let query = crate::query::ListQuery {
                page: request.page,
                page_size: request.page_size,
                sort_by: Some(request.sort_by.clone().unwrap_or_else(|| "name".into())),
                sort_dir: request.sort_dir,
                q: request.q.clone(),
                ..Default::default()
            };
            return Ok(query.paginate_vec(&rows, search_text, |a| match request.sort_by.as_deref() {
                Some("risk_score") => a
                    .risk_score
                    .map(|value| format!("{value:03}"))
                    .unwrap_or_else(|| if query.descending() { String::new() } else { "999".into() }),
                Some("active_sessions" | "tool_count") => a
                    .attributes
                    .get(request.sort_by.as_deref().unwrap_or_default())
                    .and_then(serde_json::Value::as_u64)
                    .map(|v| format!("{v:020}"))
                    .unwrap_or_else(|| if query.descending() { String::new() } else { "~".into() }),
                Some("exposure_score") => format!("{:03}", a.exposure_score),
                Some("created_at") => a.created_at.to_rfc3339(),
                Some("updated_at") => a.updated_at.to_rfc3339(),
                Some("last_seen_at") => a
                    .last_seen_at
                    .as_ref()
                    .map(Timestamp::to_rfc3339)
                    .unwrap_or_else(|| if query.descending() { String::new() } else { "~".into() }),
                Some("kind") => a.kind.as_str().into(),
                Some("lifecycle") => a.lifecycle.as_str().into(),
                _ => a.name.clone(),
            }));
        };
        let column = column.to_string();
        let request = request.clone();
        db.with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let mut count =
                    QueryBuilder::<Postgres>::new("SELECT count(*) FROM assets a WHERE a.deleted_at IS NULL");
                restrict(&mut count, &filter, request.q.as_deref());
                let total: i64 = count
                    .build_query_scalar()
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("asset_count", &e))?;
                let mut query =
                    QueryBuilder::<Postgres>::new("SELECT to_jsonb(a) FROM assets a WHERE a.deleted_at IS NULL");
                restrict(&mut query, &filter, request.q.as_deref());
                query
                    .push(" ORDER BY ")
                    .push(column)
                    .push(" ")
                    .push(request.sort_dir.as_sql())
                    .push(" NULLS LAST, a.id ASC LIMIT ")
                    .push_bind(request.limit())
                    .push(" OFFSET ")
                    .push_bind(request.offset());
                let rows: Vec<serde_json::Value> = query
                    .build_query_scalar()
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("asset_page", &e))?;
                let assets = rows.into_iter().map(serde_json::from_value).collect::<Result<Vec<Asset>, _>>()?;
                Ok(Page::new(assets, total, &request))
            })
        })
        .await
    }
}

fn restrict(query: &mut QueryBuilder<'_, Postgres>, filter: &AssetSelection, keyword: Option<&str>) {
    for (column, values) in [
        ("a.kind", &filter.kinds),
        ("a.lifecycle", &filter.lifecycles),
        ("a.data_class", &filter.classifications),
        ("a.department", &filter.departments),
        (EXPOSURE_SQL, &filter.exposures),
    ] {
        if !values.is_empty() {
            query.push(" AND (").push(column).push(")=ANY(").push_bind(values.clone()).push(")");
        }
    }
    for (key, values) in &filter.facets.values {
        query
            .push(" AND (")
            .push(super::asset_facet_sql::facet(key))
            .push(")=ANY(")
            .push_bind(values.clone())
            .push(")");
    }
    if let Some(minimum) = filter.min_exposure {
        query.push(" AND a.exposure_score>=").push_bind(i16::from(minimum));
    }
    if let Some(keyword) = keyword.filter(|v| !v.trim().is_empty()) {
        query.push(" AND position(").push_bind(keyword.trim().to_lowercase())
            .push(" in lower(concat_ws(' ',a.id::text,a.name,a.fingerprint,a.endpoint,a.kind,a.owner,a.department,a.tags::text,a.vendor,a.version,a.attributes::text,CASE a.lifecycle WHEN 'requested' THEN 'pending' WHEN 'under-review' THEN 'pending' WHEN 'trial' THEN 'pending' WHEN 'production' THEN 'approved' WHEN 'changing' THEN 'pending' WHEN 'archived' THEN 'revoked' ELSE 'rejected' END)))>0");
    }
}

fn search_text(asset: &Asset) -> String {
    format!(
        "{} {} {} {} {} {} {} {} {} {} {} {}",
        asset.id,
        asset.name,
        asset.fingerprint,
        asset.endpoint.as_deref().unwrap_or_default(),
        asset.kind.as_str(),
        asset.owner.as_deref().unwrap_or_default(),
        asset.department.as_deref().unwrap_or_default(),
        asset.tags.join(" "),
        asset.vendor.as_deref().unwrap_or_default(),
        asset.version.as_deref().unwrap_or_default(),
        serde_json::to_string(&asset.attributes).unwrap_or_default(),
        match asset.lifecycle {
            LifecycleState::Requested
            | LifecycleState::UnderReview
            | LifecycleState::Trial
            | LifecycleState::Changing => "pending",
            LifecycleState::Production => "approved",
            LifecycleState::Archived => "revoked",
            LifecycleState::Rejected => "rejected",
        }
    )
}

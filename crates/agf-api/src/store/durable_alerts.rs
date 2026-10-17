//! Alert API writes acknowledge SQL commits; reads include history and changes from other instances.
use super::*;
use agf_core::{alert::Alert, pagination::Page};
use agf_storage::{AlertRepo, repository::AlertFilter};

impl ApiStore {
    pub async fn alert_get_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Alert>> {
        let Some(database) = &self.database else { return self.alert_get(tenant, id) };
        let alert =
            database.with_tenant(tenant, move |tx| Box::pin(async move { AlertRepo::get(tx, id).await })).await?;
        if let Some(alert) = &alert {
            self.hydrate_alert(alert)?;
        }
        Ok(alert)
    }

    pub async fn alert_page_durable(
        &self,
        tenant: TenantId,
        query: &crate::query::ListQuery,
        filter: AlertFilter,
    ) -> DomainResult<Page<Alert>> {
        if let Some(database) = &self.database {
            let request = query.to_page_request();
            return database
                .with_tenant(tenant, move |tx| {
                    Box::pin(async move { AlertRepo::list_filtered(tx, &request, filter).await })
                })
                .await;
        }
        let mut alerts: Vec<_> =
            self.alert_list(tenant, None, None)?.into_iter().filter(|alert| filter.matches(alert)).collect();
        alerts.sort_by(|a, b| {
            // Keep missing deadlines last in both directions, matching the SQL path.
            if query.sort_by.as_deref() == Some("sla_due_at") {
                match (a.sla_due_at, b.sla_due_at) {
                    (None, Some(_)) => return std::cmp::Ordering::Greater,
                    (Some(_), None) => return std::cmp::Ordering::Less,
                    _ => {}
                }
            }
            let order = match query.sort_by.as_deref() {
                Some("severity") => a.severity.cmp(&b.severity),
                Some("dedup_count") => a.dedup_count.cmp(&b.dedup_count),
                Some("title") => a.title.cmp(&b.title),
                Some("first_seen_at") => a.first_seen_at.cmp(&b.first_seen_at),
                Some("created_at") => a.created_at.cmp(&b.created_at),
                Some("updated_at") => a.updated_at.cmp(&b.updated_at),
                Some("sla_due_at") => a.sla_due_at.cmp(&b.sla_due_at),
                _ => a.last_seen_at.cmp(&b.last_seen_at),
            };
            let order = if query.descending() { order.reverse() } else { order };
            order.then_with(|| a.id.cmp(&b.id))
        });
        let mut page_query = query.clone();
        page_query.sort_by = None;
        Ok(page_query.paginate_vec(
            &alerts,
            |a| format!("{} {} {} {}", a.id, a.title, a.description, a.dedup_key),
            |_| String::new(),
        ))
    }

    pub async fn alert_upsert_durable(&self, write: AlertWrite) -> DomainResult<(Alert, bool)> {
        let Some(database) = &self.database else {
            let (id, created) = self.alert_upsert_dedup(
                write.tenant,
                &write.dedup_key,
                &write.title,
                &write.description,
                write.severity,
                write.domain,
                &write.asset_ids,
                &write.finding_ids,
            )?;
            return self
                .alert_get(write.tenant, id)?
                .map(|alert| (alert, created))
                .ok_or_else(|| DomainError::Internal("Created alert is missing".into()));
        };
        let (alert, created) = database
            .with_tenant(write.tenant, move |tx| {
                Box::pin(async move {
                    for id in &write.asset_ids {
                        let exists: bool = sqlx::query_scalar(
                            "SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1 AND deleted_at IS NULL)",
                        )
                        .bind(id.as_uuid())
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("alert_asset", &e))?;
                        if !exists {
                            return Err(DomainError::NotFound { entity: "asset", id: id.to_string() });
                        }
                    }
                    for id in &write.finding_ids {
                        let exists: bool = sqlx::query_scalar(
                            "SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1 AND deleted_at IS NULL)",
                        )
                        .bind(id.as_uuid())
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("alert_finding", &e))?;
                        if !exists {
                            return Err(DomainError::NotFound { entity: "finding", id: id.to_string() });
                        }
                    }
                    let (id, created) = AlertRepo::upsert_dedup(
                        tx,
                        &write.dedup_key,
                        &write.title,
                        &write.description,
                        write.severity,
                        write.domain,
                        &write.asset_ids,
                        &write.finding_ids,
                        write.sla_due_at,
                    )
                    .await?;
                    let alert = AlertRepo::get(tx, id)
                        .await?
                        .ok_or_else(|| DomainError::Internal("Committed alert is missing".into()))?;
                    Ok((alert, created))
                })
            })
            .await?;
        self.hydrate_alert(&alert)?;
        Ok((alert, created))
    }

    pub async fn alert_set_state_durable(
        &self,
        tenant: TenantId,
        id: Id,
        state: AlertState,
        assignee: Option<String>,
    ) -> DomainResult<Alert> {
        let Some(database) = &self.database else { return self.alert_set_state(tenant, id, state, assignee) };
        let alert = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    AlertRepo::set_state(tx, id, state, assignee.as_deref()).await?;
                    AlertRepo::get(tx, id)
                        .await?
                        .ok_or_else(|| DomainError::NotFound { entity: "alert", id: id.to_string() })
                })
            })
            .await?;
        self.hydrate_alert(&alert)?;
        Ok(alert)
    }
}

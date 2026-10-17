//! SQL-confirmed finding writes and current reads for automatic analysis and manual workflows.
use super::*;
use agf_core::risk::FindingState;
use agf_storage::FindingRepo;

impl ApiStore {
    pub async fn finding_insert_durable(&self, finding: &Finding) -> DomainResult<Id> {
        let Some(database) = &self.database else { return self.finding_insert(finding) };
        let value = finding.clone();
        let id = database
            .with_tenant(finding.tenant_id, move |tx| Box::pin(async move { FindingRepo::insert(tx, &value).await }))
            .await?;
        self.hydrate_finding(finding)?;
        Ok(id)
    }
    pub async fn finding_get_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Finding>> {
        let Some(database) = &self.database else { return self.finding_get(tenant, id) };
        let finding =
            database.with_tenant(tenant, move |tx| Box::pin(async move { FindingRepo::get(tx, id).await })).await?;
        if let Some(finding) = &finding {
            self.hydrate_finding(finding)?;
        }
        Ok(finding)
    }
    pub async fn finding_list_all_durable(&self, tenant: TenantId) -> DomainResult<Vec<Finding>> {
        let Some(database) = &self.database else { return self.finding_list_all(tenant) };
        database.with_tenant(tenant, |tx| Box::pin(async move { FindingRepo::all(tx).await })).await
    }
    pub async fn finding_list_durable(
        &self,
        tenant: TenantId,
        request: &PageRequest,
        filters: agf_storage::repository::FindingFilter,
    ) -> DomainResult<Page<Finding>> {
        let Some(database) = &self.database else {
            let mut rows: Vec<_> = self.finding_list_all(tenant)?.into_iter().filter(|f| filters.matches(f)).collect();
            rows.sort_by_key(|f| f.id);
            let query = crate::query::ListQuery {
                page: request.page,
                page_size: request.page_size,
                sort_by: Some(request.sort_by.clone().unwrap_or_else(|| "last_seen_at".into())),
                sort_dir: request.sort_dir,
                q: request.q.clone(),
                ..Default::default()
            };
            return Ok(query.paginate_vec(
                &rows,
                |f| format!("{} {} {}", f.title, f.summary, f.target),
                |f| match request.sort_by.as_deref() {
                    Some("title") => f.title.clone(),
                    Some("severity") => format!("{:03}", f.severity.weight()),
                    Some("created_at") => f.created_at.to_rfc3339(),
                    Some("updated_at") => f.updated_at.to_rfc3339(),
                    Some("first_seen_at") => f.first_seen_at.to_rfc3339(),
                    Some("confidence") => format!("{:08.6}", f.confidence),
                    _ => f.last_seen_at.to_rfc3339(),
                },
            ));
        };
        let request = request.clone();
        database
            .with_tenant(tenant, move |tx| Box::pin(async move { FindingRepo::search(tx, &request, &filters).await }))
            .await
    }
    pub async fn finding_set_state_durable(
        &self,
        tenant: TenantId,
        id: Id,
        state: FindingState,
        note: Option<String>,
        level: Option<EvidenceLevel>,
    ) -> DomainResult<Finding> {
        let Some(database) = &self.database else { return self.finding_set_state(tenant, id, state, note, level) };
        let finding = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    FindingRepo::set_state(tx, id, state.as_str(), note.as_deref(), level.map(|l| l.as_str())).await?;
                    FindingRepo::get(tx, id)
                        .await?
                        .ok_or_else(|| DomainError::NotFound { entity: "finding", id: id.to_string() })
                })
            })
            .await?;
        self.hydrate_finding(&finding)?;
        Ok(finding)
    }
}

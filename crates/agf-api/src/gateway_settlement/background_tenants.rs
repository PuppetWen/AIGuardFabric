//! Only tenant identities are read globally; all evidence and mutations use tenant RLS.
use super::{authority, store};
use crate::AppState;
use agf_core::{error::DomainResult, ids::TenantId};

pub(super) const PAGE_SIZE: usize = 32;

pub(super) struct Page {
    pub(super) tenants: Vec<TenantId>,
    pub(super) more: bool,
}

pub(super) async fn page(state: &AppState, after: Option<TenantId>) -> DomainResult<Page> {
    // Include disabled and deleted rows: retiring an identity must not hold a reservation forever.
    // This is not an authentication directory or positive execution grant.
    let ids: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 33")
            .bind(after.map(|id| id.as_uuid()))
            .fetch_all(authority::database(state)?.db().pool())
            .await
            .map_err(|error| agf_storage::map_sqlx_err("gateway_maintenance_tenant_page", &error))?;
    validate(ids.into_iter().map(TenantId::from_uuid).collect(), after)
}

pub(super) fn validate(ids: Vec<TenantId>, after: Option<TenantId>) -> DomainResult<Page> {
    if ids.len() > PAGE_SIZE + 1
        || ids.iter().any(|id| id.as_uuid().is_nil())
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
        || ids.first().is_some_and(|first| after.is_some_and(|cursor| *first <= cursor))
    {
        return Err(store::missing());
    }
    let more = ids.len() > PAGE_SIZE;
    Ok(Page { tenants: ids.into_iter().take(PAGE_SIZE).collect(), more })
}

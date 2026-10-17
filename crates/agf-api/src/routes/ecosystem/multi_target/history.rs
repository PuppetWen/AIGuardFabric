use super::{
    authority::Authority,
    history_model::{self, Capacity, OWNER_KIND, OwnerIndex},
    records::{self, Envelope, Fact},
    store,
};
use crate::{
    AppState, Principal,
    error::ApiResult,
    routes::{ApiJson, parse_id},
    soar_workflow::Actor,
    store::asset_transaction::AssetTransaction,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
pub(super) async fn capacity(state: &AppState, tx: &AssetTransaction<'_>, tenant: TenantId) -> DomainResult<Capacity> {
    let id = crate::model_routes::tenant_record_id(tenant);
    tx.configuration_lock(super::CAPACITY_KIND, id).await?;
    let count = tx.multi_target_fact_count().await?;
    let current = tx.configuration::<Envelope>(super::CAPACITY_KIND, id).await?;
    let capacity = match current {
        Some(row) => history_model::restore(state, tenant, id, row)?,
        None if count == 0 => Capacity { tenant, claimed: 0, active: vec![] },
        None => return Err(records::corrupt()),
    };
    capacity.validate(tenant, count)?;
    Ok(capacity)
}
async fn write_capacity(state: &AppState, tx: &AssetTransaction<'_>, capacity: &Capacity) -> DomainResult<()> {
    let id = crate::model_routes::tenant_record_id(capacity.tenant);
    tx.configure(
        super::CAPACITY_KIND,
        id,
        Some(serde_json::to_value(history_model::seal(state, capacity.tenant, id, capacity)?)?),
    )
    .await
}
pub(super) async fn admit(state: &AppState, tx: &AssetTransaction<'_>, fact: &Fact) -> DomainResult<()> {
    let mut capacity = capacity(state, tx, fact.tenant).await?;
    let id = history_model::owner_id(fact.tenant, &fact.owner)?;
    tx.configuration_lock(OWNER_KIND, id).await?;
    let mut index = tx
        .configuration::<Envelope>(OWNER_KIND, id)
        .await?
        .map(|row| history_model::restore::<OwnerIndex>(state, fact.tenant, id, row))
        .transpose()?
        .unwrap_or(OwnerIndex { tenant: fact.tenant, owner: fact.owner.clone(), claimed: 0, recent: vec![] });
    index.validate(fact.tenant, &fact.owner)?;
    capacity.admit(fact.request_id)?;
    index.admit(fact.request_id)?;
    write_capacity(state, tx, &capacity).await?;
    tx.configure(OWNER_KIND, id, Some(serde_json::to_value(history_model::seal(state, fact.tenant, id, &index)?)?))
        .await
}
fn pagination(raw: Option<&str>) -> DomainResult<(usize, usize)> {
    let mut limit = None;
    let mut offset = None;
    for part in raw.filter(|raw| !raw.is_empty()).into_iter().flat_map(|raw| raw.split('&')) {
        let (key, value) = part.split_once('=').ok_or_else(query_error)?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(query_error());
        }
        let value = value.parse::<usize>().map_err(|_| query_error())?;
        match key {
            "limit" if limit.is_none() => limit = Some(value),
            "offset" if offset.is_none() => offset = Some(value),
            _ => return Err(query_error()),
        }
    }
    let (limit, offset) = (limit.unwrap_or(20), offset.unwrap_or(0));
    if !(1..=50).contains(&limit) || offset >= history_model::RECENT {
        return Err(query_error());
    }
    Ok((limit, offset))
}
fn query_error() -> DomainError {
    DomainError::Validation("Use unique limit=1..50 and offset=0..255; no other query parameters".into())
}
pub(super) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, true)?;
    let value = Box::pin(authority.within(async {
        authority.check(&state).await?;
        let (limit, offset) = pagination(raw.as_deref())?;
        let tenant = authority.principal.tenant;
        let owner = Actor::from_principal(&authority.principal)?;
        let id = history_model::owner_id(tenant, &owner)?;
        let index = state
            .configurations
            .get::<Envelope>(tenant, OWNER_KIND, id)
            .await?
            .map(|row| history_model::restore::<OwnerIndex>(&state, tenant, id, row))
            .transpose()?;
        let mut items = Vec::new();
        if let Some(index) = &index {
            index.validate(tenant, &owner)?;
            for request in index.recent.iter().skip(offset).take(limit) {
                let fact = store::get(&state, tenant, *request).await?.ok_or_else(records::corrupt)?;
                fact.owns(&authority.principal)?;
                items.push(fact.summary());
            }
        }
        authority.check(&state).await?;
        Ok(json!({
            "items": items,
            "total": index.as_ref().map_or(0, |row| row.recent.len()),
            "offset": offset,
            "limit": limit,
            "truncated": index.as_ref().is_some_and(|row| row.claimed > history_model::RECENT as u64),
            "completeHistory": false,
            "limits": {
                "retainedBodies": history_model::ACTIVE,
                "permanentUuidFacts": history_model::PERMANENT,
                "recentOwnerUuids": history_model::RECENT
            },
            "getNeverDispatches": true
        }))
    }))
    .await?;
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Archive {
    expected_generation: u64,
}
pub(super) async fn archive(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(input): ApiJson<Archive>,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, false)?;
    let value = Box::pin(authority.within(async {
        authority.check(&state).await?;
        if input.expected_generation == 0 {
            return Err(query_error());
        }
        let request = parse_id(&raw, "redteam-multi-target-run").map_err(|error| error.error)?;
        let tenant = authority.principal.tenant;
        let original = store::get(&state, tenant, request)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "redteam multi-target run", id: raw.clone() })?;

        original.owns(&authority.principal)?;
        let database = state
            .store
            .database()
            .ok_or_else(|| DomainError::PreconditionFailed("Archive requires durable SQL".into()))?;

        let tx = AssetTransaction::begin(database, tenant).await?;
        tx.tenant_enabled().await?;
        authority.check(&state).await?;
        let mut capacity = capacity(&state, &tx, tenant).await?;
        tx.configuration_lock(super::KIND, records::id(tenant, request)).await?;
        let mut next = store::current(&state, &tx, &original).await?;
        next.owns(&authority.principal)?;
        let mut audit = AppState::audit_entry(
            tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&authority.principal, "redteam-multi-target-archive"),
            AuditTarget::new("redteam-multi-target-archive", Some(request.to_string()), None),
            "Reviewed evidence body archived; original UUID, intent and terminal audit remain permanent",
        );
        if !next.archive(input.expected_generation, audit.id)? {
            return super::routes::project(&state, &authority, next).await;
        }

        capacity.archive(request)?;
        audit.request_id = Some(request.to_string());
        audit.after = Some(json!({
            "generation": next.generation,
            "originalStatus": next.status,
            "evidenceSha256": next.archived_evidence_sha256,
            "canRetryDispatch": false
        }));

        write_capacity(&state, &tx, &capacity).await?;
        store::write(&state, &tx, &next).await?;
        tx.audit(audit).await?;
        authority.check(&state).await?;
        tx.commit(&state.store).await?;
        super::routes::project(&state, &authority, next).await
    }))
    .await?;
    Ok(Json(value))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pagination_is_bounded_and_duplicate_unknown_encoded_fields_never_truncate_proof() {
        assert!(pagination(Some("limit=50&offset=255")).is_ok());
        for raw in ["limit=0", "limit=51", "offset=256", "limit=2&limit=3", "tenant=other", "limit=%31", "offset=-1"] {
            assert!(pagination(Some(raw)).is_err());
        }
    }
}

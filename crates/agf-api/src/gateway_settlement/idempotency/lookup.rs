//! Lookup authenticates current identity/lease/grants; it neither reads cloud sources nor writes records.
use super::{Binding, Duplicate, INDEX, identity, model::Entry};
use crate::{
    Principal,
    error::ApiResult,
    gateway_settlement::{
        authority,
        records::{FACT, Fact},
        routes, store,
    },
    policy_store::{AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization},
    state::AppState,
    store::asset_transaction::AssetTransaction,
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use axum::{
    Json,
    extract::{OriginalUri, State},
    http::HeaderMap,
};
use serde_json::Value;
use std::time::Duration;

static READ: PublicationAuthorization =
    PublicationAuthorization { resource: "models", action: "read", additional: &[] };
static DUPLICATE: PublicationAuthorization = PublicationAuthorization {
    resource: "models",
    action: "write",
    additional: &[Grant { resource: "models", action: "read" }],
};
struct Loaded {
    fact: Box<Fact>,
    duplicate: Duplicate,
}

pub(crate) async fn prelookup(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    key: &str,
    fingerprint: &str,
    window: (Timestamp, tokio::time::Instant),
) -> DomainResult<Option<Duplicate>> {
    if state.store.database().is_none() {
        return Ok(None);
    }
    if identity::header(headers)? != key {
        return Err(identity::invalid());
    }
    let binding = identity::binding(state, principal, key, fingerprint)?;
    authority::budget(window.1)?;
    tokio::time::timeout_at(window.1, load(state, principal, headers, &binding, &DUPLICATE, false, window))
        .await
        .map_err(|_| timeout())?
        .map(|row| row.map(|loaded| loaded.duplicate))
}

pub(in crate::gateway_settlement) async fn by_header(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> ApiResult<Json<Value>> {
    if uri.query().is_some() {
        return Err(DomainError::Validation("Original key lookup accepts no URL query parameters".into()).into());
    }
    let key = identity::header(&headers)?;
    let (id, namespace) = identity::namespace(&state, &principal, key)?;
    let binding = Binding { id, namespace, input: String::new() };
    let window = (Timestamp::now(), tokio::time::Instant::now() + Duration::from_secs(110));
    let deadline = window.1;
    let result = tokio::time::timeout_at(deadline, async {
        let loaded = load(&state, &principal, &headers, &binding, &READ, true, window).await?.ok_or_else(|| {
            DomainError::NotFound { entity: "gateway-admission-key", id: "original header key".into() }
        })?;
        let value = routes::view(&state, &loaded.fact).await?;
        // Receipt projection may await encrypted local pending evidence; recheck before disclosure.
        authorized(&state, &principal, &headers, &READ, &loaded.fact, deadline).await?;
        Ok::<_, DomainError>(Json(value))
    })
    .await
    .map_err(|_| timeout())??;
    Ok(result)
}

async fn load(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    binding: &Binding,
    grant: &'static PublicationAuthorization,
    require_before_missing: bool,
    window: (Timestamp, tokio::time::Instant),
) -> DomainResult<Option<Loaded>> {
    let (submitted_at, deadline) = window;
    authority::budget(deadline)?;
    let lease = AccessLease::capture(state, principal, headers)?;
    let submission = AuthorizedSubmission { principal, lease: lease.as_ref(), submitted_at, authorization: grant };
    if require_before_missing {
        crate::policy_store::authorize_publication(state, &submission).await?;
    }
    let tx = AssetTransaction::begin(authority::database(state)?, principal.tenant).await?;
    tx.tenant_enabled().await?;
    let Some(raw) = tx.admission_key_record(INDEX, binding.id).await? else { return Ok(None) };
    let entry: Entry = store::decode(state, principal.tenant, binding.id, INDEX, raw)?;
    entry.validate(binding.id, &binding.namespace)?;
    let current = crate::policy_store::authorize_publication(state, &submission).await?;
    entry.owner().matches(&current)?;
    let fact: Fact = store::decode(
        state,
        principal.tenant,
        entry.attempt(),
        FACT,
        store::read(&tx, FACT, entry.attempt()).await?.ok_or_else(identity::corrupt)?,
    )?;
    entry.fact(&fact)?;
    let current = crate::policy_store::authorize_publication(state, &submission).await?;
    entry.owner().matches(&current)?;
    authority::budget(deadline)?;
    tx.commit(&state.store).await?;
    let current = crate::policy_store::authorize_publication(state, &submission).await?;
    entry.owner().matches(&current)?;
    authority::budget(deadline)?;
    Ok(Some(Loaded {
        fact: Box::new(fact),
        duplicate: Duplicate {
            attempt: entry.attempt(),
            same_input: entry.matches(binding),
            owner: Box::new(entry.owner().clone()),
        },
    }))
}

async fn authorized(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    grant: &'static PublicationAuthorization,
    fact: &Fact,
    deadline: tokio::time::Instant,
) -> DomainResult<()> {
    let lease = AccessLease::capture(state, principal, headers)?;
    let current = crate::policy_store::authorize_publication(
        state,
        &AuthorizedSubmission {
            principal,
            lease: lease.as_ref(),
            submitted_at: Timestamp::now(),
            authorization: grant,
        },
    )
    .await?;
    fact.origin.matches(&current)?;
    authority::budget(deadline)
}
fn timeout() -> DomainError {
    DomainError::Timeout("Original gateway key lookup budget expired".into())
}

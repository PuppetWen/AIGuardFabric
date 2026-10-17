use super::{
    KIND,
    authority::Submission,
    configuration::{ProfileInput, ProfileView, StoredProfile, absent_view},
    endpoint, util,
};
use crate::{
    AppState, Principal, model_gateway::StoredEndpoint, policy_store::OfflinePublicationProof,
    store::asset_transaction::AssetTransaction,
};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::DomainResult,
    ids::{Id, TenantId},
};
use agf_storage::configuration::{
    BoundedConfigurationList, ConfigurationGuard, GuardedBatchDecision, OfflineGuardedBatch,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) async fn load(state: &AppState, principal: &Principal) -> DomainResult<ProfileView> {
    principal.require(state, "models", "read").map_err(|error| error.error)?;
    let rows = state.configurations.list_bounded::<Value>(principal.tenant, KIND, 1, 16 * 1024).await?;
    let BoundedConfigurationList::Complete(rows) = rows else {
        return Err(util::corrupt());
    };
    let row = rows
        .into_iter()
        .next()
        .map(serde_json::from_value::<StoredProfile>)
        .transpose()
        .map_err(|_| util::corrupt())?;
    match row {
        None => Ok(absent_view()),
        Some(row) => {
            row.validate(principal.tenant)?;
            Ok(row.view())
        }
    }
}

/// Original submission surrounds locks, audit wait and publication; no provider request is made.
pub(crate) async fn save(state: &AppState, submission: &Submission, input: &ProfileInput) -> DomainResult<ProfileView> {
    input.validate()?;
    tokio::time::timeout_at(submission.deadline, Box::pin(save_inner(state, submission, input)))
        .await
        .map_err(|_| util::stale())?
}
async fn save_inner(state: &AppState, submission: &Submission, input: &ProfileInput) -> DomainResult<ProfileView> {
    submission.authorize(state).await?;
    if state.store.database().is_some() {
        return sql(state, submission, input).await;
    }
    offline(state, submission, input).await
}
fn guards(input: &ProfileInput) -> Vec<(String, Id)> {
    let mut keys = if input.enabled {
        input
            .settings
            .as_ref()
            .map(|settings| {
                vec![
                    (crate::model_gateway::ENDPOINT_KIND.into(), settings.chat_endpoint_id),
                    (crate::model_gateway::ENDPOINT_KIND.into(), settings.embedding_endpoint_id),
                ]
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    keys.sort();
    keys.dedup();
    keys
}
fn validate_references(
    state: &AppState,
    tenant: TenantId,
    input: &ProfileInput,
    rows: &BTreeMap<(String, Id), Option<Value>>,
) -> DomainResult<()> {
    if !input.enabled {
        return Ok(());
    }
    let settings = input.settings.as_ref().ok_or_else(util::invalid)?;
    let read = |id| -> DomainResult<StoredEndpoint> {
        serde_json::from_value(
            rows.get(&(crate::model_gateway::ENDPOINT_KIND.into(), id))
                .and_then(Option::as_ref)
                .cloned()
                .ok_or_else(util::stale)?,
        )
        .map_err(Into::into)
    };
    endpoint::validate(
        state,
        tenant,
        settings,
        &read(settings.chat_endpoint_id)?,
        &read(settings.embedding_endpoint_id)?,
    )
}
fn audit(submission: &Submission, row: &StoredProfile) -> AuditLog {
    let mut log = AppState::audit_entry(
        row.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, "semantic-cache-profile"),
        AuditTarget::new(KIND, Some(row.id.to_string()), None),
        "",
    );
    log.after = Some(json!({"version":row.version,"enabled":row.enabled,
        "mode":row.settings.as_ref().map(|settings| settings.mode),
        "providerContacted":false,"providerWeightsRevisionVerified":false}));
    log
}
async fn offline(state: &AppState, submission: &Submission, input: &ProfileInput) -> DomainResult<ProfileView> {
    let authorization = submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &authorization).await?;
    let keys = guards(input);
    let refs = keys.iter().map(|(kind, id)| ConfigurationGuard { kind, id: *id }).collect::<Vec<_>>();
    let mut output = absent_view();
    state.configurations.mutate_offline_guarded_batch_audited(
        submission.principal.tenant,
        OfflineGuardedBatch {
            kind: KIND,
            id: util::record_id(submission.principal.tenant),
            guards: &refs,
            security: Some(OfflinePublicationProof::security(&authorization)?),
            related: &[],
            max_main_bytes: 16 * 1024,
            max_related_bytes: 1024 * 1024,
            max_total_write_bytes: 8 * 1024 * 1024,
        },
        |locked, current: &mut Option<StoredProfile>, _| {
            validate_references(state, submission.principal.tenant, input, &locked.guards)?;
            let candidate = input.apply(submission.principal.tenant, current.as_ref())?;
            candidate.validate(submission.principal.tenant)?;
            output = candidate.view();
            let log = audit(submission, &candidate);
            *current = Some(candidate);
            Ok(GuardedBatchDecision::Write { related: BTreeMap::new(), audit: Box::new(log) })
        },
        |log, locked| {
            proof.check(state, &authorization, locked)?;
            validate_references(state, submission.principal.tenant, input, &locked.guards)?;
            submission.budget()?;
            state.store.audit_append(log)
        },
    )?;
    Ok(output)
}
async fn sql(state: &AppState, submission: &Submission, input: &ProfileInput) -> DomainResult<ProfileView> {
    let db = state.store.database().ok_or_else(util::corrupt)?;
    let tenant = submission.principal.tenant;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    // Sort all source and profile keys together, matching existing configuration lock identities.
    let id = util::record_id(tenant);
    let mut keys = guards(input);
    keys.push((KIND.into(), id));
    keys.sort();
    let mut rows = BTreeMap::new();
    for (kind, id) in keys {
        tx.configuration_lock(&kind, id).await?;
        rows.insert((kind.clone(), id), tx.configuration::<Value>(&kind, id).await?);
    }
    validate_references(state, tenant, input, &rows)?;
    let current: Option<StoredProfile> =
        rows.get(&(KIND.into(), id)).cloned().flatten().map(serde_json::from_value).transpose()?;
    let candidate = input.apply(tenant, current.as_ref())?;
    candidate.validate(tenant)?;
    submission.authorize(state).await?;
    tx.configure(KIND, id, Some(serde_json::to_value(&candidate)?)).await?;
    tx.audit(audit(submission, &candidate)).await?;
    submission.authorize(state).await?;
    validate_references(state, tenant, input, &rows)?;
    submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(candidate.view())
}

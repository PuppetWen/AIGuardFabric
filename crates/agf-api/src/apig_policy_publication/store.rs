//! APIG facts, bounded encrypted bodies and one audit publish under the same authority fence.
use super::{
    authority::Submission,
    contract::Scope,
    dependencies,
    records::{Fence, Main, Values},
    sql, util,
};
use crate::{
    policy_store::{OfflinePublicationProof, TrustedPolicySelection},
    state::AppState,
};
use agf_core::{
    asset::Asset,
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    policy::Policy,
};
use agf_storage::configuration::{ConfigurationGuard, GuardedBatchDecision, OfflineGuardedBatch};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Mutation<'a> {
    pub submission: &'a Submission,
    pub scope: Option<&'a Scope>,
    pub selection: Option<&'a TrustedPolicySelection>,
    pub fence: Option<&'a Fence>,
    pub source: &'a [Policy],
    pub related: &'a [ConfigurationGuard<'static>],
}
pub(super) struct Snapshot {
    pub related: Values,
}

pub(super) enum Decision {
    Unchanged,
    Write { related: Values, audit: Box<AuditLog> },
}

pub(super) async fn load(state: &AppState, tenant: TenantId) -> DomainResult<Main> {
    let main =
        state.configurations.get(tenant, super::records::STATE, util::main_id(tenant)).await?.unwrap_or_default();
    validate_main(&main, tenant)?;
    Ok(main)
}

pub(super) async fn mutate<F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<Main>
where
    F: FnOnce(&mut Main, &Snapshot) -> DomainResult<Decision> + Send,
{
    validate_options(&options)?;
    if state.store.database().is_some() {
        return Box::pin(sql::mutate(state, options, apply)).await;
    }
    let submission = options.submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &submission).await?;
    let tenant = submission.principal.tenant;
    let guards = dependencies::guards(options.scope, options.selection);
    let mut declared =
        options.related.iter().map(|key| ConfigurationGuard { kind: key.kind, id: key.id }).collect::<Vec<_>>();
    declared.sort_by_key(|key| (key.kind, key.id));
    let assets = offline_assets(state, tenant, options.selection)?;
    let (main, _) = state.configurations.mutate_offline_guarded_batch_audited(
        tenant,
        OfflineGuardedBatch {
            kind: super::records::STATE,
            id: util::main_id(tenant),
            guards: &guards,
            security: Some(OfflinePublicationProof::security(&submission)?),
            related: &declared,
            max_main_bytes: 4 * 1024 * 1024,
            max_related_bytes: 1024 * 1024,
            max_total_write_bytes: 8 * 1024 * 1024,
        },
        |locked, main: &mut Main, originals| {
            util::initialize(main, tenant)?;
            if let Some(scope) = options.scope {
                dependencies::validate_locked(state, scope, options.fence, options.source, &locked.guards, &assets)?;
            }
            let snapshot = Snapshot { related: originals.clone() };
            let Decision::Write { related, audit } = apply(main, &snapshot)? else {
                return Ok(GuardedBatchDecision::Unchanged);
            };
            validate_write(main, tenant, &snapshot.related, &related, &audit)?;
            Ok(GuardedBatchDecision::Write { related, audit })
        },
        |audit, locked| {
            proof.check(state, &submission, locked)?;
            let assets = offline_assets(state, tenant, options.selection)?;
            if let Some(scope) = options.scope {
                dependencies::validate_locked(state, scope, options.fence, options.source, &locked.guards, &assets)?;
            }
            // The approved synchronous sink seals once or changes nothing. No fallible action follows it.
            state.store.audit_append(audit)
        },
    )?;
    Ok(main)
}

pub(super) fn validate_options(options: &Mutation<'_>) -> DomainResult<()> {
    let fenced = options.fence.is_some();
    let selected = options.selection.is_some();
    let scoped = options.scope.is_some();
    if fenced != selected || (fenced && !scoped) {
        return Err(DomainError::Internal("发布事务缺少完整依赖锁声明".into()));
    }
    let tenant = options.submission.principal.tenant;
    if tenant.as_uuid().is_nil() || options.scope.is_some_and(|scope| scope.tenant != tenant) {
        return Err(util::corrupt());
    }
    let guards = dependencies::guards(options.scope, options.selection);
    let mut prerequisites = BTreeSet::new();
    for key in &guards {
        if key.id.is_nil()
            || !prerequisites.insert((key.kind, key.id))
            || (key.kind == super::records::STATE && key.id == util::main_id(tenant))
        {
            return Err(DomainError::Internal("APIG发布依赖声明重复或身份无效".into()));
        }
    }
    if prerequisites.len() > super::MAX_GUARDS {
        return Err(util::capacity());
    }
    let mut related = BTreeSet::new();
    for key in options.related {
        if key.id.is_nil()
            || !matches!(
                key.kind,
                super::records::FACT
                    | super::records::DETAIL
                    | super::records::PREVIEW
                    | super::records::PENDING
                    | super::records::STATE
            )
            || !related.insert((key.kind, key.id))
            || prerequisites.contains(&(key.kind, key.id))
            || (key.kind == super::records::STATE && key.id == util::main_id(options.submission.principal.tenant))
        {
            return Err(DomainError::Internal("发布事务的关联声明重复或不受支持".into()));
        }
    }
    if related.len() > 100
        || options.selection.is_some_and(|selection| selection.agent_ids.len() > super::MAX_AGENT_IDS)
    {
        return Err(util::capacity());
    }
    Ok(())
}

pub(super) fn validate_write(
    main: &mut Main,
    tenant: TenantId,
    originals: &Values,
    related: &Values,
    audit: &AuditLog,
) -> DomainResult<()> {
    if audit.tenant_id != tenant || audit.id.is_nil() {
        return Err(util::corrupt());
    }
    for ((kind, id), value) in related {
        let prior = originals.get(&(kind.clone(), *id)).ok_or_else(util::corrupt)?;
        if matches!(kind.as_str(), super::records::DETAIL | super::records::PREVIEW) {
            let old_size = body_size(prior.as_ref())?;
            let new_size = body_size(value.as_ref())?;
            main.stored_content_bytes = main
                .stored_content_bytes
                .checked_sub(old_size)
                .and_then(|size| size.checked_add(new_size))
                .ok_or_else(util::corrupt)?;
        }
        if let Some(value) = value {
            util::bound(value, 1024 * 1024)?;
        }
    }
    validate_main(main, tenant)?;
    if main.stored_content_bytes > 64 * 1024 * 1024 {
        return Err(util::capacity());
    }
    util::bound(main, 4 * 1024 * 1024)?;
    Ok(())
}

fn body_size(value: Option<&serde_json::Value>) -> DomainResult<usize> {
    let Some(value) = value else {
        return Ok(0);
    };
    let size = util::bound(value, 1024 * 1024)?;
    if value["class"] == "archived" {
        // A validated marker is a permanent light fact, outside the encrypted-body budget.
        serde_json::from_value::<super::records::DetailRecord>(value.clone())?;
        return Ok(0);
    }
    Ok(size)
}

fn validate_main(main: &Main, tenant: TenantId) -> DomainResult<()> {
    if main.tenant.is_some_and(|owner| owner != tenant)
        || main.operations.len() > 128
        || main.previews.len() > 32
        || main.observations.len() > 8
        || [main.operations.as_slice(), main.previews.as_slice(), main.observations.as_slice()]
            .iter()
            .any(|ids| ids.iter().any(Id::is_nil) || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len())
    {
        return Err(util::corrupt());
    }
    Ok(())
}

fn offline_assets(
    state: &AppState,
    tenant: TenantId,
    selection: Option<&TrustedPolicySelection>,
) -> DomainResult<BTreeMap<Id, Asset>> {
    let mut assets = BTreeMap::new();
    if let Some(selection) = selection {
        for id in &selection.agent_ids {
            if let Some(asset) = state.store.asset_get(tenant, *id)? {
                assets.insert(*id, asset);
            }
        }
    }
    Ok(assets)
}

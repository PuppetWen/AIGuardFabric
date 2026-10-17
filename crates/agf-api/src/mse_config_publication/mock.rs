//! The isolated provider persists content separately from the workflow receipt.
//! A workflow audit rollback cannot pretend to undo an accepted provider write.
use super::{
    MAX_CONTENT_BYTES,
    contract::{BundleTarget, Scope, TransportMode},
};
use crate::{model_gateway, state::AppState};
use agf_alicloud::mse::config_cas::{ConfigKey, ConfigObservation, PublishOutcome, content_md5};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

const KIND: &str = "mse-config-publication-mock";
const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    schema: u64,
    engine_origin: String,
    region_id: String,
    instance_id: String,
    namespace_id: String,
    config_group: String,
    config_data_id: String,
    config_dialect: String,
    managed_upsert_confirmed: bool,
    content: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u64,
    tenant_id: TenantId,
    id: Id,
    target_scope_id: Id,
    target: BundleTarget,
    revision: u64,
    content_md5: String,
    content: SecretMaterial,
}

struct Content {
    text: String,
    md5: String,
}

pub(super) async fn query(state: &AppState, scope: &Scope) -> DomainResult<ConfigObservation> {
    let row = state
        .configurations
        .mutate::<Option<Record>, _>(scope.tenant, KIND, record_id(scope), |stored| {
            if stored.is_none() {
                *stored = Some(seed(state, scope)?);
            }
            checked(state, scope, stored.as_ref().ok_or_else(corrupt)?)?;
            Ok(())
        })
        .await?
        .ok_or_else(corrupt)?;
    let content = checked(state, scope, &row)?;
    Ok(ConfigObservation {
        key: ConfigKey {
            namespace_id: scope.target.namespace_id.clone(),
            group: scope.target.group.clone(),
            data_id: scope.target.data_id.clone(),
        },
        content: content.text,
        md5: content.md5,
        observed_at: Timestamp::now(),
    })
}

pub(super) async fn publish(
    state: &AppState,
    scope: &Scope,
    expected_md5: &str,
    desired: &str,
) -> DomainResult<PublishOutcome> {
    if desired.len() > MAX_CONTENT_BYTES {
        return Err(DomainError::PreconditionFailed("Mock配置正文超过256KiB".into()));
    }
    let mut accepted = false;
    state
        .configurations
        .mutate::<Option<Record>, _>(scope.tenant, KIND, record_id(scope), |stored| {
            let current = stored
                .as_ref()
                .ok_or_else(|| DomainError::PreconditionFailed("Mock目标尚未完成明确观察，不能直接发布".into()))?;
            let content = checked(state, scope, current)?;
            if content.md5 != expected_md5 {
                return Ok(());
            }
            let mut candidate = current.clone();
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or_else(|| DomainError::PreconditionFailed("Mock配置修订已达上限，原内容保持不变".into()))?;
            candidate.content = encrypted(state, scope, desired)?;
            candidate.content_md5 = content_md5(desired);
            bounded(&candidate)?;
            *stored = Some(candidate);
            accepted = true;
            Ok(())
        })
        .await?;
    Ok(if accepted { PublishOutcome::Accepted } else { PublishOutcome::Conflict })
}

fn seed(state: &AppState, scope: &Scope) -> DomainResult<Record> {
    let seed: Seed = serde_json::from_str(include_str!("fixtures/mock-target.json"))?;
    let target = &scope.target;
    let observed = (
        &target.engine_origin,
        &target.region,
        &target.instance_id,
        &target.namespace_id,
        &target.group,
        &target.data_id,
        &target.dialect,
    );
    let expected = (
        &seed.engine_origin,
        &seed.region_id,
        &seed.instance_id,
        &seed.namespace_id,
        &seed.config_group,
        &seed.config_data_id,
        &seed.config_dialect,
    );
    let same_target = observed == expected;
    if target.transport_mode != TransportMode::Mock
        || !target.mocked
        || seed.schema != 1
        || !seed.managed_upsert_confirmed
        || !same_target
    {
        return Err(DomainError::PreconditionFailed(
            "Mock仅支持指南中的明确示例目标，不为未知target制造存在证据".into(),
        ));
    }
    let row = Record {
        schema: 1,
        tenant_id: scope.tenant,
        id: record_id(scope),
        target_scope_id: target.target_scope_id,
        target: BundleTarget::from(target),
        revision: 1,
        content_md5: content_md5(&seed.content),
        content: encrypted(state, scope, &seed.content)?,
    };
    bounded(&row)?;
    Ok(row)
}

fn checked(state: &AppState, scope: &Scope, row: &Record) -> DomainResult<Content> {
    let same_identity =
        (row.tenant_id, row.id, row.target_scope_id) == (scope.tenant, record_id(scope), scope.target.target_scope_id);
    let aad = FieldCipher::make_aad(&scope.tenant, &row.id);
    if scope.target.transport_mode != TransportMode::Mock
        || !scope.target.mocked
        || row.schema != 1
        || row.revision == 0
        || !same_identity
        || row.target != BundleTarget::from(&scope.target)
        || row.content.aad.as_deref() != Some(aad.as_str())
    {
        return Err(corrupt());
    }
    bounded(row)?;
    let plaintext = model_gateway::cipher(state)?.decrypt(&row.content)?;
    let text = plaintext.expose_secret();
    if text.len() > MAX_CONTENT_BYTES || row.content_md5 != content_md5(text) {
        return Err(corrupt());
    }
    Ok(Content { text: text.into(), md5: row.content_md5.clone() })
}

fn encrypted(state: &AppState, scope: &Scope, text: &str) -> DomainResult<SecretMaterial> {
    if text.len() > MAX_CONTENT_BYTES {
        return Err(DomainError::PreconditionFailed("Mock配置正文超过256KiB".into()));
    }
    model_gateway::encrypt(state, scope.tenant, record_id(scope), text.into())
}
fn record_id(scope: &Scope) -> Id {
    deterministic_id("agf.mse.config-publication.mock", &format!("{}:{}", scope.tenant, scope.target.target_scope_id))
}
fn bounded(row: &Record) -> DomainResult<()> {
    if serde_json::to_vec(row)?.len() > MAX_RECORD_BYTES {
        return Err(DomainError::PreconditionFailed("Mock配置记录超过1MiB，原内容保持不变".into()));
    }
    Ok(())
}
fn corrupt() -> DomainError {
    DomainError::Crypto("持久Mock配置的租户、目标或内容校验失败".into())
}

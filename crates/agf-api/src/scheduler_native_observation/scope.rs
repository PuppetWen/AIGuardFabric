use super::util;
use crate::{
    cloud_store,
    integration_store::{Stored, decrypt},
    state::AppState,
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SourceTarget {
    pub tenant: TenantId,
    pub configuration_id: Id,
    pub configuration_version: u64,
    pub scope_id: Id,
    pub fingerprint: String,
    pub region: String,
    pub rpc_origin: String,
    pub configured_account_id: Option<String>,
    pub account_identity_verified: bool,
    pub cluster_id: String,
    pub app_name: String,
    pub mocked: bool,
    pub transport_mode: String,
}
impl SourceTarget {
    pub(super) fn native(&self) -> agf_alicloud::schedulerx3::native_observation::Scope {
        agf_alicloud::schedulerx3::native_observation::Scope {
            cluster_id: self.cluster_id.clone(),
            app_name: self.app_name.clone(),
        }
    }
}
pub(super) fn from_row(state: &AppState, tenant: TenantId, row: &Stored) -> DomainResult<SourceTarget> {
    if !row.enabled
        || row.name != super::NAME
        || row.version == 0
        || row.id != crate::integration_store::id(tenant, super::NAME)
    {
        return Err(util::stale());
    }
    let private = decrypt(state, tenant, row)?;
    let required = |key| {
        private
            .settings
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| util::text(value, 256))
            .map(str::to_owned)
            .ok_or_else(|| {
                DomainError::PreconditionFailed("请明确配置 Scheduler region_id、cluster_id 和 app_name".into())
            })
    };
    let region = required("region_id")?;
    let cluster_id = required("cluster_id")?;
    let app_name = required("app_name")?;
    let resolved = cloud_store::endpoint(AliCloudService::SchedulerX3, &private)?;
    let rpc_origin = normalized_origin(&resolved.url("/"))?;
    let configured_account_id = account_text(private.settings.get("account_id"))?;
    let mocked = state.config.mock_mode || row.mock;
    let transport_mode = if mocked {
        "mock".to_owned()
    } else {
        state.scheduler_native_observation.mode(tenant, &rpc_origin)?.to_owned()
    };
    let mut target = SourceTarget {
        tenant,
        configuration_id: row.id,
        configuration_version: row.version,
        scope_id: Id::nil(),
        fingerprint: super::source_fingerprint(&serde_json::to_value(row)?)?,
        region,
        rpc_origin,
        configured_account_id,
        account_identity_verified: false,
        cluster_id,
        app_name,
        mocked,
        transport_mode,
    };
    target.scope_id = identity(&target)?;
    Ok(target)
}
pub(super) fn identity(target: &SourceTarget) -> DomainResult<Id> {
    Ok(deterministic_id(
        "agf.scheduler.native.scope",
        &util::canonical_hash(&json!({
            "tenant":target.tenant,"configuration":target.configuration_id,
            "endpoint":target.rpc_origin,"region":target.region,"cluster":target.cluster_id,
            "app":target.app_name,"mocked":target.mocked,"transportMode":target.transport_mode,
            "configuredAccount":target.configured_account_id
        }))?,
    ))
}
pub(super) fn normalized_origin(origin: &str) -> DomainResult<String> {
    let url = url::Url::parse(origin).map_err(|_| util::corrupt())?;
    let literal_loopback = url
        .host_str()
        .is_some_and(|host| host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
    if (url.scheme() != "https" && !(url.scheme() == "http" && literal_loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
    {
        return Err(DomainError::PreconditionFailed(
            "Scheduler RPC 来源须为 HTTPS 根地址或具备显式测试能力的字面回环地址".into(),
        ));
    }
    Ok(format!("{}/", url.origin().ascii_serialization()))
}
fn account_text(value: Option<&serde_json::Value>) -> DomainResult<Option<String>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) if value.is_empty() => Ok(None),
        Some(serde_json::Value::String(value)) if util::text(value, 256) => Ok(Some(value.clone())),
        _ => Err(DomainError::PreconditionFailed("配置 account_id 须为有界文本；它不证明云账号身份".into())),
    }
}
pub(super) async fn current(state: &AppState, tenant: TenantId) -> DomainResult<Option<SourceTarget>> {
    let row = cloud_store::load(state, tenant, super::NAME).await?;
    row.filter(|row| row.enabled).map(|row| from_row(state, tenant, &row)).transpose()
}
pub(super) fn validate_locked(
    state: &AppState,
    expected: &SourceTarget,
    value: Option<&serde_json::Value>,
) -> DomainResult<()> {
    let row: Stored = value.cloned().map(serde_json::from_value).transpose()?.ok_or_else(util::stale)?;
    if from_row(state, expected.tenant, &row)? != *expected {
        return Err(util::stale());
    }
    Ok(())
}

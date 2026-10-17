//! Per-tenant LDAP/AD directory configuration and password login.
use super::*;
use agf_auth::ldap::Config;

mod settings;
mod sign_in;

const KIND: &str = "ldap-provider";

#[derive(Clone, Serialize, Deserialize)]
struct Directory {
    revision: Id,
    enabled: bool,
    name: String,
    config: Config,
    auto_provision: bool,
    default_role: String,
    secret: Option<SecretMaterial>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/settings/identity/ldap", get(settings::get).put(settings::save))
        .route("/auth/ldap/login", post(sign_in::login))
}

async fn provider(state: &AppState, tenant: TenantId) -> DomainResult<Directory> {
    state
        .configurations
        .get(tenant, KIND, Id::nil())
        .await?
        .filter(|p: &Directory| p.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("此租户尚未启用 LDAP/AD 登录，请联系管理员".into()))
}

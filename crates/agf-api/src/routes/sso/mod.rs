//! Tenant OIDC configuration and browser-bound login transactions.
use crate::{error::ApiResult, middleware::Principal, routes::ApiJson, state::AppState};
use agf_auth::oidc::{self, ClientAuth, Metadata};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod configuration;
mod flow;
mod identity;
mod ldap;
mod qr;
mod recent;
mod saml;
pub(crate) use recent::verify as verify_recent;

const KIND: &str = "oidc-provider";
const FLOW_KIND: &str = "oidc-login-flow";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/settings/identity/oidc", get(configuration::get).put(configuration::save))
        .route("/auth/oidc/start", post(flow::start))
        .route("/auth/oidc/exchange", post(flow::exchange))
        .route("/auth/oidc/complete", post(flow::complete))
        .merge(saml::router())
        .merge(qr::router())
        .merge(ldap::router())
}

#[derive(Clone, Serialize, Deserialize)]
struct Provider {
    revision: Id,
    enabled: bool,
    name: String,
    issuer: String,
    client_id: String,
    client_auth: ClientAuth,
    redirect_uri: String,
    auto_provision: bool,
    default_role: String,
    email_domains: Vec<String>,
    secret: Option<SecretMaterial>,
    metadata: Option<Metadata>,
}

async fn provider(state: &AppState, tenant: TenantId) -> DomainResult<Provider> {
    state
        .configurations
        .get(tenant, KIND, Id::nil())
        .await?
        .filter(|p: &Provider| p.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("此租户尚未启用企业 OIDC 登录，请联系管理员".into()))
}

fn unseal(state: &AppState, tenant: TenantId, id: Id, secret: &SecretMaterial) -> DomainResult<String> {
    let aad = agf_storage::crypto::FieldCipher::make_aad(&tenant, &id);
    if secret.aad.as_deref() != Some(&aad) {
        return Err(DomainError::Crypto("身份配置绑定不匹配".into()));
    }
    Ok(crate::model_gateway::cipher(state)?.decrypt(secret)?.expose_secret().to_owned())
}

fn denied() -> DomainError {
    DomainError::Unauthenticated("企业登录事务无效或已使用，请重新登录".into())
}

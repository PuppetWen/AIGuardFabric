//! Tenant-scoped, SP-initiated SAML browser login.
use super::*;
use agf_auth::service::{LoginOutcome, LoginRequest};
use agf_core::user::{IdentityProvider, User};
use axum::{
    body::Bytes,
    extract::Path,
    http::header,
    response::{IntoResponse, Redirect},
};
use saml_rs::{
    AcsEndpoint, AuthnRequestSigningPolicy, BrowserInput, Credentials, EntityId, IdpDescriptor, MetadataTrustPolicy,
    Pending, PendingSnapshot, PrivateKeyPem, RelayStateParam, ResponseSignaturePolicy, Saml, SamlValidationContext,
    SpConfig, SpValidationPolicy, SsoResponse, StartSso,
};

mod configuration;
mod flow;

const KIND: &str = "saml-provider";
const FLOW_KIND: &str = "saml-login-flow";
const REPLAY_KIND: &str = "saml-replay";

#[derive(Clone, Serialize, Deserialize)]
struct Provider {
    revision: Id,
    enabled: bool,
    name: String,
    idp_metadata_xml: String,
    idp_entity_id: String,
    sp_entity_id: String,
    acs_url: String,
    auto_provision: bool,
    default_role: String,
    email_domains: Vec<String>,
    email_attribute: String,
    name_attribute: String,
    signing_cert: String,
    signing_key: SecretMaterial,
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/settings/identity/saml", get(configuration::get).put(configuration::save))
        .route("/auth/saml/{tenant_slug}/metadata", get(configuration::metadata))
        .route("/auth/saml/start", post(flow::start))
        .route("/auth/saml/{tenant_slug}/acs", post(flow::acs))
        .route("/auth/saml/status", post(flow::status))
        .route("/auth/saml/complete", post(flow::complete))
}

async fn provider(state: &AppState, tenant: TenantId) -> DomainResult<Provider> {
    state
        .configurations
        .get(tenant, KIND, Id::nil())
        .await?
        .filter(|p: &Provider| p.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("此租户尚未启用 SAML 登录，请联系管理员".into()))
}

fn idp(provider: &Provider) -> DomainResult<IdpDescriptor> {
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(&provider.idp_entity_id).map_err(saml_error)?,
        &provider.idp_metadata_xml,
        // This XML is pasted by an authorized tenant administrator and stored locally;
        // no unauthenticated metadata URL is fetched or trusted during login.
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .map_err(saml_error)
}

fn sp(state: &AppState, tenant: TenantId, provider: &Provider) -> DomainResult<Saml<saml_rs::Sp>> {
    let key = unseal(state, tenant, Id::nil(), &provider.signing_key)?;
    let mut policy = SpValidationPolicy::strict();
    // A root-signed Response protects its enclosed Assertion. Requiring both
    // signatures would reject common enterprise IdPs without improving trust.
    policy.assertions = saml_rs::AssertionSignaturePolicy::AllowUnsignedForCompatibility;
    policy.responses = ResponseSignaturePolicy::RequireSigned;
    policy.authn_requests = AuthnRequestSigningPolicy::Sign;
    let config = SpConfig::builder(EntityId::try_new(&provider.sp_entity_id).map_err(saml_error)?)
        .acs_endpoint(AcsEndpoint::post(&provider.acs_url).map_err(saml_error)?)
        .credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(key)),
            signing_certificate: Some(saml_rs::CertificatePem::new(&provider.signing_cert)),
            ..Credentials::default()
        })
        .validation(policy)
        .build()
        .map_err(saml_error)?;
    Saml::sp(config).map_err(saml_error)
}

fn saml_error(error: saml_rs::SamlError) -> DomainError {
    tracing::warn!(reason = %error, "SAML 验证失败");
    DomainError::Unauthenticated("SAML 身份验证未通过，请重新登录或检查身份服务配置".into())
}

async fn resolve_user(
    state: &AppState,
    tenant: TenantId,
    provider: &Provider,
    session: &saml_rs::SsoSession,
) -> DomainResult<User> {
    let subject = session.name_id().value();
    if subject.is_empty() || subject.len() > 512 {
        return Err(DomainError::Unauthenticated("身份服务没有提供有效的 NameID".into()));
    }
    let attribute = |name: &str| -> Option<String> {
        session
            .attributes()
            .get(name)
            .and_then(|a| a.values().first())
            .map(|v| v.as_str().trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let email = attribute(&provider.email_attribute).or_else(|| subject.contains('@').then(|| subject.to_owned()));
    if !provider.email_domains.is_empty()
        && !email
            .as_ref()
            .and_then(|v| v.rsplit_once('@'))
            .is_some_and(|(_, domain)| provider.email_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
    {
        return Err(DomainError::Forbidden("SAML 身份不属于允许的邮箱域名".into()));
    }
    let external = serde_json::to_string(&[&provider.idp_entity_id, subject])?;
    let id = agf_core::ids::deterministic_id("saml-user", &format!("{tenant}:{external}"));
    if state.auth_backend.find_user(tenant, id).await?.is_none() && provider.auto_provision {
        let mut user = User::new_local(tenant, format!("saml-{id}"), email.unwrap_or_default());
        user.id = id;
        user.idp = IdentityProvider::Saml;
        user.external_subject = Some(external.clone());
        user.must_change_password = false;
        user.display_name = attribute(&provider.name_attribute).unwrap_or_else(|| user.username.clone());
        state.auth_backend.provision_federated(&user, std::slice::from_ref(&provider.default_role)).await?;
    }
    let user = state
        .auth_backend
        .find_user(tenant, id)
        .await?
        .ok_or_else(|| DomainError::Forbidden("SAML 账号尚未纳管，请联系管理员启用首次登录创建账号".into()))?;
    if user.idp != IdentityProvider::Saml
        || user.external_subject.as_deref() != Some(&external)
        || user.is_superadmin
        || !user.can_authenticate()
    {
        return Err(DomainError::Forbidden("企业账号不可用".into()));
    }
    Ok(user)
}

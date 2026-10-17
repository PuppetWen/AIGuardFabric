use super::*;

#[derive(Deserialize)]
pub(super) struct Body {
    expected_revision: Option<Id>,
    enabled: bool,
    name: String,
    idp_metadata_xml: String,
    sp_entity_id: String,
    acs_url: String,
    auto_provision: bool,
    default_role: String,
    #[serde(default)]
    email_domains: Vec<String>,
    email_attribute: String,
    name_attribute: String,
    #[serde(default)]
    rotate_signing_key: bool,
}

fn public(provider: &Provider) -> Value {
    json!({"revision":provider.revision, "enabled":provider.enabled, "name":provider.name,
        "idp_metadata_xml":provider.idp_metadata_xml, "idp_entity_id":provider.idp_entity_id,
        "sp_entity_id":provider.sp_entity_id, "acs_url":provider.acs_url,
        "auto_provision":provider.auto_provision, "default_role":provider.default_role,
        "email_domains":provider.email_domains, "email_attribute":provider.email_attribute,
        "name_attribute":provider.name_attribute, "signing_certificate":provider.signing_cert})
}

pub(super) async fn get(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "read")?;
    let stored: Option<Provider> = state.configurations.get(principal.tenant, KIND, Id::nil()).await?;
    Ok(Json(stored.as_ref().map_or_else(
        || {
            json!({
                "revision":null, "enabled":false, "name":"企业 SAML", "idp_metadata_xml":"",
                "idp_entity_id":"", "sp_entity_id":"", "acs_url":"", "auto_provision":false,
                "default_role":"viewer", "email_domains":[], "email_attribute":"email",
                "name_attribute":"displayName", "signing_certificate":""
            })
        },
        public,
    )))
}

fn validate_urls(body: &Body, slug: &str) -> DomainResult<()> {
    let sp = agf_auth::oidc::endpoint(&body.sp_entity_id)?;
    let acs = agf_auth::oidc::endpoint(&body.acs_url)?;
    if sp.path() != format!("/api/v1/auth/saml/{slug}/metadata")
        || acs.path() != format!("/api/v1/auth/saml/{slug}/acs")
        || sp.origin() != acs.origin()
        || sp.query().is_some()
        || acs.query().is_some()
    {
        return Err(DomainError::Validation("SAML 服务地址应使用控制台同源的本租户 metadata/acs 路径".into()));
    }
    Ok(())
}

fn validate_metadata(body: &Body) -> DomainResult<String> {
    if body.idp_metadata_xml.len() > 131_072 {
        return Err(DomainError::Validation("IdP 元数据不能超过 128 KiB".into()));
    }
    let descriptor =
        IdpDescriptor::from_metadata_xml(&body.idp_metadata_xml, MetadataTrustPolicy::UnsignedForCompatibility)
            .map_err(saml_error)?;
    let metadata = descriptor.metadata();
    let sso = metadata
        .get_single_sign_on_service(saml_rs::constants::Binding::Redirect)
        .ok_or_else(|| DomainError::Validation("IdP 元数据缺少 HTTP-Redirect 登录地址".into()))?;
    agf_auth::oidc::endpoint(&sso)?;
    if metadata.x509_certificates(saml_rs::constants::CertUse::Signing).is_empty() {
        return Err(DomainError::Validation("IdP 元数据缺少响应签名证书".into()));
    }
    Ok(descriptor.entity_id().as_str().to_owned())
}

fn new_signing_key(state: &AppState, tenant: TenantId) -> DomainResult<(String, SecretMaterial)> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 3072)
        .map_err(|_| DomainError::Crypto("SAML RSA 密钥生成失败".into()))?;
    let pem = private.to_pkcs8_pem(LineEnding::LF).map_err(|_| DomainError::Crypto("SAML RSA 密钥编码失败".into()))?;
    let key =
        rcgen::KeyPair::from_pem(pem.as_str()).map_err(|_| DomainError::Crypto("SAML RSA 密钥加载失败".into()))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|_| DomainError::Crypto("SAML 证书参数无效".into()))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "AIGuardFabric SAML SP");
    let cert = params.self_signed(&key).map_err(|_| DomainError::Crypto("SAML 签名证书生成失败".into()))?;
    let sealed = crate::model_gateway::encrypt(state, tenant, Id::nil(), key.serialize_pem())?;
    Ok((cert.pem(), sealed))
}

pub(super) async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Body>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "write")?;
    let tenant = principal.tenant;
    let slug = crate::tenant_directory::get(&state, tenant).await?.slug;
    validate_urls(&body, &slug)?;
    if body.name.trim().is_empty()
        || body.name.len() > 128
        || !["viewer", "auditor", "soc-analyst", "asset-owner"].contains(&body.default_role.as_str())
        || body.email_domains.len() > 100
        || [body.email_attribute.as_str(), body.name_attribute.as_str()]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 256)
    {
        return Err(DomainError::Validation("请填写 SAML 名称、属性名和受支持的默认角色".into()).into());
    }
    let domains: Vec<String> = body.email_domains.iter().map(|s| s.trim().to_ascii_lowercase()).collect();
    if domains.iter().any(|s| {
        s.is_empty()
            || s.len() > 253
            || !s.contains('.')
            || !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    }) {
        return Err(DomainError::Validation("邮箱域名请填写完整域名，不使用通配符".into()).into());
    }
    let idp_entity_id = if body.enabled || !body.idp_metadata_xml.trim().is_empty() {
        validate_metadata(&body)?
    } else {
        String::new()
    };
    let old: Option<Provider> = state.configurations.get(tenant, KIND, Id::nil()).await?;
    if old.is_some() && body.expected_revision.is_none() {
        return Err(DomainError::Validation("编辑 SAML 配置须提供 expected_revision，请重新加载".into()).into());
    }
    if old.as_ref().map(|p| p.revision) != body.expected_revision {
        return Err(DomainError::Conflict("SAML 配置已被其他人修改，请重新加载后合并变更".into()).into());
    }
    let expected = body.expected_revision;
    let (signing_cert, signing_key) = if !body.rotate_signing_key {
        old.as_ref()
            .map(|p| (p.signing_cert.clone(), p.signing_key.clone()))
            .map_or_else(|| new_signing_key(&state, tenant), Ok)?
    } else {
        new_signing_key(&state, tenant)?
    };
    let stored = Provider {
        revision: Id::new(),
        enabled: body.enabled,
        name: body.name.trim().into(),
        idp_metadata_xml: body.idp_metadata_xml,
        idp_entity_id,
        sp_entity_id: body.sp_entity_id,
        acs_url: body.acs_url,
        auto_provision: body.auto_provision,
        default_role: body.default_role,
        email_domains: domains,
        email_attribute: body.email_attribute.trim().into(),
        name_attribute: body.name_attribute.trim().into(),
        signing_cert,
        signing_key,
    };
    sp(&state, tenant, &stored)?;
    let entry = AppState::audit_entry(
        tenant,
        agf_core::audit::AuditAction::Configure,
        agf_core::audit::AuditOutcome::Success,
        AppState::audit_actor(&principal, "saml"),
        agf_core::audit::AuditTarget::new("saml-provider", None, Some(stored.name.clone())),
        "更新企业 SAML 登录配置",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Option<Provider>, _>(tenant, KIND, Id::nil(), entry.clone(), |current| {
            if current.as_ref().map(|p| p.revision) != expected {
                return Err(DomainError::Conflict("SAML 配置已被其他人修改，请重新加载后合并变更".into()));
            }
            *current = Some(stored.clone());
            Ok(())
        })
        .await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的 SAML 配置审计投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(public(&stored)))
}

pub(super) async fn metadata(
    Path(slug): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<axum::response::Response> {
    let tenant = crate::tenant_directory::resolve(&state, &slug).await?.id;
    let stored: Provider = state
        .configurations
        .get(tenant, KIND, Id::nil())
        .await?
        .ok_or(DomainError::NotFound { entity: "saml-provider", id: slug })?;
    let xml = sp(&state, tenant, &stored)?.metadata_xml().to_owned();
    Ok(([(header::CONTENT_TYPE, "application/samlmetadata+xml; charset=utf-8")], xml).into_response())
}

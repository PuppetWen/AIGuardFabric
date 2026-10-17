use super::*;

#[derive(Deserialize)]
pub(super) struct Body {
    #[serde(default)]
    expected_revision: Option<Id>,
    enabled: bool,
    name: String,
    issuer: String,
    client_id: String,
    #[serde(default)]
    client_auth: ClientAuth,
    client_secret: Option<String>,
    redirect_uri: String,
    #[serde(default)]
    auto_provision: bool,
    default_role: String,
    #[serde(default)]
    email_domains: Vec<String>,
}

fn public(provider: &Provider) -> Value {
    json!({"revision":provider.revision, "enabled":provider.enabled, "name":provider.name, "issuer":provider.issuer,
        "client_id":provider.client_id, "client_auth":provider.client_auth,
        "redirect_uri":provider.redirect_uri, "auto_provision":provider.auto_provision,
        "default_role":provider.default_role, "email_domains":provider.email_domains,
        "credential_configured":provider.secret.is_some(), "discovered":provider.metadata.is_some()})
}

pub(super) async fn get(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "read")?;
    let stored: Option<Provider> = state.configurations.get(principal.tenant, KIND, Id::nil()).await?;
    Ok(Json(stored.map_or_else(
        || {
            json!({"revision":null,"enabled":false,"name":"企业登录", "issuer":"", "client_id":"",
        "client_auth":"client_secret_basic", "redirect_uri":"", "auto_provision":false,
        "default_role":"viewer", "email_domains":[], "credential_configured":false, "discovered":false})
        },
        |p| public(&p),
    )))
}

pub(super) async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Body>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "write")?;
    if body.name.trim().is_empty()
        || body.name.len() > 128
        || body.client_id.trim().is_empty()
        || body.client_id.len() > 512
        || body.client_secret.as_ref().is_some_and(|v| v.len() > 8192)
        || !["viewer", "auditor", "soc-analyst", "asset-owner"].contains(&body.default_role.as_str())
        || body.email_domains.len() > 100
    {
        return Err(DomainError::Validation("请填写名称、Client ID 和受支持的默认角色".into()).into());
    }
    oidc::endpoint(&body.issuer)?;
    let callback = oidc::endpoint(&body.redirect_uri)?;
    if callback.path() != "/login/oidc/callback" || callback.query().is_some() {
        return Err(DomainError::Validation(
            "回调地址应为控制台外部 HTTPS 地址加 /login/oidc/callback，不带查询参数".into(),
        )
        .into());
    }
    let domains: Vec<String> = body.email_domains.iter().map(|s| s.trim().to_ascii_lowercase()).collect();
    if domains.iter().any(|s| {
        s.is_empty()
            || s.len() > 253
            || !s.contains('.')
            || !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    }) {
        return Err(DomainError::Validation("邮箱域名请填写完整域名，例如 example.com，不使用通配符".into()).into());
    }
    let old: Option<Provider> = state.configurations.get(principal.tenant, KIND, Id::nil()).await?;
    if old.is_some() && body.expected_revision.is_none() {
        return Err(DomainError::Validation("编辑企业登录配置须提供 expected_revision，请重新加载".into()).into());
    }
    if old.as_ref().map(|p| p.revision) != body.expected_revision {
        return Err(DomainError::Conflict("企业登录配置已被其他人修改，请重新加载后合并变更".into()).into());
    }
    let expected = body.expected_revision;
    let secret = if body.client_auth == ClientAuth::None {
        None
    } else if let Some(value) = body.client_secret.filter(|v| !v.is_empty()) {
        Some(crate::model_gateway::encrypt(&state, principal.tenant, Id::nil(), value)?)
    } else {
        old.filter(|p| p.issuer == body.issuer && p.client_id == body.client_id).and_then(|p| p.secret)
    };
    if body.enabled && body.client_auth != ClientAuth::None && secret.is_none() {
        return Err(DomainError::Validation("机密客户端必须填写 Client Secret".into()).into());
    }
    let metadata = if body.enabled { Some(oidc::discover(&body.issuer).await?) } else { None };
    let stored = Provider {
        revision: Id::new(),
        enabled: body.enabled,
        name: body.name.trim().into(),
        issuer: body.issuer,
        client_id: body.client_id,
        client_auth: body.client_auth,
        redirect_uri: body.redirect_uri,
        auto_provision: body.auto_provision,
        default_role: body.default_role,
        email_domains: domains,
        secret,
        metadata,
    };
    let entry = AppState::audit_entry(
        principal.tenant,
        agf_core::audit::AuditAction::Configure,
        agf_core::audit::AuditOutcome::Success,
        AppState::audit_actor(&principal, "oidc"),
        agf_core::audit::AuditTarget::new("oidc-provider", None, Some(stored.name.clone())),
        "更新企业 OIDC 登录配置",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Option<Provider>, _>(principal.tenant, KIND, Id::nil(), entry.clone(), |current| {
            if current.as_ref().map(|p| p.revision) != expected {
                return Err(DomainError::Conflict("企业登录配置已被其他人修改，请重新加载后合并变更".into()));
            }
            *current = Some(stored.clone());
            Ok(())
        })
        .await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的 OIDC 配置审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(public(&stored)))
}

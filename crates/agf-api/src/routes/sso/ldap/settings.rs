use super::*;

#[derive(Deserialize)]
pub(super) struct Body {
    expected_revision: Option<Id>,
    enabled: bool,
    name: String,
    config: Config,
    bind_password: Option<String>,
    auto_provision: bool,
    default_role: String,
}

fn public(provider: &Directory) -> Value {
    json!({"revision":provider.revision, "enabled":provider.enabled, "name":provider.name,
        "config":provider.config, "credential_configured":provider.secret.is_some(),
        "auto_provision":provider.auto_provision, "default_role":provider.default_role})
}

pub(super) async fn get(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "read")?;
    let stored: Option<Directory> = state.configurations.get(principal.tenant, KIND, Id::nil()).await?;
    Ok(Json(stored.as_ref().map_or_else(
        || {
            json!({
            "revision":null, "enabled":false, "name":"公司目录", "credential_configured":false,
            "auto_provision":false, "default_role":"viewer", "config":{
                "url":"", "start_tls":false, "base_dn":"", "bind_dn":"",
                "user_filter":"(&(objectClass=user)(sAMAccountName={username}))",
                "id_attribute":"objectGUID", "email_attribute":"mail", "name_attribute":"displayName", "ca_pem":""
            }})
        },
        public,
    )))
}

pub(super) async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Body>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "write")?;
    body.config.validate()?;
    if body.name.trim().is_empty()
        || body.name.len() > 128
        || body.bind_password.as_ref().is_some_and(|value| value.len() > 8192)
        || !["viewer", "auditor", "soc-analyst", "asset-owner"].contains(&body.default_role.as_str())
    {
        return Err(DomainError::Validation("请填写名称、目录连接与受支持的默认角色".into()).into());
    }
    let old: Option<Directory> = state.configurations.get(principal.tenant, KIND, Id::nil()).await?;
    if old.is_some() && body.expected_revision.is_none() {
        return Err(DomainError::Validation("编辑目录配置须提供 expected_revision，请重新加载".into()).into());
    }
    if old.as_ref().map(|p| p.revision) != body.expected_revision {
        return Err(DomainError::Conflict("目录配置已被其他人修改，请重新加载后合并变更".into()).into());
    }
    let expected = body.expected_revision;
    let secret = if let Some(password) = body.bind_password.filter(|value| !value.is_empty()) {
        Some(crate::model_gateway::encrypt(&state, principal.tenant, Id::nil(), password)?)
    } else {
        old.as_ref()
            .filter(|p| p.config.url == body.config.url && p.config.bind_dn == body.config.bind_dn)
            .and_then(|p| p.secret.clone())
    };
    if body.enabled && secret.is_none() {
        return Err(DomainError::Validation("启用目录登录前请填写服务账号口令".into()).into());
    }
    let stored = Directory {
        revision: Id::new(),
        enabled: body.enabled,
        name: body.name.trim().into(),
        config: body.config,
        auto_provision: body.auto_provision,
        default_role: body.default_role,
        secret,
    };
    let entry = AppState::audit_entry(
        principal.tenant,
        agf_core::audit::AuditAction::Configure,
        agf_core::audit::AuditOutcome::Success,
        AppState::audit_actor(&principal, "ldap"),
        agf_core::audit::AuditTarget::new("ldap-provider", None, Some(stored.name.clone())),
        "更新 LDAP/AD 登录配置",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Option<Directory>, _>(principal.tenant, KIND, Id::nil(), entry.clone(), |current| {
            if current.as_ref().map(|p| p.revision) != expected {
                return Err(DomainError::Conflict("目录配置已被其他人修改，请重新加载后合并变更".into()));
            }
            *current = Some(stored.clone());
            Ok(())
        })
        .await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的目录配置审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(public(&stored)))
}

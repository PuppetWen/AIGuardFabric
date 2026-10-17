use super::*;
use agf_auth::service::{LoginOutcome, LoginRequest};
use agf_core::secret::generate_token;
use axum::http::HeaderMap;

#[derive(Default, Serialize, Deserialize)]
struct Flow {
    revision: Option<Id>,
    started_at: i64,
    expires_at: i64,
    phase: String,
    sealed: Option<SecretMaterial>,
    user_id: Option<Id>,
    attempts: u8,
}
#[derive(Serialize, Deserialize)]
struct Secrets {
    binding_hash: String,
    verifier: String,
    nonce: String,
}

#[derive(Deserialize)]
pub(super) struct Start {
    tenant_slug: String,
}
#[derive(Deserialize)]
pub(super) struct Callback {
    tenant_slug: String,
    state: Id,
    binding: String,
    code: Option<String>,
    mfa_code: Option<String>,
}

pub(super) async fn start(State(state): State<AppState>, ApiJson(body): ApiJson<Start>) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    let metadata = provider.metadata.as_ref().ok_or_else(denied)?;
    state.configurations.purge_expired(tenant, FLOW_KIND, Timestamp::now().unix_secs()).await?;
    let id = Id::from_uuid(uuid::Uuid::new_v4());
    let binding = generate_token();
    let secrets =
        Secrets { binding_hash: oidc::challenge(&binding), verifier: generate_token(), nonce: generate_token() };
    let url = oidc::authorize_url(
        metadata,
        &provider.client_id,
        &provider.redirect_uri,
        &id.to_string(),
        &secrets.nonce,
        &secrets.verifier,
    )?;
    let now = Timestamp::now().unix_secs();
    let flow = Flow {
        revision: Some(provider.revision),
        started_at: now,
        expires_at: now + 600,
        phase: "pending".into(),
        sealed: Some(crate::model_gateway::encrypt(&state, tenant, id, serde_json::to_string(&secrets)?)?),
        ..Flow::default()
    };
    state.configurations.put(tenant, FLOW_KIND, id, &flow).await?;
    Ok(Json(json!({"authorization_url":url, "state":id, "binding":binding, "redirect_uri":provider.redirect_uri})))
}

async fn claim(
    state: &AppState,
    tenant: TenantId,
    provider: &Provider,
    body: &Callback,
    phase: &str,
    next: &str,
) -> DomainResult<(Flow, Secrets)> {
    if !(32..=256).contains(&body.binding.len()) {
        return Err(denied());
    }
    let flow: Flow = state
        .configurations
        .mutate(tenant, FLOW_KIND, body.state, |flow: &mut Flow| {
            if flow.revision != Some(provider.revision)
                || flow.expires_at <= Timestamp::now().unix_secs()
                || flow.phase != phase
                || flow.attempts >= 5
            {
                return Err(denied());
            }
            let secrets: Secrets =
                serde_json::from_str(&unseal(state, tenant, body.state, flow.sealed.as_ref().ok_or_else(denied)?)?)?;
            if secrets.binding_hash != oidc::challenge(&body.binding) {
                return Err(denied());
            }
            flow.phase = next.into();
            if phase == "ready" {
                flow.attempts += 1;
            }
            Ok(())
        })
        .await?;
    let secrets = serde_json::from_str(&unseal(state, tenant, body.state, flow.sealed.as_ref().ok_or_else(denied)?)?)?;
    Ok((flow, secrets))
}

pub(super) async fn exchange(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Callback>,
) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    let code = body.code.as_deref().filter(|s| !s.is_empty() && s.len() <= 8192).ok_or_else(denied)?;
    let (mut flow, mut secrets) = claim(&state, tenant, &provider, &body, "pending", "exchanging").await?;
    let client_secret = provider.secret.as_ref().map(|s| unseal(&state, tenant, Id::nil(), s)).transpose()?;
    let identity = oidc::exchange(&oidc::Exchange {
        metadata: provider.metadata.as_ref().ok_or_else(denied)?,
        client_id: &provider.client_id,
        client_secret: client_secret.as_deref(),
        client_auth: provider.client_auth,
        redirect_uri: &provider.redirect_uri,
        code,
        verifier: &secrets.verifier,
        nonce: &secrets.nonce,
        started_at: flow.started_at,
    })
    .await?;
    // Configuration may have been disabled or replaced while the provider was responding.
    if self::provider(&state, tenant).await?.revision != provider.revision {
        return Err(denied().into());
    }
    let user = super::identity::resolve(&state, tenant, &provider, &identity).await?;
    secrets.verifier.clear();
    secrets.nonce.clear();
    flow.sealed = Some(crate::model_gateway::encrypt(&state, tenant, body.state, serde_json::to_string(&secrets)?)?);
    flow.phase = "ready".into();
    flow.user_id = Some(user.id);
    state.configurations.put(tenant, FLOW_KIND, body.state, &flow).await?;
    Ok(Json(json!({"mfa_required":user.mfa_enabled})))
}

pub(super) async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Callback>,
) -> ApiResult<Json<crate::routes::auth::LoginResponse>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    let (flow, _) = claim(&state, tenant, &provider, &body, "ready", "signing").await?;
    let auth = crate::auth_policy::service(&state, tenant).await?;
    let request = LoginRequest {
        username: String::new(),
        password: String::new(),
        mfa_code: body.mfa_code,
        source_ip: None,
        user_agent: headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned),
        device: Some("oidc".into()),
    };
    let outcome = auth.login_federated(&*state.auth_backend, tenant, flow.user_id.ok_or_else(denied)?, &request).await;
    let LoginOutcome::Success { tokens, user, permissions } = (match outcome {
        Ok(value) => value,
        Err(error) => {
            state
                .configurations
                .mutate(tenant, FLOW_KIND, body.state, |flow: &mut Flow| {
                    if flow.phase == "signing" {
                        flow.phase = "ready".into();
                    }
                    Ok(())
                })
                .await?;
            return Err(error.into());
        }
    }) else {
        return Err(denied().into());
    };
    state.configurations.delete(tenant, FLOW_KIND, body.state).await?;
    super::recent::record(&state, tenant, user.id, &tokens.session_id).await?;
    state
        .audit(
            tenant,
            agf_core::audit::AuditAction::Login,
            agf_core::audit::AuditOutcome::Success,
            agf_core::audit::AuditActor {
                id: Some(user.id),
                kind: "user".into(),
                name: user.username.clone(),
                source_ip: None,
                user_agent: request.user_agent,
                session_id: Some(tokens.session_id.clone()),
            },
            agf_core::audit::AuditTarget::new("session", Some(tokens.session_id.clone()), Some(user.username.clone())),
            "企业 OIDC 登录成功",
        )
        .await?;
    Ok(Json(crate::routes::auth::LoginResponse {
        password_policy: crate::auth_policy::TenantPolicy::load(&state, tenant).await?.view,
        roles: state.auth_backend.roles_of(tenant, user.id).await?,
        mfa_enrollment_required: state.auth_backend.mfa_required(tenant).await? && !user.mfa_enabled,
        must_change_password: false,
        tokens: Some(tokens),
        change_token: None,
        user,
        permissions,
        message: "企业登录成功".into(),
    }))
}

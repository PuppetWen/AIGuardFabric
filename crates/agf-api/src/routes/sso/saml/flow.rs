use super::*;
use agf_core::secret::generate_token;
use axum::http::HeaderMap;
use std::time::SystemTime;

#[derive(Default, Serialize, Deserialize)]
struct Flow {
    revision: Option<Id>,
    expires_at: i64,
    phase: String,
    request_id: String,
    binding_hash: String,
    user_id: Option<Id>,
    attempts: u8,
}

#[derive(Default, Serialize, Deserialize)]
struct ReplayRecord {
    expires_at: i64,
}

#[derive(Deserialize)]
pub(super) struct Start {
    tenant_slug: String,
}

#[derive(Deserialize)]
pub(super) struct Complete {
    tenant_slug: String,
    state: Id,
    binding: String,
    mfa_code: Option<String>,
}

fn denied() -> DomainError {
    DomainError::Unauthenticated("SAML 登录事务无效或已使用，请重新登录".into())
}

pub(super) async fn start(State(state): State<AppState>, ApiJson(body): ApiJson<Start>) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    let idp = idp(&provider)?;
    state.configurations.purge_expired(tenant, FLOW_KIND, Timestamp::now().unix_secs()).await?;
    let id = Id::new();
    let binding = generate_token();
    let relay = RelayStateParam::try_from_option(Some(id.to_string())).map_err(saml_error)?;
    let started =
        sp(&state, tenant, &provider)?.start_sso(&idp, StartSso::redirect().relay_state(relay)).map_err(saml_error)?;
    let authorization_url = started.outbound.redirect_url().map_err(saml_error)?.to_owned();
    let flow = Flow {
        revision: Some(provider.revision),
        expires_at: Timestamp::now().unix_secs() + 600,
        phase: "pending".into(),
        request_id: started.pending.request_id().as_str().into(),
        binding_hash: agf_auth::oidc::challenge(&binding),
        ..Flow::default()
    };
    state.configurations.put(tenant, FLOW_KIND, id, &flow).await?;
    Ok(Json(json!({"authorization_url":authorization_url, "state":id, "binding":binding,
        "redirect_uri":provider.acs_url})))
}

async fn reserve_replay(state: &AppState, tenant: TenantId, issuer: &str, kind: &str, value: &str) -> DomainResult<()> {
    let now = Timestamp::now().unix_secs();
    let id = agf_core::ids::deterministic_id(REPLAY_KIND, &format!("{tenant}:{issuer}:{kind}:{value}"));
    state
        .configurations
        .mutate::<Option<ReplayRecord>, _>(tenant, REPLAY_KIND, id, |current| {
            if current.as_ref().is_some_and(|record| record.expires_at > now) {
                return Err(denied());
            }
            *current = Some(ReplayRecord { expires_at: now + 1_200 });
            Ok(())
        })
        .await?;
    Ok(())
}

fn relay_state(fields: &[saml_rs::FormField]) -> DomainResult<Id> {
    let mut values = fields.iter().filter(|f| f.name() == "RelayState").map(saml_rs::FormField::value);
    let value = values.next().ok_or_else(denied)?;
    if values.next().is_some() {
        return Err(denied());
    }
    Id::parse(value).map_err(|_| denied())
}

fn callback_url(provider: &Provider, slug: &str, id: Id) -> DomainResult<String> {
    let mut url = agf_auth::oidc::endpoint(&provider.acs_url)?;
    url.set_path("/login/saml/callback");
    url.query_pairs_mut().append_pair("state", &id.to_string()).append_pair("tenant", slug);
    Ok(url.into())
}

pub(super) async fn acs(
    Path(tenant_slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Redirect> {
    if body.len() > 524_288
        || !headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| {
            v.split(';').next().is_some_and(|mime| mime.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        })
    {
        return Err(DomainError::Validation("SAML 响应格式无效或过大".into()).into());
    }
    let fields: Vec<saml_rs::FormField> = url::form_urlencoded::parse(&body)
        .map(|(name, value)| saml_rs::FormField::new(name.into_owned(), value.into_owned()))
        .collect();
    let id = relay_state(&fields)?;
    let tenant = crate::tenant_directory::resolve(&state, &tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    let flow: Flow = state
        .configurations
        .mutate(tenant, FLOW_KIND, id, |flow: &mut Flow| {
            if flow.revision != Some(provider.revision)
                || flow.expires_at <= Timestamp::now().unix_secs()
                || flow.phase != "pending"
            {
                return Err(denied());
            }
            flow.phase = "verifying".into();
            Ok(())
        })
        .await?;
    let snapshot = PendingSnapshot::<saml_rs::AuthnRequest>::authn_request(
        &flow.request_id,
        RelayStateParam::try_from_option(Some(id.to_string())).map_err(saml_error)?,
        &provider.idp_entity_id,
        "post",
        &provider.acs_url,
        "post",
    );
    let pending = Pending::<saml_rs::AuthnRequest>::from_snapshot(snapshot).map_err(saml_error)?;
    let validation = SamlValidationContext::new(SystemTime::now(), saml_rs::ReplayPolicy::DisabledForCompatibility);
    let session = sp(&state, tenant, &provider)?
        .finish_sso(&idp(&provider)?, &pending, BrowserInput::<SsoResponse>::post(fields), validation)
        .map_err(saml_error)?;
    // The library validates signatures, issuer, audience, recipient and time first.
    // Shared CAS reservations then reject replay across all API instances.
    state.configurations.purge_expired(tenant, REPLAY_KIND, Timestamp::now().unix_secs()).await?;
    reserve_replay(&state, tenant, &provider.idp_entity_id, "response", session.response_id().as_str()).await?;
    reserve_replay(&state, tenant, &provider.idp_entity_id, "assertion", session.assertion_id().as_str()).await?;
    if super::provider(&state, tenant).await?.revision != provider.revision {
        return Err(denied().into());
    }
    let user = resolve_user(&state, tenant, &provider, &session).await?;
    state
        .configurations
        .mutate(tenant, FLOW_KIND, id, |flow: &mut Flow| {
            if flow.phase != "verifying" || flow.revision != Some(provider.revision) {
                return Err(denied());
            }
            flow.phase = "ready".into();
            flow.user_id = Some(user.id);
            Ok(())
        })
        .await?;
    Ok(Redirect::to(&callback_url(&provider, &tenant_slug, id)?))
}

pub(super) async fn status(State(state): State<AppState>, ApiJson(body): ApiJson<Complete>) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    if !(32..=256).contains(&body.binding.len()) {
        return Err(denied().into());
    }
    let flow: Flow = state.configurations.get(tenant, FLOW_KIND, body.state).await?.ok_or_else(denied)?;
    if flow.revision != Some(provider.revision)
        || flow.expires_at <= Timestamp::now().unix_secs()
        || flow.phase != "ready"
        || flow.binding_hash != agf_auth::oidc::challenge(&body.binding)
    {
        return Err(denied().into());
    }
    let user = state.auth_backend.find_user(tenant, flow.user_id.ok_or_else(denied)?).await?.ok_or_else(denied)?;
    Ok(Json(json!({"mfa_required":user.mfa_enabled})))
}

pub(super) async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Complete>,
) -> ApiResult<Json<crate::routes::auth::LoginResponse>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    if !(32..=256).contains(&body.binding.len()) {
        return Err(denied().into());
    }
    let flow: Flow = state
        .configurations
        .mutate(tenant, FLOW_KIND, body.state, |flow: &mut Flow| {
            if flow.revision != Some(provider.revision)
                || flow.expires_at <= Timestamp::now().unix_secs()
                || flow.phase != "ready"
                || flow.attempts >= 5
                || flow.binding_hash != agf_auth::oidc::challenge(&body.binding)
            {
                return Err(denied());
            }
            flow.phase = "signing".into();
            flow.attempts += 1;
            Ok(())
        })
        .await?;
    let auth = crate::auth_policy::service(&state, tenant).await?;
    let request = LoginRequest {
        username: String::new(),
        password: String::new(),
        mfa_code: body.mfa_code,
        source_ip: None,
        user_agent: headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned),
        device: Some("saml".into()),
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
    super::super::recent::record(&state, tenant, user.id, &tokens.session_id).await?;
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
            "企业 SAML 登录成功",
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
        message: "企业 SAML 登录成功".into(),
    }))
}

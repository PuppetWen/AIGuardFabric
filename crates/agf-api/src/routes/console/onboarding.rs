//! 纳管计划（`/agents/onboarding-plan`）与原始日志回放（`/ingest/replay`）端点。

use super::*;

// ===========================================================================
// 纳管计划 / 日志回放
// ===========================================================================

/// 纳管计划（`GET /api/v1/agents/onboarding-plan`，query 版）。
///
/// # Errors
/// 权限不足（`agents:read`）、参数非法、资产不存在或不是 agent 类型、存储错误。
pub(super) async fn onboarding_plan_get(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    query: ListQuery,
) -> ApiResult<Json<OnboardingPlanView>> {
    let request = OnboardingPlanRequest {
        agent_id: query
            .filter("agent_id")
            .or_else(|| query.filter("agentId"))
            .or_else(|| query.filter("id"))
            .map(ToString::to_string),
        target: query
            .filter("target")
            .map(|value| serde_json::from_value(serde_json::Value::String(value.into())))
            .transpose()
            .map_err(|_| DomainError::Validation("Unsupported onboarding target".into()))?,
        model: query.filter("model").map(ToString::to_string),
        sdk: None,
        kind: query.filter("kind").map(ToString::to_string),
        mode: query.filter("mode").map(ToString::to_string),
        platform: query.filter("platform").map(ToString::to_string),
        locale: query.filter("locale").map(ToString::to_string),
        public_base: query.filter("public_base").or_else(|| query.filter("publicBase")).map(ToString::to_string),
    };
    onboarding_plan(&state, &principal, &headers, &request).await
}

/// 纳管计划（`POST /api/v1/agents/onboarding-plan`，控制台实际用法：body `{agentId, mode}`）。
///
/// # Errors
/// 同 [`onboarding_plan_get`]。
pub(super) async fn onboarding_plan_post(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    crate::routes::ApiJson(body): crate::routes::ApiJson<OnboardingPlanRequest>,
) -> ApiResult<Json<OnboardingPlanView>> {
    onboarding_plan(&state, &principal, &headers, &body).await
}

/// 纳管计划主体（GET/POST 共用）。
///
/// # Errors
/// 权限不足、参数非法、资产不存在或类型不符、存储错误。
async fn onboarding_plan(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    request: &OnboardingPlanRequest,
) -> ApiResult<Json<OnboardingPlanView>> {
    principal.require(state, "agents", "read")?;
    let mode = parse_onboarding_mode(request.mode.as_deref())?;
    let target = super::onboarding_targets::select(mode, request.target)?;
    let sdk = matches!(target, OnboardingTarget::PythonStartup | OnboardingTarget::NodeCjsStartup);
    let model = matches!(target, OnboardingTarget::ModelOpenai | OnboardingTarget::ModelAnthropic);
    if (!sdk && request.sdk.is_some()) || (!model && request.model.is_some()) {
        return Err(DomainError::Validation("Fields do not belong to the selected target".into()).into());
    }
    let authority = super::onboarding_authority::ReadAuthority::capture(state, principal, headers, sdk, model)?;
    authority.check(state).await?;
    let tenant = principal.tenant;

    // 资产 id 优先（校验 UUID → 台账存在性 → 类型必须是 agent）。
    let (agent_id, _agent_name) = match request.agent_id.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(raw) => {
            let id = crate::routes::parse_id(raw, "agent")?;
            let Some(asset) = state.store.asset_get_durable(tenant, id).await? else {
                return Err(ApiError::new(DomainError::NotFound { entity: "agent", id: raw.to_string() }));
            };
            if asset.kind != AssetKind::Agent {
                return Err(ApiError::new(DomainError::Validation(format!(
                    "资产 {} 的类型是 {}，不是 agent，无法生成纳管计划",
                    asset.id,
                    asset.kind.as_str()
                ))));
            }
            (asset.id.to_string(), Some(asset.name))
        }
        None => (String::new(), None),
    };
    // kind 参数（未给 id 时用于生成通用计划）：必须是合法资产类型。
    let kind = match request.kind.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(raw) => Some(AssetKind::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?),
        None => None,
    };

    if kind.is_some_and(|kind| kind != AssetKind::Agent) {
        return Err(DomainError::Validation("Onboarding kind must be agent".into()).into());
    }
    let platform = request.platform.as_deref().unwrap_or("windows-amd64");
    if !matches!(platform, "windows-amd64" | "linux-amd64" | "macos-arm64") {
        return Err(DomainError::Validation("Unsupported collector platform".into()).into());
    }
    let zh = match request.locale.as_deref().unwrap_or("zh-CN") {
        "zh" | "zh-CN" => true,
        "en" | "en-US" => false,
        _ => return Err(DomainError::Validation("Unsupported onboarding locale".into()).into()),
    };
    let base = match request.public_base.as_deref() {
        Some(value) => {
            let url = url::Url::parse(value).map_err(|_| DomainError::Validation("Invalid public origin".into()))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(DomainError::Validation(
                    "Public origin must be HTTP(S), without path or credentials".into(),
                )
                .into());
            }
            url.origin().ascii_serialization()
        }
        None => public_base(state, headers),
    };
    let artifact_sha256 =
        if mode == "sidecar" { crate::routes::downloads::published_digest(state, platform).await } else { None };
    let artifact_url = artifact_sha256.as_ref().map(|_| format!("/downloads/agents/{platform}"));
    let tenant_id = tenant.to_string();
    let commands = super::onboarding_commands::PlanCommands {
        base: &base,
        tenant: &tenant_id,
        mode,
        platform,
        zh,
        artifact: artifact_url.as_deref(),
        sha256: artifact_sha256.as_deref(),
    };
    let windows = platform == "windows-amd64";
    let mut sdk_sources = Vec::new();
    let template = match target {
        OnboardingTarget::Collector => super::onboarding_templates::Template {
            endpoint: format!("{base}/api/v1/ingest/agent"),
            ready: true,
            env: commands.env(),
            steps: commands.steps(),
            configuration: None,
            key_env: Some("AGF_AGENT_TOKEN".into()),
        },
        OnboardingTarget::McpStdio => super::onboarding_templates::stdio(&base, windows, zh)?,
        OnboardingTarget::McpHttp => super::onboarding_templates::mcp_http(&base, zh),
        OnboardingTarget::PythonStartup | OnboardingTarget::NodeCjsStartup => {
            sdk_sources = super::onboarding_startup::choices(state, tenant).await?;
            if let Some(input) = &request.sdk {
                let (configuration, selected) =
                    super::onboarding_startup::configuration(state, tenant, target, input, &base).await?;
                let encoded = serde_json::to_string_pretty(&configuration)
                    .map_err(|_| DomainError::Config("Startup configuration encoding failed".into()))?;
                super::onboarding_templates::startup(target, input, &selected, &base, encoded, windows, zh)
            } else {
                super::onboarding_templates::incomplete(target, &base, zh)
            }
        }
        OnboardingTarget::ModelOpenai | OnboardingTarget::ModelAnthropic => {
            if let Some(model) = &request.model {
                super::onboarding_targets::plain(model, 256)?;
                if model == "auto" {
                    return Err(DomainError::Validation("Choose an exact enabled model ID".into()).into());
                }
                let rows = match state
                    .configurations
                    .list_bounded::<crate::model_gateway::StoredEndpoint>(
                        tenant,
                        crate::model_gateway::ENDPOINT_KIND,
                        512,
                        2 * 1024 * 1024,
                    )
                    .await?
                {
                    agf_storage::configuration::BoundedConfigurationList::Complete(rows) => rows,
                    _ => {
                        return Err(DomainError::PreconditionFailed(
                            "Model inventory exceeds the plan selection budget".into(),
                        )
                        .into());
                    }
                };
                if !rows
                    .iter()
                    .any(|row| row.endpoint.tenant_id == tenant && row.endpoint.enabled && row.endpoint.model == *model)
                {
                    return Err(
                        DomainError::Validation("Choose an exact enabled model in the current tenant".into()).into()
                    );
                }
                super::onboarding_templates::model(target, model, &base, windows, zh)
            } else {
                super::onboarding_templates::incomplete(target, &base, zh)
            }
        }
    };
    authority.check(state).await?;
    Ok(Json(OnboardingPlanView {
        agent_id,
        mode: mode.into(),
        target: target.as_str().into(),
        ready: template.ready,
        available_targets: super::onboarding_targets::available(mode),
        links: super::onboarding_targets::links(target, zh),
        sdk_sources,
        configuration_json: template.configuration,
        key_env: template.key_env,
        endpoint: template.endpoint,
        env_snippet: template.env,
        steps: template.steps,
        artifact_url,
        artifact_sha256,
        platform: platform.into(),
        estimated_downtime_sec: None,
        rollout: "manual".into(),
    }))
}

/// 平台对外基址：优先请求 `Host` 头，其次配置里的 `AGF_SERVER_HOST`/`AGF_SERVER_PORT`
/// （`0.0.0.0` 对客户端不可用，故换成 `127.0.0.1`）。
fn public_base(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(host) = headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()) {
        let host = host.trim();
        if !host.is_empty() {
            let scheme = headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .filter(|v| *v == "https")
                .unwrap_or("http");
            if host.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c)) {
                return format!("{scheme}://{host}");
            }
        }
    }
    let host = match state.config.server.host.as_str() {
        "0.0.0.0" | "::" | "" => "127.0.0.1",
        other => other,
    };
    format!("http://{host}:{}", state.config.server.port)
}

/// 纳管模式解析（缺省 `sidecar`）。
///
/// # Errors
/// 未知模式。
fn parse_onboarding_mode(raw: Option<&str>) -> ApiResult<&'static str> {
    let normalized = raw.map(|v| v.trim().to_ascii_lowercase().replace('_', "-"));
    match normalized.as_deref() {
        None | Some("") => Ok("sidecar"),
        Some("sidecar") => Ok("sidecar"),
        Some("sdk-inject") => Ok("sdk-inject"),
        Some("gateway-register") => Ok("gateway-register"),
        Some(other) => Err(ApiError::new(DomainError::Validation(format!(
            "未知纳管模式 {other}（可选：sidecar / sdk-inject / gateway-register）"
        )))),
    }
}

/// 未解析原始日志只读预览（`GET /api/v1/ingest/replay`，query 版）。
///
/// **委托**给 [`crate::routes::ingest::replay_get`]；只读原文，不运行 `Replayer`。
///
/// # Errors
/// 权限不足（`sources:write`）、`source_id` 缺失（400）、`limit` 非正（400）、仓储读取失败。
pub(super) async fn ingest_replay_get(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    crate::routes::ingest::replay_get(State(state), principal, query).await
}

/// 显式执行原始日志回放（`POST /api/v1/ingest/replay`，body 版）。
///
/// # Errors
/// 同 [`ingest_replay_get`]。
pub(super) async fn ingest_replay_post(
    State(state): State<AppState>,
    principal: Principal,
    crate::routes::ApiJson(body): crate::routes::ApiJson<crate::routes::ingest::ReplayRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::routes::ingest::replay_post(State(state), principal, crate::routes::ApiJson(body)).await
}

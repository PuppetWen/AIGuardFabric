use super::*;
use agf_core::model::{Modality, ModelEndpoint, ModelPricing};

#[derive(Deserialize)]
pub(super) struct EndpointBody {
    expected_version: Option<u64>,
    name: String,
    provider: String,
    model: String,
    base_url: String,
    api_key: Option<String>,
    api_version: Option<String>,
    #[serde(default)]
    local_deployment: bool,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    supports_streaming: Option<bool>,
    #[serde(default)]
    supports_tools: Option<bool>,
    #[serde(default)]
    max_data_class: Option<DataClass>,
    #[serde(default)]
    priority: Option<u32>,
    #[serde(default)]
    pricing: Option<ModelPricing>,
}
fn yes() -> bool {
    true
}

pub(super) fn public(record: &StoredEndpoint, mock_mode: bool) -> Value {
    let mut value = serde_json::to_value(&record.endpoint).unwrap_or(Value::Null);
    value["credential_configured"] = json!(record.secret.is_some());
    value["version"] = json!(record.version);
    value["mocked"] = json!(
        mock_mode
            || record.endpoint.provider == LlmProvider::Mock
            || crate::model_gateway::missing_upstream_key(record)
    );
    value["api_version"] = json!(record.endpoint.extra_headers.get("api-version"));
    value
}

pub(super) async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "models", "read")?;
    let items: Vec<StoredEndpoint> = state.configurations.list(principal.tenant, ENDPOINT_KIND).await?;
    Ok(Json(json!({"items": items.iter().map(|r| public(r, state.config.mock_mode)).collect::<Vec<_>>()})))
}

pub(super) async fn catalog(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "models", "read")?;
    let items: Vec<Value> = LlmProvider::all()
        .into_iter()
        .map(|provider| {
            json!({
                "value":provider.as_str(),
                "suggestedBaseUrl":agf_aigw::provider::default_base_url(provider),
                "requiresCustomBaseUrl":matches!(provider,
                    LlmProvider::AzureOpenAi | LlmProvider::Bedrock | LlmProvider::Ollama |
                    LlmProvider::Vllm | LlmProvider::CustomOpenAiCompat),
                "localDeployment":provider == LlmProvider::Mock,
            })
        })
        .collect();
    Ok(Json(json!({"items":items})))
}

pub(super) async fn create(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<EndpointBody>,
) -> ApiResult<(axum::http::StatusCode, Json<Value>)> {
    let value = save(&state, &principal, Id::new(), body, None).await?;
    Ok((axum::http::StatusCode::CREATED, Json(value)))
}

pub(super) async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
    ApiJson(body): ApiJson<EndpointBody>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "models", "write")?;
    let id = parse_id(&raw, "model-endpoint")?;
    let existing: StoredEndpoint = state
        .configurations
        .get(principal.tenant, ENDPOINT_KIND, id)
        .await?
        .ok_or(DomainError::NotFound { entity: "model-endpoint", id: raw })?;
    Ok(Json(save(&state, &principal, id, body, Some(existing)).await?))
}

async fn save(
    state: &AppState,
    principal: &Principal,
    id: Id,
    body: EndpointBody,
    old: Option<StoredEndpoint>,
) -> ApiResult<Value> {
    principal.require(state, "models", "write")?;
    let expected_version = match (old.as_ref(), body.expected_version) {
        (Some(_), None) => {
            return Err(DomainError::Validation("编辑模型端点须提供 expected_version，请重新加载".into()).into());
        }
        (None, Some(version)) if version != 0 => {
            return Err(DomainError::Validation("新模型端点的 expected_version 必须为 0".into()).into());
        }
        (_, Some(version)) => version,
        (None, None) => 0,
    };
    if old.as_ref().map_or(0, |record| record.version) != expected_version {
        return Err(DomainError::Conflict("模型端点已被其他人修改，请重新加载后合并变更".into()).into());
    }
    let next_version = expected_version.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?;
    if body.name.trim().is_empty() || body.model.trim().is_empty() || body.name.len() > 128 || body.model.len() > 256 {
        return Err(DomainError::Validation("请填写端点名称和厂商模型 ID".into()).into());
    }
    let provider = LlmProvider::all()
        .into_iter()
        .find(|p| p.as_str() == body.provider)
        .ok_or_else(|| DomainError::Validation("未知模型厂商".into()))?;
    let url =
        url::Url::parse(&body.base_url).map_err(|_| DomainError::Validation("请输入完整的模型 Base URL".into()))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.query().is_some()
            && (provider != LlmProvider::AzureOpenAi
                || url.query_pairs().any(|(key, value)| key != "api-version" || value.is_empty())))
        || url.fragment().is_some()
    {
        return Err(DomainError::Validation("Base URL 只允许 HTTP(S)，凭据请单独填写".into()).into());
    }
    let reference = old.as_ref().and_then(|r| r.endpoint.credential_ref).unwrap_or_default();
    let secret = match body.api_key.filter(|k| !k.is_empty()) {
        Some(key) => {
            if key.trim().is_empty() {
                return Err(DomainError::Validation("API Key 不能仅包含空白".into()).into());
            }
            if provider == LlmProvider::Bedrock {
                super::credentials::aws(&key)?;
            } else if key.contains(['\r', '\n']) {
                return Err(DomainError::Validation("API Key 不能包含换行".into()).into());
            }
            Some(crate::model_gateway::encrypt(state, principal.tenant, reference, key)?)
        }
        None => {
            if old.as_ref().is_some_and(|row| {
                row.secret.is_some()
                    && (row.endpoint.base_url != body.base_url.trim_end_matches('/')
                        || row.endpoint.provider != provider)
            }) {
                return Err(DomainError::Validation("更换模型厂商或目标地址时，请重新填写 API Key".into()).into());
            }
            old.as_ref().and_then(|r| r.secret.clone())
        }
    };
    let now = Timestamp::now();
    let mut extra_headers = old.as_ref().map(|r| r.endpoint.extra_headers.clone()).unwrap_or_default();
    if let Some(version) = body.api_version {
        if version.len() > 64 || !version.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(DomainError::Validation("API version 仅允许字母、数字和连字符，最长 64 字符".into()).into());
        }
        if version.is_empty() {
            extra_headers.remove("api-version");
        } else {
            extra_headers.insert("api-version".into(), version);
        }
    }
    let record = StoredEndpoint {
        version: next_version,
        endpoint: ModelEndpoint {
            id,
            tenant_id: principal.tenant,
            asset_id: id,
            name: body.name.trim().into(),
            provider,
            base_url: body.base_url.trim_end_matches('/').into(),
            model: body.model.trim().into(),
            modalities: vec![Modality::Text, Modality::Vision],
            context_window: None,
            max_output_tokens: None,
            supports_streaming: body
                .supports_streaming
                .unwrap_or_else(|| old.as_ref().is_none_or(|r| r.endpoint.supports_streaming)),
            supports_tools: body
                .supports_tools
                .unwrap_or_else(|| old.as_ref().is_none_or(|r| r.endpoint.supports_tools)),
            credential_ref: secret.as_ref().map(|_| reference),
            local_deployment: body.local_deployment,
            max_data_class: body.max_data_class.unwrap_or(DataClass::Internal),
            pricing: body
                .pricing
                .unwrap_or_else(|| old.as_ref().map_or_else(ModelPricing::default, |r| r.endpoint.pricing)),
            enabled: body.enabled,
            fallback: false,
            priority: body.priority.unwrap_or_else(|| old.as_ref().map_or(0, |r| r.endpoint.priority)),
            extra_headers,
            created_at: old.as_ref().map_or(now, |r| r.endpoint.created_at),
            updated_at: now,
        },
        secret,
    };
    let audit = AppState::audit_entry(
        principal.tenant,
        agf_core::audit::AuditAction::Configure,
        agf_core::audit::AuditOutcome::Success,
        AppState::audit_actor(principal, "model-endpoint"),
        agf_core::audit::AuditTarget::new("model-endpoint", Some(id.to_string()), Some(record.endpoint.name.clone())),
        "保存模型端点；凭据使用 AES-GCM 加密；下一请求读取新配置",
    );
    crate::store::model_assets::save(state, principal.tenant, &record, expected_version, audit).await?;
    Ok(public(&record, state.config.mock_mode))
}

pub(super) async fn remove(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
    Query(version): Query<DeleteVersion>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "models", "write")?;
    let id = parse_id(&raw, "model-endpoint")?;
    let audit = AppState::audit_entry(
        principal.tenant,
        agf_core::audit::AuditAction::Delete,
        agf_core::audit::AuditOutcome::Success,
        AppState::audit_actor(&principal, "model-endpoint"),
        agf_core::audit::AuditTarget::new("model-endpoint", Some(id.to_string()), None),
        "删除模型端点配置并停用资产投影",
    );
    crate::store::model_assets::remove(&state, principal.tenant, id, version.expected_version, audit).await?;
    Ok(Json(json!({"deleted":true})))
}

#[derive(Deserialize)]
pub(super) struct DeleteVersion {
    expected_version: u64,
}

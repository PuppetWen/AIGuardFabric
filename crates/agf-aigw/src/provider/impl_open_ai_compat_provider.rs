//! 由 `provider.rs` 拆分：`impl_OpenAiCompatProvider`/`openai_complete` 等 7 项（纯搬移，逻辑不变）。
use super::*;

impl OpenAiCompatProvider {
    /// 构造。
    #[must_use]
    pub fn new(
        provider: LlmProvider,
        model: impl Into<String>,
        base_url: impl Into<String>,
        credential: Option<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            provider,
            model: model.into(),
            base_url: if base.trim().is_empty() { default_base_url(provider).to_string() } else { base },
            credential,
            extra_headers: BTreeMap::new(),
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 从模型端点 + 凭据解析器构造（**凭据缺失不报错**）。
    #[must_use]
    pub fn from_endpoint(endpoint: &ModelEndpoint, resolver: &dyn CredentialResolver) -> Self {
        let credential =
            endpoint.credential_ref.as_ref().and_then(|r| resolver.resolve_api_key(r)).filter(|k| !k.trim().is_empty());
        Self {
            provider: endpoint.provider,
            model: endpoint.model.clone(),
            base_url: if endpoint.base_url.trim().is_empty() {
                default_base_url(endpoint.provider).to_string()
            } else {
                endpoint.base_url.clone()
            },
            credential,
            extra_headers: endpoint.extra_headers.clone(),
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 明文凭据（`None` = 未配置）。
    #[must_use]
    pub fn api_key(&self) -> Option<&str> {
        self.credential.as_deref().filter(|k| !k.trim().is_empty())
    }

    /// 是否缺凭据（宏生成的 `report_health()` 使用）。
    #[must_use]
    pub fn api_key_missing(&self) -> bool {
        self.api_key().is_none()
    }

    /// 请求地址。
    #[must_use]
    pub fn chat_url(&self) -> String {
        let Ok(mut url) = reqwest::Url::parse(&self.base_url) else {
            return join_url(&self.base_url, "chat/completions");
        };
        let path = url.path().trim_end_matches('/');
        let path = if self.uses_azure_auth() && path.is_empty() {
            "/openai/v1/chat/completions".to_string()
        } else if path.ends_with("/chat/completions") {
            path.to_string()
        } else {
            format!("{path}/chat/completions")
        };
        url.set_path(&path);
        if self.uses_azure_auth()
            && path.contains("/deployments/")
            && !url.query_pairs().any(|(key, _)| key == "api-version")
        {
            url.query_pairs_mut()
                .append_pair("api-version", self.extra_headers.get("api-version").map_or("2024-10-21", String::as_str));
        }
        url.to_string()
    }

    /// 是否使用 Azure 风格鉴权头（`api-key` 而非 `Authorization`）。
    #[must_use]
    pub const fn uses_azure_auth(&self) -> bool {
        matches!(self.provider, LlmProvider::AzureOpenAi)
    }

    pub(crate) fn attach_headers(&self, mut builder: reqwest::RequestBuilder, key: &str) -> reqwest::RequestBuilder {
        if self.uses_azure_auth() {
            builder = builder.header("api-key", key);
        } else {
            builder = builder.bearer_auth(key);
        }
        for (k, v) in &self.extra_headers {
            if self.uses_azure_auth() && k.eq_ignore_ascii_case("api-version") {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder
    }

    /// 未配置凭据时的可降级错误（**绝不联网**）。
    #[allow(clippy::unused_self)]
    pub(crate) fn unconfigured(&self) -> DomainError {
        unconfigured_error(self.provider.as_str())
    }
}

/// 生成 OpenAI 兼容适配器的 `complete` / `stream`。
pub(crate) async fn openai_complete(p: &OpenAiCompatProvider, req: &ChatRequest) -> DomainResult<ChatResponse> {
    let Some(key) = p.api_key() else {
        return Err(p.unconfigured());
    };
    let body = to_openai_body(req, false);
    let builder = p.client.post(p.chat_url()).json(&body);
    let builder = p.attach_headers(builder, key);
    let resp = execute_once(p.adapter_name(), &p.state, builder.send()).await?;
    let raw = read_json(p.adapter_name(), resp, &p.state).await?;
    from_openai_response(&raw)
}

/// 生成 OpenAI 兼容适配器的流式建立逻辑。
pub(crate) async fn openai_stream(p: &OpenAiCompatProvider, req: &ChatRequest) -> DomainResult<ProviderStream> {
    let Some(key) = p.api_key() else {
        return Err(p.unconfigured());
    };
    let body = to_openai_body(req, true);
    let builder = p.client.post(p.chat_url()).header("accept", "text/event-stream").json(&body);
    let builder = p.attach_headers(builder, key);
    let resp = execute_once(p.adapter_name(), &p.state, builder.send()).await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        p.state.failure(&format!("HTTP {status}"));
        return Err(http_status_error(OPENAI_ADAPTER, status, &text));
    }
    Ok(sse_stream("llm-openai-compat", resp, p.state.clone(), from_openai_chunk))
}

/// 厂商默认 `base_url`（端点未显式配置时使用）。
#[must_use]
pub fn default_base_url(provider: LlmProvider) -> &'static str {
    match provider {
        LlmProvider::OpenAi => "https://api.openai.com/v1",
        LlmProvider::AzureOpenAi => "https://YOUR-RESOURCE.openai.azure.com/openai/v1",
        LlmProvider::DashScope => "https://dashscope.aliyuncs.com/compatible-mode/v1",
        LlmProvider::Ark => "https://ark.cn-beijing.volces.com/api/v3",
        LlmProvider::Hunyuan => "https://api.hunyuan.cloud.tencent.com/v1",
        LlmProvider::Qianfan => "https://qianfan.baidubce.com/v2",
        LlmProvider::Moonshot => "https://api.moonshot.cn/v1",
        LlmProvider::DeepSeek => "https://api.deepseek.com/v1",
        LlmProvider::Zhipu => "https://open.bigmodel.cn/api/paas/v4",
        LlmProvider::MiniMax => "https://api.minimax.chat/v1",
        LlmProvider::Ollama => "http://127.0.0.1:11434/v1",
        LlmProvider::Vllm => "http://127.0.0.1:8000/v1",
        LlmProvider::Anthropic => "https://api.anthropic.com/v1",
        LlmProvider::Gemini => "https://generativelanguage.googleapis.com/v1beta",
        LlmProvider::Bedrock => "https://bedrock-runtime.us-east-1.amazonaws.com",
        LlmProvider::Mock | LlmProvider::CustomOpenAiCompat => "http://127.0.0.1:8080/v1",
    }
}

impl AnthropicProvider {
    /// 构造。
    #[must_use]
    pub fn new(model: impl Into<String>, base_url: impl Into<String>, credential: Option<String>) -> Self {
        let base = base_url.into();
        Self {
            model: model.into(),
            base_url: if base.trim().is_empty() { default_base_url(LlmProvider::Anthropic).to_string() } else { base },
            credential,
            api_version: "2023-06-01".to_string(),
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 从模型端点构造。
    #[must_use]
    pub fn from_endpoint(endpoint: &ModelEndpoint, resolver: &dyn CredentialResolver) -> Self {
        let credential =
            endpoint.credential_ref.as_ref().and_then(|r| resolver.resolve_api_key(r)).filter(|k| !k.trim().is_empty());
        let base_url = if endpoint.base_url.trim().is_empty() {
            default_base_url(LlmProvider::Anthropic).to_string()
        } else {
            endpoint.base_url.clone()
        };
        let api_version =
            endpoint.extra_headers.get("anthropic-version").cloned().unwrap_or_else(|| "2023-06-01".to_string());
        Self {
            model: endpoint.model.clone(),
            base_url,
            credential,
            api_version,
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 明文凭据。
    #[must_use]
    pub fn api_key(&self) -> Option<&str> {
        self.credential.as_deref().filter(|k| !k.trim().is_empty())
    }

    /// 是否缺凭据。
    #[must_use]
    pub fn api_key_missing(&self) -> bool {
        self.api_key().is_none()
    }

    /// 请求地址。
    #[must_use]
    pub fn messages_url(&self) -> String {
        join_url(&self.base_url, "messages")
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn unconfigured(&self) -> DomainError {
        unconfigured_error("anthropic")
    }
}

pub(crate) async fn anthropic_complete(p: &AnthropicProvider, req: &ChatRequest) -> DomainResult<ChatResponse> {
    req.ensure_anthropic_native_unchanged()?;
    let Some(key) = p.api_key() else {
        return Err(p.unconfigured());
    };
    let body = to_anthropic_body(req, false);
    let resp = execute_once(
        p.adapter_name(),
        &p.state,
        p.client
            .post(p.messages_url())
            .header("x-api-key", key)
            .header("anthropic-version", &p.api_version)
            .json(&body)
            .send(),
    )
    .await?;
    let raw = read_json(p.adapter_name(), resp, &p.state).await?;
    from_anthropic_response(&raw)
}

pub(crate) async fn anthropic_stream(p: &AnthropicProvider, req: &ChatRequest) -> DomainResult<ProviderStream> {
    req.ensure_anthropic_native_unchanged()?;
    let Some(key) = p.api_key() else {
        return Err(p.unconfigured());
    };
    let body = to_anthropic_body(req, true);
    let resp = execute_once(
        p.adapter_name(),
        &p.state,
        p.client
            .post(p.messages_url())
            .header("x-api-key", key)
            .header("anthropic-version", &p.api_version)
            .header("accept", "text/event-stream")
            .json(&body)
            .send(),
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        p.state.failure(&format!("HTTP {status}"));
        return Err(http_status_error(ANTHROPIC_ADAPTER, status, &text));
    }
    Ok(sse_stream("llm-anthropic", resp, p.state.clone(), from_anthropic_event))
}

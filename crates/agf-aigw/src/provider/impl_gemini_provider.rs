//! 由 `provider.rs` 拆分：`impl_GeminiProvider`/`gemini_complete` 等 10 项（纯搬移，逻辑不变）。
use super::*;

impl GeminiProvider {
    /// 构造。
    #[must_use]
    pub fn new(model: impl Into<String>, base_url: impl Into<String>, credential: Option<String>) -> Self {
        let base = base_url.into();
        Self {
            model: model.into(),
            base_url: if base.trim().is_empty() { default_base_url(LlmProvider::Gemini).to_string() } else { base },
            credential,
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 从模型端点构造。
    #[must_use]
    pub fn from_endpoint(endpoint: &ModelEndpoint, resolver: &dyn CredentialResolver) -> Self {
        let credential =
            endpoint.credential_ref.as_ref().and_then(|r| resolver.resolve_api_key(r)).filter(|k| !k.trim().is_empty());
        Self {
            model: endpoint.model.clone(),
            base_url: if endpoint.base_url.trim().is_empty() {
                default_base_url(LlmProvider::Gemini).to_string()
            } else {
                endpoint.base_url.clone()
            },
            credential,
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

    /// 非流式请求地址。
    #[must_use]
    pub fn generate_url(&self) -> String {
        join_url(&self.base_url, &format!("models/{}:generateContent", self.model))
    }

    /// 流式请求地址（`alt=sse` 让 Gemini 用 SSE 而非 JSON 数组分块）。
    #[must_use]
    pub fn stream_url(&self) -> String {
        join_url(&self.base_url, &format!("models/{}:streamGenerateContent?alt=sse", self.model))
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn unconfigured(&self) -> DomainError {
        unconfigured_error("gemini")
    }
}

pub(crate) async fn gemini_complete(p: &GeminiProvider, req: &ChatRequest) -> DomainResult<ChatResponse> {
    let Some(key) = p.api_key() else {
        return Err(p.unconfigured());
    };
    validate_gemini_stops(req)?;
    let body = to_gemini_body(req);
    let resp = execute_once(
        p.adapter_name(),
        &p.state,
        p.client.post(p.generate_url()).header("x-goog-api-key", key).json(&body).send(),
    )
    .await?;
    let raw = read_json(p.adapter_name(), resp, &p.state).await?;
    from_gemini_response(&raw)
}

pub(crate) async fn gemini_stream(p: &GeminiProvider, req: &ChatRequest) -> DomainResult<ProviderStream> {
    let Some(key) = p.api_key() else {
        return Err(p.unconfigured());
    };
    validate_gemini_stops(req)?;
    let body = to_gemini_body(req);
    let resp = execute_once(
        p.adapter_name(),
        &p.state,
        p.client
            .post(p.stream_url())
            .header("x-goog-api-key", key)
            .header("accept", "text/event-stream")
            .json(&body)
            .send(),
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        p.state.failure(&format!("HTTP {status}"));
        return Err(http_status_error(GEMINI_ADAPTER, status, &text));
    }
    Ok(sse_stream("llm-gemini", resp, p.state.clone(), from_gemini_chunk))
}

fn validate_gemini_stops(req: &ChatRequest) -> DomainResult<()> {
    if req.stop.len() > 5 {
        return Err(DomainError::Validation("Gemini 最多支持 5 个停止序列".into()));
    }
    Ok(())
}

impl BedrockProvider {
    /// 构造。
    #[must_use]
    pub fn new(model: impl Into<String>, region: impl Into<String>, credentials: Option<AwsCredentials>) -> Self {
        let region = region.into();
        let base = format!("https://bedrock-runtime.{region}.amazonaws.com");
        Self {
            model: model.into(),
            region,
            base_url: base,
            credentials,
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 从模型端点构造：区域取 `extra_headers["aws_region"]`，凭据走解析器、再兜底环境变量。
    #[must_use]
    pub fn from_endpoint(endpoint: &ModelEndpoint, resolver: &dyn CredentialResolver) -> Self {
        let region = endpoint.extra_headers.get("aws_region").cloned().unwrap_or_else(|| "us-east-1".to_string());
        let credentials = endpoint
            .credential_ref
            .as_ref()
            .and_then(|r| resolver.resolve_aws_credentials(r))
            .or_else(env_aws_credentials);
        let base_url = if endpoint.base_url.trim().is_empty() {
            format!("https://bedrock-runtime.{region}.amazonaws.com")
        } else {
            endpoint.base_url.clone()
        };
        Self {
            model: endpoint.model.clone(),
            region,
            base_url,
            credentials,
            state: ProviderState::default(),
            client: build_http_client(),
        }
    }

    /// 是否已配置凭据。
    #[must_use]
    pub const fn configured(&self) -> bool {
        self.credentials.is_some()
    }

    /// 是否缺凭据。
    #[must_use]
    pub const fn api_key_missing(&self) -> bool {
        self.credentials.is_none()
    }

    /// `converse` 请求地址。
    #[must_use]
    pub fn converse_url(&self) -> String {
        join_url(&self.base_url, &format!("model/{}/converse", self.model))
    }

    /// `converse-stream` 请求地址。
    #[must_use]
    pub fn converse_stream_url(&self) -> String {
        join_url(&self.base_url, &format!("model/{}/converse-stream", self.model))
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn unconfigured(&self) -> DomainError {
        unconfigured_error("bedrock")
    }

    /// 构造已签名的请求。
    pub(crate) fn signed_request(&self, url: &str, body: &Value) -> DomainResult<reqwest::RequestBuilder> {
        let Some(creds) = &self.credentials else {
            return Err(self.unconfigured());
        };
        let body_bytes = serde_json::to_vec(body)?;
        let headers = sign_sigv4(&SigV4Input {
            method: "POST",
            url,
            body: &body_bytes,
            region: &self.region,
            service: "bedrock",
            credentials: creds,
            now: Timestamp::now(),
        })?;
        let mut builder = self.client.post(url);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        Ok(builder.body(body_bytes))
    }
}

/// 从环境变量读取 AWS 凭据（EC2/ECS/SSO 元数据链未接入，见模块局限说明）。
pub(crate) fn env_aws_credentials() -> Option<AwsCredentials> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    if access_key_id.trim().is_empty() || secret_access_key.trim().is_empty() {
        return None;
    }
    Some(AwsCredentials { access_key_id, secret_access_key, session_token: std::env::var("AWS_SESSION_TOKEN").ok() })
}

pub(crate) async fn bedrock_complete(p: &BedrockProvider, req: &ChatRequest) -> DomainResult<ChatResponse> {
    let body = to_bedrock_converse_body(req);
    let url = p.converse_url();
    let builder = p.signed_request(&url, &body)?;
    let resp = execute_once(p.adapter_name(), &p.state, builder.send()).await?;
    let raw = read_json(p.adapter_name(), resp, &p.state).await?;
    from_bedrock_converse_response(&raw)
}

pub(crate) async fn bedrock_stream(p: &BedrockProvider, req: &ChatRequest) -> DomainResult<ProviderStream> {
    let body = to_bedrock_converse_body(req);
    let url = p.converse_stream_url();
    let builder = p.signed_request(&url, &body)?;
    let resp = execute_once(p.adapter_name(), &p.state, builder.send()).await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        p.state.failure(&format!("HTTP {status}"));
        return Err(http_status_error(BEDROCK_ADAPTER, status, &text));
    }
    Ok(bedrock_event_stream(resp, p.state.clone()))
}

/// Bedrock `converse` 响应 → canonical（与 Anthropic Messages 结构相近但字段不同）。
///
/// # Errors
/// 响应缺少 `output.message` 时返回 `DomainError::Parse`。
pub fn from_bedrock_converse_response(raw: &Value) -> DomainResult<ChatResponse> {
    let message = raw
        .get("output")
        .and_then(|o| o.get("message"))
        .ok_or_else(|| DomainError::Parse("Bedrock 响应缺少 output.message".to_string()))?;
    let mut text = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    for block in message.get("content").and_then(Value::as_array).into_iter().flatten() {
        if let Some(t) = block.get("text").and_then(Value::as_str) {
            text.push_str(t);
        }
        if let Some(tu) = block.get("toolUse") {
            tool_calls.push(ToolCall {
                id: format!("call_{}", tool_calls.len()),
                name: tu.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                arguments: tu.get("input").cloned().unwrap_or(Value::Null),
            });
        }
    }
    let finish_reason = raw.get("stopReason").and_then(Value::as_str).map_or(FinishReason::Stop, |r| match r {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        "content_filtered" | "guardrail_intervened" => FinishReason::ContentFilter,
        _ => FinishReason::Other,
    });
    let mut msg = ChatMessage::assistant(text);
    msg.tool_calls = tool_calls;
    Ok(ChatResponse {
        id: format!("agf-{}", agf_core::secret::generate_token()),
        model: raw.get("modelId").and_then(Value::as_str).unwrap_or_default().to_string(),
        message: msg,
        finish_reason,
        usage: raw.get("usage").map_or_else(Usage::default, |u| Usage {
            prompt_tokens: u.get("inputTokens").and_then(Value::as_u64).unwrap_or(0),
            completion_tokens: u.get("outputTokens").and_then(Value::as_u64).unwrap_or(0),
            cached_tokens: u.get("cacheReadInputTokens").and_then(Value::as_u64).unwrap_or(0),
            ..Usage::default()
        }),
        raw: Some(raw.clone()),
    })
}

/// canonical → Bedrock `converse` 请求体。
#[must_use]
pub fn to_bedrock_converse_body(req: &ChatRequest) -> Value {
    let mut body = Map::new();
    let mut messages: Vec<Value> = Vec::new();
    for m in &req.messages {
        if m.role == crate::wire::Role::System {
            continue;
        }
        let role = if m.role == crate::wire::Role::Assistant { "assistant" } else { "user" };
        let mut blocks: Vec<Value> = Vec::new();
        match m.role {
            crate::wire::Role::Tool => {
                blocks.push(json!({
                    "toolResult": {
                        "toolUseId": m.tool_call_id.clone().unwrap_or_default(),
                        "content": [{"text": m.content.as_plain_text()}],
                    }
                }));
            }
            _ => {
                let text = m.content.as_plain_text();
                if !text.is_empty() {
                    blocks.push(json!({"text": text}));
                }
                for call in &m.tool_calls {
                    blocks.push(json!({"toolUse": {"toolUseId": call.id, "name": call.name, "input": call.arguments}}));
                }
            }
        }
        if blocks.is_empty() {
            blocks.push(json!({"text": ""}));
        }
        messages.push(json!({"role": role, "content": blocks}));
    }
    body.insert("messages".into(), Value::Array(messages));
    if let Some(system) = req.system_prompt() {
        body.insert("system".into(), json!([{"text": system}]));
    }
    let mut inference = Map::new();
    if let Some(t) = req.temperature {
        inference.insert("temperature".into(), json!(t));
    }
    if let Some(top_p) = req.top_p {
        inference.insert("topP".into(), json!(top_p));
    }
    if !req.stop.is_empty() {
        inference.insert("stopSequences".into(), json!(req.stop));
    }
    if let Some(m) = req.max_tokens {
        inference.insert("maxTokens".into(), json!(m));
    }
    if !inference.is_empty() {
        body.insert("inferenceConfig".into(), Value::Object(inference));
    }
    if !req.tools.is_empty() {
        let specs: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                json!({"toolSpec": {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": {
                        "json": if t.parameters.is_null() { json!({"type": "object"}) } else { t.parameters.clone() }
                    }
                }})
            })
            .collect();
        body.insert("toolConfig".into(), json!({"tools": specs}));
    }
    Value::Object(body)
}

/// Bedrock `converse-stream` 的 AWS Event Stream 帧解析流。
///
/// 帧格式（大端）：
/// ```text
/// [0..4)   total_length (u32)
/// [4..8)   headers_length (u32)
/// [8..12)  prelude_crc (u32)
/// [12..12+headers_length)  headers
/// [..-4)   payload
/// [-4..)   message_crc (u32)
/// ```
/// 这里**不校验 CRC**（真实端点验证需要 AWS 凭据，属待验证项），
/// 只做长度切分与载荷解析，保证跨 chunk 粘包安全。
pub(crate) fn bedrock_event_stream(resp: reqwest::Response, state: ProviderState) -> ProviderStream {
    use futures::StreamExt as _;
    let mut body = resp.bytes_stream();
    let output = async_stream::stream! {
        let gate = StateGate::new(&state);
        let mut buffer: Vec<u8> = Vec::new();
        let mut saw_finish = false;
        loop {
            match body.next().await {
                None => break,
                Some(Err(e)) => {
                    gate.failure(&e.to_string());
                    yield Err(DomainError::DependencyUnavailable {
                        dependency: "bedrock".to_string(),
                        cause: format!("事件流读取中断: {e}"),
                    });
                    return;
                }
                Some(Ok(bytes)) => buffer.extend_from_slice(&bytes),
            }
            loop {
                if buffer.len() < 12 {
                    break;
                }
                let total = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if total < 16 || buffer.len() < total {
                    break;
                }
                let frame: Vec<u8> = buffer.drain(..total).collect();
                let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
                let headers_end = (12 + headers_len).min(frame.len().saturating_sub(4));
                let payload_end = frame.len().saturating_sub(4);
                if headers_end > payload_end {
                    continue;
                }
                let Ok(value) = serde_json::from_slice::<Value>(&frame[headers_end..payload_end]) else {
                    continue;
                };
                if let Some(chunk) = parse_bedrock_event(&value) {
                    saw_finish |= chunk.finish_reason.is_some();
                    yield Ok(chunk);
                }
            }
        }
        // 完整帧也必须含真实 messageStop；残缺尾帧和 EOF 都不能合成成功。
        if !saw_finish || !buffer.is_empty() {
            gate.failure("upstream event stream ended without a complete finish witness");
            yield Err(DomainError::DependencyUnavailable {
                dependency: "bedrock".into(), cause: "上游事件流缺少完整结束证据".into(),
            });
            return;
        }
        gate.success();
    };
    Box::pin(output)
}

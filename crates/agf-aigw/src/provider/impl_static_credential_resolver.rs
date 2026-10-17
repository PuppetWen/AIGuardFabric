//! 由 `provider.rs` 拆分：`impl_StaticCredentialResolver`/`impl_StaticCredentialResolver` 等 14 项（纯搬移，逻辑不变）。
use super::*;

impl StaticCredentialResolver {
    /// 新建空解析器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一条 API Key。
    #[must_use]
    pub fn with_key(mut self, credential_ref: Id, key: impl Into<String>) -> Self {
        self.keys.insert(credential_ref.to_string(), key.into());
        self
    }

    /// 插入一条 AWS 凭据。
    #[must_use]
    pub fn with_aws(mut self, credential_ref: Id, creds: AwsCredentials) -> Self {
        self.aws.insert(credential_ref.to_string(), creds);
        self
    }
}

impl CredentialResolver for StaticCredentialResolver {
    fn resolve_api_key(&self, credential_ref: &Id) -> Option<String> {
        self.keys.get(&credential_ref.to_string()).cloned()
    }

    fn resolve_aws_credentials(&self, credential_ref: &Id) -> Option<AwsCredentials> {
        self.aws.get(&credential_ref.to_string()).cloned()
    }
}

impl CredentialResolver for MockCredentialResolver {
    fn resolve_api_key(&self, _credential_ref: &Id) -> Option<String> {
        None
    }
}

impl EnvCredentialResolver {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 为某个凭据引用显式指定环境变量名（优先于 `AGF_LLM_KEY_<id>` 约定）。
    #[must_use]
    pub fn with_env(mut self, credential_ref: Id, env_name: impl Into<String>) -> Self {
        self.overrides.insert(credential_ref.to_string(), env_name.into());
        self
    }
}

impl CredentialResolver for EnvCredentialResolver {
    fn resolve_api_key(&self, credential_ref: &Id) -> Option<String> {
        let id = credential_ref.to_string();
        let name = self
            .overrides
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("AGF_LLM_KEY_{}", id.replace('-', "").to_uppercase()));
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn resolve_aws_credentials(&self, _credential_ref: &Id) -> Option<AwsCredentials> {
        env_aws_credentials()
    }
}

impl ProviderDescriptor {
    /// 构造描述。
    #[must_use]
    pub fn new(
        name: &str,
        display_name: &str,
        protocol: &str,
        providers: Vec<LlmProvider>,
        required_secrets: Vec<String>,
        real_implementation: bool,
    ) -> Self {
        Self {
            adapter: AdapterDescriptor {
                name: name.to_string(),
                display_name: display_name.to_string(),
                category: "llm".to_string(),
                required_secrets,
                optional_secrets: vec!["base_url".to_string(), "api_version".to_string()],
                capabilities: LLM_CAPABILITIES.to_vec(),
                degradation: "未配置 API Key 时不发起任何上游请求，网关自动切换到 MockProvider \
                              （src/mock.rs）返回确定性回复，平台功能不中断"
                    .to_string(),
                mock_location: "crates/agf-aigw/src/mock.rs#MockProvider".to_string(),
                real_implementation,
                doc_anchor: "docs/roadmap.md".to_string(),
            },
            providers,
            protocol: protocol.to_string(),
            real_implementation,
        }
    }

    /// 未配置凭据时的健康报告（**降级而非失败**）。
    #[must_use]
    pub fn unconfigured_health(&self, reason: &str, circuit: CircuitSnapshot) -> AdapterHealth {
        let mut h = AdapterHealth::unconfigured(self.adapter.name.as_str(), reason);
        h.circuit = circuit;
        h.capabilities = LLM_CAPABILITIES.to_vec();
        h
    }
}

impl ProviderState {
    /// 读取熔断快照。
    #[must_use]
    pub fn snapshot(&self) -> CircuitSnapshot {
        self.circuit.lock().clone()
    }

    /// 记录失败。
    pub fn failure(&self, error: &str) {
        self.circuit.lock().on_failure(&agf_core::adapter::CircuitBreakerConfig::default(), error, Timestamp::now());
    }

    /// 记录成功。
    pub fn success(&self) {
        self.circuit.lock().on_success();
    }
}

impl StateGate {
    pub(crate) fn new(state: &ProviderState) -> Self {
        Self { state: state.clone() }
    }

    pub(crate) fn failure(&self, error: &str) {
        self.state.failure(error);
    }

    pub(crate) fn success(&self) {
        self.state.success();
    }
}

// ---------------------------------------------------------------------------
// 公共执行帮助
// ---------------------------------------------------------------------------

/// 构造 HTTP 客户端（10 分钟总超时；单次调用超时由 [`DEFAULT_TIMEOUT_SECS`] 控制）。
pub(crate) fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_mins(10)).build().unwrap_or_else(|e| {
        warn!(error = %e, "构造 HTTP 客户端失败，退回默认客户端");
        reqwest::Client::new()
    })
}

/// 把 HTTP 响应状态映射为领域错误（4xx 不可重试，5xx/429 可重试）。
pub(crate) fn http_status_error(provider: &str, status: reqwest::StatusCode, _body: &str) -> DomainError {
    // Upstream error bodies can echo prompts, credentials, or personal data. The
    // status and provider identify the failure without copying that body into
    // API responses, audit records, or application logs.
    if status.as_u16() == 429 || status.is_server_error() {
        DomainError::DependencyUnavailable {
            dependency: provider.to_string(),
            cause: format!("HTTP {}", status.as_u16()),
        }
    } else {
        DomainError::Config(format!("{provider} 拒绝请求：HTTP {}；请检查模型、凭据和请求参数", status.as_u16()))
    }
}

/// 组装 URL（容忍 base_url 末尾斜杠）。
pub(crate) fn join_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

/// 执行一次受超时保护 + 熔断门禁的 HTTP 调用。
pub(crate) async fn execute_once<F>(
    provider_name: &str,
    state: &ProviderState,
    fut: F,
) -> DomainResult<reqwest::Response>
where
    F: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    // 熔断门禁：开路期间直接快速失败，不发请求
    let mut snap = state.snapshot();
    if !snap.allows_call(&agf_core::adapter::CircuitBreakerConfig::default(), Timestamp::now()) {
        return Err(DomainError::DependencyUnavailable {
            dependency: provider_name.to_string(),
            cause: "熔断器开路，快速失败".to_string(),
        });
    }
    match tokio::time::timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), fut).await {
        Err(_) => {
            state.failure("请求超时");
            Err(DomainError::Timeout(format!("{provider_name} 请求超时（{DEFAULT_TIMEOUT_SECS}s）")))
        }
        Ok(Err(e)) => {
            state.failure(&e.to_string());
            Err(DomainError::DependencyUnavailable {
                dependency: provider_name.to_string(),
                cause: format!("网络错误: {e}"),
            })
        }
        Ok(Ok(resp)) => Ok(resp),
    }
}

/// 读取响应体为 JSON（非 2xx 时返回映射后的错误）。
pub(crate) async fn read_json(
    provider_name: &str,
    resp: reqwest::Response,
    state: &ProviderState,
) -> DomainResult<Value> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| DomainError::DependencyUnavailable {
        dependency: provider_name.to_string(),
        cause: format!("读取响应体失败: {e}"),
    })?;
    if !status.is_success() {
        state.failure(&format!("HTTP {status}"));
        return Err(http_status_error(provider_name, status, &text));
    }
    state.success();
    serde_json::from_str(&text).map_err(|e| DomainError::Parse(format!("{provider_name} 响应不是合法 JSON: {e}")))
}

/// 把 SSE 字节流转换为 canonical 分片流。
///
/// 这是**唯一**的流式解析路径：`parse` 负责把一家厂商的 JSON 分片映射为
/// [`StreamChunk`]，[`SseDecoder`] 负责跨 chunk 边界的粘包处理。
/// 流结束后把结果写回**同一份** [`ProviderState`]（熔断计数在流式路径同样生效）。
pub(crate) fn sse_stream(
    provider_name: &'static str,
    resp: reqwest::Response,
    state: ProviderState,
    parse: SseParser,
) -> ProviderStream {
    use futures::StreamExt as _;
    let body = resp.bytes_stream();
    let output = async_stream::stream! {
        let gate = StateGate::new(&state);
        let mut decoder = SseDecoder::new();
        let mut chunks = body;
        let mut saw_finish = false;
        while let Some(item) = chunks.next().await {
            let bytes = match item {
                Ok(b) => b,
                Err(e) => {
                    gate.failure(&e.to_string());
                    yield Err(DomainError::DependencyUnavailable {
                        dependency: provider_name.to_string(),
                        cause: format!("流式读取中断: {e}"),
                    });
                    return;
                }
            };
            for event in decoder.feed(&bytes) {
                if event.is_done() {
                    // 只有真实协议结束帧可以补齐 canonical 结束信息。
                    if !saw_finish { yield Ok(StreamChunk::finished(FinishReason::Stop, None)); }
                    saw_finish = true;
                    continue;
                }
                let value = match event.json() {
                    Ok(v) => v,
                    Err(_) => {
                        // 单条分片解析失败不终止整个流（上游偶发心跳/空行）
                        // Never log the malformed upstream body: it can contain prompt data.
                        debug!("跳过无法解析的 SSE 分片");
                        continue;
                    }
                };
                if value.get("type").and_then(Value::as_str) == Some("error") || value.get("error").is_some() {
                    gate.failure("upstream SSE error");
                    yield Err(DomainError::DependencyUnavailable {
                        dependency: provider_name.to_string(), cause: "上游流式事件报告错误".into(),
                    });
                    return;
                }
                let chunk = parse(&value);
                if chunk.finish_reason.is_some() {
                    saw_finish = true;
                }
                yield Ok(chunk);
            }
        }
        for event in decoder.finish() {
            if event.is_done() {
                if !saw_finish { yield Ok(StreamChunk::finished(FinishReason::Stop, None)); }
                saw_finish = true;
                continue;
            }
            if let Ok(value) = event.json() {
                if value.get("type").and_then(Value::as_str) == Some("error") || value.get("error").is_some() {
                    gate.failure("upstream SSE error");
                    yield Err(DomainError::DependencyUnavailable {
                        dependency: provider_name.to_string(), cause: "上游流式事件报告错误".into(),
                    });
                    return;
                }
                let chunk = parse(&value);
                if chunk.finish_reason.is_some() {
                    saw_finish = true;
                }
                yield Ok(chunk);
            }
        }
        if !saw_finish {
            // EOF 不能冒充完成证据，也不能把已观测的部分用量升级为完整用量。
            gate.failure("upstream SSE ended without a finish witness");
            yield Err(DomainError::DependencyUnavailable {
                dependency: provider_name.to_string(), cause: "上游流缺少真实结束证据".into(),
            });
            return;
        }
        gate.success();
    };
    Box::pin(output)
}

//! 由 `mcp_proxy.rs` 拆分：`impl_JsonRpcParseError`/`impl_JsonRpcParseError` 等 8 项（纯搬移，逻辑不变）。
use super::*;

impl std::fmt::Display for JsonRpcParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "JSON 解析失败: {e}"),
            Self::NotAnObject => write!(f, "JSON-RPC 帧必须是 JSON 对象"),
            Self::BadVersion(v) => write!(f, "jsonrpc 字段必须为 \"2.0\"，实际为 {v:?}"),
            Self::UnknownShape => write!(f, "帧既不含 method 也不含 result/error，无法判定方向"),
            Self::TooLarge { actual, limit } => write!(f, "帧过大：{actual} 字节（上限 {limit}）"),
        }
    }
}

impl std::error::Error for JsonRpcParseError {}

impl From<JsonRpcParseError> for DomainError {
    fn from(value: JsonRpcParseError) -> Self {
        Self::Parse(format!("MCP JSON-RPC 帧非法: {value}"))
    }
}

impl JsonRpcFrame {
    /// 默认帧大小上限（1 MiB）。
    pub const DEFAULT_MAX_BYTES: usize = 1024 * 1024;

    /// 解析一行 JSON-RPC 文本。
    ///
    /// 会做三件事：JSON 解析、`jsonrpc == "2.0"` 校验、形状判定
    /// （含 `method` ⇒ 请求；否则须含 `result`/`error` ⇒ 响应）。
    ///
    /// # Errors
    /// 见 [`JsonRpcParseError`]。
    pub fn parse(raw: &str) -> Result<Self, JsonRpcParseError> {
        Self::parse_with_limit(raw, Self::DEFAULT_MAX_BYTES)
    }

    /// 带大小上限的解析。
    ///
    /// # Errors
    /// 见 [`JsonRpcParseError`]。
    pub fn parse_with_limit(raw: &str, max_bytes: usize) -> Result<Self, JsonRpcParseError> {
        if raw.len() > max_bytes {
            return Err(JsonRpcParseError::TooLarge { actual: raw.len(), limit: max_bytes });
        }
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| JsonRpcParseError::InvalidJson(e.to_string()))?;
        let obj = value.as_object().ok_or(JsonRpcParseError::NotAnObject)?;
        let version = obj.get("jsonrpc").and_then(serde_json::Value::as_str).unwrap_or_default();
        if version != "2.0" {
            return Err(JsonRpcParseError::BadVersion(version.to_string()));
        }
        let frame = Self {
            jsonrpc: "2.0".to_string(),
            id: obj.get("id").cloned(),
            method: obj.get("method").and_then(serde_json::Value::as_str).map(str::to_string),
            params: obj.get("params").cloned(),
            result: obj.get("result").cloned(),
            error: obj.get("error").cloned(),
        };
        if frame.method.is_none() && frame.result.is_none() && frame.error.is_none() {
            return Err(JsonRpcParseError::UnknownShape);
        }
        Ok(frame)
    }

    /// 解析 MCP `stdin` 的按行分帧输入（每行一个 JSON-RPC 帧）。
    ///
    /// 空行被跳过；**任一行非法即整体失败**（返回该行号），因为 MCP stdio 是
    /// 严格的一行一帧，静默丢弃坏行会让客户端永远等待。
    ///
    /// # Errors
    /// 返回 `(行号从 1 开始, 错误)`。
    pub fn parse_lines(input: &str, max_bytes: usize) -> Result<Vec<Self>, (usize, JsonRpcParseError)> {
        let mut out = Vec::new();
        for (idx, line) in input.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match Self::parse_with_limit(line, max_bytes) {
                Ok(frame) => out.push(frame),
                Err(e) => return Err((idx + 1, e)),
            }
        }
        Ok(out)
    }

    /// 是否为请求（含 `method`）。
    #[must_use]
    pub const fn is_request(&self) -> bool {
        self.method.is_some()
    }

    /// 是否为响应。
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.method.is_none() && (self.result.is_some() || self.error.is_some())
    }

    /// 方法名（响应返回 `"-"`）。
    #[must_use]
    pub fn method_name(&self) -> &str {
        self.method.as_deref().unwrap_or("-")
    }

    /// 是否为 `tools/call`。
    #[must_use]
    pub fn is_tool_call(&self) -> bool {
        self.method.as_deref() == Some("tools/call")
    }

    /// `params.name`（工具名）。
    #[must_use]
    pub fn tool_name(&self) -> Option<&str> {
        self.params.as_ref()?.get("name")?.as_str()
    }

    /// `params.arguments`（工具参数；缺失时返回空对象）。
    #[must_use]
    pub fn arguments(&self) -> serde_json::Value {
        self.params.as_ref().and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| serde_json::json!({}))
    }

    /// 从参数中提取常用目标：`domain` / `url`（取 host）/ `path` / `command`。
    ///
    /// 只识别**明确的字段名**，不做启发式字符串扫描（避免把普通文本误判为命令）。
    #[must_use]
    pub fn extract_targets(&self) -> FrameTargets {
        let args = self.arguments();
        let s = |key: &str| args.get(key).and_then(serde_json::Value::as_str).map(str::to_string);
        let command = s("command").or_else(|| s("cmd")).or_else(|| s("script")).or_else(|| s("code"));
        let path = s("path").or_else(|| s("file")).or_else(|| s("filename")).or_else(|| s("file_path"));
        let domain = s("domain")
            .or_else(|| s("host"))
            .or_else(|| s("url").as_deref().and_then(host_of))
            .or_else(|| s("endpoint").as_deref().and_then(host_of));
        FrameTargets { command, path, domain }
    }

    /// 序列化为 JSON 文本。
    ///
    /// # Errors
    /// 序列化失败（`serde_json::Value` 不会失败，保留 `Result` 以便未来替换实现）。
    pub fn to_line(&self) -> DomainResult<String> {
        serde_json::to_string(self).map_err(|e| DomainError::Internal(format!("JSON-RPC 序列化失败: {e}")))
    }

    /// 用新载荷替换参数（脱敏改写路径）。
    #[must_use]
    pub fn with_params(mut self, params: serde_json::Value) -> Self {
        self.params = Some(params);
        self
    }

    /// 用新结果替换响应体（出站脱敏路径）。
    #[must_use]
    pub fn with_result(mut self, result: serde_json::Value) -> Self {
        self.result = Some(result);
        self
    }

    /// 构造 JSON-RPC 错误响应（拦截回执）。
    #[must_use]
    pub fn error_response(
        id: Option<serde_json::Value>,
        code: i64,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> Self {
        let mut error = serde_json::json!({"code": code, "message": message});
        if let (Some(d), Some(obj)) = (data, error.as_object_mut()) {
            obj.insert("data".to_string(), d);
        }
        Self { jsonrpc: "2.0".to_string(), id, method: None, params: None, result: None, error: Some(error) }
    }

    /// 构造工具调用请求（测试与回放用）。
    #[must_use]
    pub fn tool_call(id: i64, name: &str, arguments: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(id)),
            method: Some("tools/call".to_string()),
            params: Some(serde_json::json!({"name": name, "arguments": arguments})),
            result: None,
            error: None,
        }
    }
}

/// 从 URL 取 host（非法 URL 返回 `None`）。
pub(crate) fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string))
}

impl InterceptOutcome {
    /// 是否放行（含脱敏放行与降级）。
    #[must_use]
    pub const fn is_forwarded(&self) -> bool {
        matches!(self, Self::Forward | Self::ForwardRedacted { .. } | Self::Degraded { .. })
    }

    /// 是否拦下。
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. } | Self::Throttled { .. } | Self::NeedsApproval { .. })
    }

    /// 对应的审计处置结果。
    #[must_use]
    pub const fn verdict(&self) -> InterceptionVerdict {
        match self {
            Self::Forward => InterceptionVerdict::Forwarded,
            Self::ForwardRedacted { .. } => InterceptionVerdict::ForwardedRedacted,
            Self::Blocked { .. } => InterceptionVerdict::Blocked,
            Self::Throttled { .. } => InterceptionVerdict::Throttled,
            Self::Degraded { .. } => InterceptionVerdict::Degraded,
            Self::NeedsApproval { .. } => InterceptionVerdict::PendingApproval,
        }
    }
}

impl SessionStats {
    /// 拦截率（`blocked / calls`，无调用时为 0）。
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn block_ratio(&self) -> f32 {
        if self.calls == 0 {
            return 0.0;
        }
        (self.blocked as f32) / (self.calls as f32)
    }
}

impl McpProxySession {
    /// 新建会话。
    #[must_use]
    pub fn new(tenant_id: TenantId, mcp_server_id: Id, transport: McpTransport) -> Self {
        Self {
            session_id: format!("mcp-{}", Id::new()),
            tenant_id,
            agent_id: None,
            context: None,
            transport,
            mcp_server_id,
            state: Mutex::new(SessionState::default()),
        }
    }

    /// 指定会话 id（代理侧已分配时使用；三级配额的会话级配额依赖它稳定）。
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// 绑定 Agent 资产。
    #[must_use]
    pub fn with_agent(mut self, agent_id: Id) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    /// 由服务端认证后注入上下文，不接受帧自述的租户/部门。
    #[must_use]
    pub fn with_context(mut self, context: PolicyContext) -> Self {
        self.context = Some(context);
        self
    }

    /// 会话 id。
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 租户。
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// 传输方式。
    #[must_use]
    pub const fn transport(&self) -> McpTransport {
        self.transport
    }

    /// 目标 MCP Server 资产 id。
    #[must_use]
    pub const fn mcp_server_id(&self) -> Id {
        self.mcp_server_id
    }

    /// 拦截点：MCP 传输一律映射到 [`InterceptPoint::McpProxy`]。
    #[must_use]
    pub const fn intercept_point(&self) -> InterceptPoint {
        InterceptPoint::McpProxy
    }

    /// 统计快照。
    pub async fn stats(&self) -> SessionStats {
        let s = self.state.lock().await;
        SessionStats {
            session_id: self.session_id.clone(),
            transport: self.transport,
            calls: s.calls,
            blocked: s.blocked,
            redacted: s.redacted,
            pending_approvals: s.pending_approvals,
            concurrency_held: s.concurrency_held,
            tool_usage: s.tool_usage.clone(),
        }
    }

    /// 记录一次调用的计数。
    pub(crate) async fn note_call(&self, tool: Option<&str>) {
        let mut s = self.state.lock().await;
        s.calls += 1;
        if let Some(t) = tool {
            *s.tool_usage.entry(t.to_string()).or_insert(0) += 1;
        }
    }

    /// 记录一次拦截。
    pub(crate) async fn note_blocked(&self) {
        self.state.lock().await.blocked += 1;
    }

    /// 记录一次脱敏改写。
    pub(crate) async fn note_redacted(&self) {
        self.state.lock().await.redacted += 1;
    }

    /// 记录一次待审批。
    pub(crate) async fn note_approval(&self) {
        self.state.lock().await.pending_approvals += 1;
    }

    /// 标记并发额度已登记（[`Self::finish`] 据此决定是否归还，避免重复 release）。
    pub(crate) async fn hold_concurrency(&self) {
        self.state.lock().await.concurrency_held = true;
    }

    /// 结束会话：若持有并发额度则归还（幂等：重复调用只归还一次）。
    ///
    /// # Errors
    /// 配额存储不可达。
    pub async fn finish(&self, quotas: &QuotaService, consumption: &QuotaConsumption) -> DomainResult<bool> {
        let held = {
            let mut s = self.state.lock().await;
            let held = s.concurrency_held;
            s.concurrency_held = false;
            held
        };
        if !held {
            return Ok(false);
        }
        quotas.complete(self.tenant_id, self.agent_id, &self.session_id, consumption).await.map(|()| true)
    }
}

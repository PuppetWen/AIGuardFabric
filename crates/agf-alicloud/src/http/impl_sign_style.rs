//! 由 `http.rs` 拆分：`impl_SignStyle`/`impl_RpcRequest` 等 10 项（纯搬移，逻辑不变）。
use super::*;

impl SignStyle {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rpc => "rpc-hmac-sha1",
            Self::V3 => "v3-acs3-hmac-sha256",
        }
    }
}

impl RpcRequest {
    /// 排障摘要不包含签名查询串、SecurityToken 或 Authorization。
    #[must_use]
    pub fn summary(&self) -> String {
        format!("{} {} ({})", self.method, self.url, self.style.as_str())
    }
}

impl RpcResponse {
    /// 远端业务 `Code` 字段（阿里云错误响应统一带 `Code`）。
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.body.get("Code").or_else(|| self.body.get("code")).and_then(serde_json::Value::as_str)
    }

    /// 远端 `Message`。
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.body.get("Message").or_else(|| self.body.get("message")).and_then(serde_json::Value::as_str)
    }

    /// 业务上是否成功（2xx 且无字符串错误 `Code`）。
    #[must_use]
    pub fn is_business_success(&self) -> bool {
        if !(200..300).contains(&self.status)
            || !self.body.is_object()
            || self.body.get("Raw").is_some()
            || self.body.get("Success").or_else(|| self.body.get("success")) == Some(&serde_json::Value::Bool(false))
        {
            return false;
        }
        match self.body.get("Code").or_else(|| self.body.get("code")) {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::String(code)) => {
                matches!(code.to_ascii_lowercase().as_str(), "success" | "ok" | "200" | "0")
                    || (code == "1" && self.body.get("Success") == Some(&serde_json::Value::Bool(true)))
            }
            Some(serde_json::Value::Number(code)) => code.as_u64().is_some_and(|code| {
                code == 0
                    || code == 200
                    || (code == 1 && self.body.get("Success") == Some(&serde_json::Value::Bool(true)))
            }),
            _ => false,
        }
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::with_body(serde_json::json!({}))
    }
}

impl RecordingTransport {
    /// 用给定响应体构造。
    #[must_use]
    pub fn with_body(body: serde_json::Value) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(body),
            status: Mutex::new(200),
            fail_with: Mutex::new(None),
        }
    }

    /// 模拟网络故障。
    #[must_use]
    pub fn failing(reason: &str) -> Self {
        let transport = Self::with_body(serde_json::Value::Null);
        if let Ok(mut slot) = transport.fail_with.lock() {
            *slot = Some(reason.to_string());
        }
        transport
    }

    /// 设置响应体。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn set_body(&self, body: serde_json::Value) -> DomainResult<()> {
        let mut slot = self.response.lock().map_err(|_| DomainError::Internal("响应锁中毒".to_string()))?;
        *slot = body;
        Ok(())
    }

    /// 设置状态码。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn set_status(&self, status: u16) -> DomainResult<()> {
        let mut slot = self.status.lock().map_err(|_| DomainError::Internal("状态码锁中毒".to_string()))?;
        *slot = status;
        Ok(())
    }

    /// 已记录的请求数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn call_count(&self) -> DomainResult<usize> {
        self.requests.lock().map(|r| r.len()).map_err(|_| DomainError::Internal("请求锁中毒".to_string()))
    }

    /// 最近一次请求（克隆）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn last_request(&self) -> DomainResult<Option<RpcRequest>> {
        self.requests.lock().map(|r| r.last().cloned()).map_err(|_| DomainError::Internal("请求锁中毒".to_string()))
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        if let Ok(mut guard) = self.requests.lock() {
            guard.push(request.clone());
        }
        let failure = self.fail_with.lock().ok().and_then(|f| f.clone());
        if let Some(reason) = failure {
            return Err(DomainError::DependencyUnavailable { dependency: "alicloud.rpc".to_string(), cause: reason });
        }
        let body =
            self.response.lock().map(|b| b.clone()).map_err(|_| DomainError::Internal("响应锁中毒".to_string()))?;
        let status = *self.status.lock().map_err(|_| DomainError::Internal("状态码锁中毒".to_string()))?;
        let raw = body.to_string();
        Ok(RpcResponse { status, body, raw })
    }
}

impl TlsPolicy {
    /// 文本形式（写入自检报告与 notes）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyChain => "verify-chain",
            Self::CustomCa => "custom-ca",
            Self::Insecure => "insecure-skip-verify",
        }
    }

    /// 是否是"放松"策略（需要在自检/日志里显式标注）。
    #[must_use]
    pub const fn is_relaxed(&self) -> bool {
        !matches!(self, Self::VerifyChain)
    }
}

/// 是否允许放松 TLS 校验：`AGF_ENV=dev|development|local` 或显式开关
/// `AGF_ALIYUN_ALLOW_INSECURE_TLS=1`。
///
/// **生产默认关闭**：`AGF_ENV` 未设置或为 `prod/production` ⇒ 即使配了 `ca_pem`/
/// `insecure_tls` 也不生效（只 `warn!` 说明被忽略）。
#[must_use]
pub fn tls_override_allowed() -> bool {
    let dev = std::env::var("AGF_ENV")
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "dev" | "development" | "local" | "test"));
    let explicit = std::env::var("AGF_ALIYUN_ALLOW_INSECURE_TLS")
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    dev || explicit
}

impl ReqwestTransport {
    /// 构造（带超时，**默认校验链**）。
    ///
    /// # Errors
    /// TLS / 客户端初始化失败。
    pub fn new(timeout_secs: u64) -> DomainResult<Self> {
        Self::with_tls_options(timeout_secs, None, false)
    }

    /// 构造（可选自定义 CA / 跳过校验）。
    ///
    /// `ca_pem` 为 PEM 编码的额外信任锚；`allow_insecure_tls` 跳过证书校验。
    /// 两者都受 [`tls_override_allowed`] 约束：不在 dev/显式开关下时**忽略并 warn**。
    ///
    /// # Errors
    /// CA PEM 非法，或 TLS / 客户端初始化失败。
    pub fn with_tls_options(
        timeout_secs: u64,
        ca_pem: Option<Vec<u8>>,
        allow_insecure_tls: bool,
    ) -> DomainResult<Self> {
        let timeout = std::time::Duration::from_secs(timeout_secs.max(1));
        let allowed = tls_override_allowed();
        if !allowed && (ca_pem.is_some() || allow_insecure_tls) {
            tracing::warn!(
                "配置了 ca_pem/insecure_tls，但 AGF_ENV 不是 dev 且未显式设置 AGF_ALIYUN_ALLOW_INSECURE_TLS=1：\
                 已忽略（生产默认校验证书链）"
            );
        }
        let ca_pem = if allowed { ca_pem } else { None };
        let allow_insecure_tls = allowed && allow_insecure_tls;

        // Signed operations must stay on the selected origin and pass the send guard once.
        // Disable reqwest's protocol-level retries as well as redirects and environment proxies.
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy();
        let mut policy = TlsPolicy::VerifyChain;
        if let Some(pem) = ca_pem {
            let mut store = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| DomainError::Config(format!("ca_pem 解析失败（需 PEM 证书）：{e}")))?;
            // 兼容只有单个证书/带注释的 PEM：bundle 为空时逐个再试一次
            if store.is_empty() {
                let single = reqwest::Certificate::from_pem(&pem)
                    .map_err(|e| DomainError::Config(format!("ca_pem 解析失败（需 PEM 证书）：{e}")))?;
                store.push(single);
            }
            let cert_count = store.len();
            for cert in store {
                builder = builder.add_root_certificate(cert);
            }
            policy = TlsPolicy::CustomCa;
            tracing::warn!(certs = cert_count, "已启用自定义 CA（ca_pem）：仅建议用于 dev/联调（模拟器自签证书）");
        }
        if allow_insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
            policy = TlsPolicy::Insecure;
            tracing::warn!("已启用 allow_insecure_tls：**证书校验被跳过**，仅限 dev/联调，禁止用于生产");
        }
        let client = builder.build().map_err(|e| DomainError::Internal(format!("reqwest 客户端初始化失败: {e}")))?;
        Ok(Self { client, timeout, tls_policy: policy })
    }

    /// 实际生效的 TLS 策略（自检/`/readyz` notes 用）。
    #[must_use]
    pub const fn tls_policy(&self) -> &TlsPolicy {
        &self.tls_policy
    }

    /// 超时设置。
    #[must_use]
    pub const fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    /// 解析响应体：JSON 优先，其次极简 XML（阿里云部分老接口返回 XML）。
    ///
    /// 完整 XML 语义由 `quick-xml` 承担（见 `agf-ingest`）；这里保持极简以免为个别老接口
    /// 引入额外依赖。
    #[must_use]
    pub fn parse_body(status: u16, text: &str) -> RpcResponse {
        let trimmed = text.trim();
        let body = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            serde_json::from_str(trimmed).unwrap_or_else(|_| serde_json::json!({ "Raw": trimmed }))
        } else if trimmed.starts_with('<') {
            parse_simple_xml(trimmed)
        } else if trimmed.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "Raw": trimmed })
        };
        RpcResponse { status, body, raw: trimmed.chars().take(2_048).collect() }
    }

    /// 异步发送（**唯一真实网络路径**）。
    ///
    /// # Errors
    /// 网络失败、超时或响应体读取失败。
    pub async fn send_async(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| DomainError::Validation(format!("非法 HTTP 方法 {}: {e}", request.method)))?;
        let url =
            if request.query.is_empty() { request.url.clone() } else { format!("{}?{}", request.url, request.query) };
        let mut builder = self.client.request(method, &url);
        for (k, v) in &request.headers {
            builder = builder.header(k, v);
        }
        if !request.body.is_empty() {
            if !request.headers.keys().any(|key| key.eq_ignore_ascii_case("content-type")) {
                builder = builder.header(reqwest::header::CONTENT_TYPE, "application/json");
            }
            builder = builder.body(request.body.clone());
        }
        let response = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                DomainError::Timeout(format!("请求 {} 超时: {}", request.url, error_chain(&e.without_url())))
            } else {
                DomainError::DependencyUnavailable {
                    dependency: "alicloud.rpc".to_string(),
                    // 展开 source 链：reqwest 的 Display 只有 "error sending request"，
                    // 证书校验失败 / DNS / 连接被拒的细节全在 source 里（排障必需）。
                    cause: format!("请求 {} 失败: {}", request.url, error_chain(&e.without_url())),
                }
            }
        })?;
        let mut response = response;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) =
            response.chunk().await.map_err(|e| DomainError::Parse(format!("读取响应体失败: {}", e.without_url())))?
        {
            if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
                return Err(DomainError::Parse("云 API 响应超过 2 MiB，请缩小分页".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(bytes).map_err(|_| DomainError::Parse("云 API 响应不是 UTF-8".into()))?;
        let trimmed = text.trim();
        let parsed = Self::parse_body(status, &text);
        if trimmed.is_empty() {
            if (200..300).contains(&status) && status != 204 && status != 205 {
                return Err(DomainError::Parse("云 API 返回空响应，不能确认执行结果".into()));
            }
        } else if trimmed.starts_with('<') {
            let root = trimmed
                .strip_prefix("<?xml")
                .and_then(|xml| xml.split_once("?>").map(|(_, body)| body.trim()))
                .unwrap_or(trimmed);
            if !(root.starts_with("<Error>") || root.starts_with("<Error "))
                || !root.ends_with("</Error>")
                || parsed.code().is_none()
                || parsed.is_business_success()
            {
                return Err(DomainError::Parse("云 API 返回非预期 XML/HTML，不能确认执行结果".into()));
            }
        } else if !serde_json::from_str::<serde_json::Value>(trimmed).is_ok_and(|value| value.is_object()) {
            return Err(DomainError::Parse("云 API 响应不是有效 JSON 对象".into()));
        }
        Ok(parsed)
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, _request: &RpcRequest) -> DomainResult<RpcResponse> {
        // 真实网络只走 send_async：reqwest 阻塞 API 在 tokio 运行时内会 panic，
        // 因此这里明确失败而不是"看起来能用"。
        Err(DomainError::Internal(
            "真实 HTTP 客户端不支持同步发送（会 panic）；请使用 RpcClient::call_async".to_string(),
        ))
    }
}

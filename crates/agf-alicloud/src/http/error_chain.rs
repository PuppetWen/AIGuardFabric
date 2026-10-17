//! 由 `http.rs` 拆分：`error_chain`/`parse_simple_xml` 等 5 项（纯搬移，逻辑不变）。
use super::*;

/// 展开错误链（`Display` 只有最外层；证书 / DNS / 连接细节在 `source()` 链里）。
#[must_use]
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        out.push_str(" ← ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

/// 极简 XML → JSON（只取根元素下的一层子元素）。
#[must_use]
pub fn parse_simple_xml(xml: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let xml = xml.trim();
    let mut rest = xml
        .strip_prefix("<?xml")
        .and_then(|declaration| declaration.split_once("?>").map(|(_, body)| body.trim()))
        .unwrap_or(xml);
    if let Some(start) = rest.find('>') {
        rest = &rest[start + 1..];
    }
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        if after.starts_with('/') || after.starts_with('?') || after.starts_with('!') {
            break;
        }
        let Some(close_rel) = after.find('>') else { break };
        let tag = after[..close_rel].trim().to_string();
        if tag.is_empty() {
            break;
        }
        let body_start = open + 1 + close_rel + 1;
        let closing = format!("</{tag}>");
        let Some(end_rel) = rest[body_start..].find(&closing) else { break };
        let value = rest[body_start..body_start + end_rel].trim();
        let json = value.parse::<i64>().map_or_else(|_| serde_json::Value::from(value), serde_json::Value::from);
        map.insert(tag, json);
        rest = &rest[body_start + end_rel + closing.len()..];
    }
    serde_json::Value::Object(map)
}

/// 把远端错误码映射为领域错误（决定是否重试：`DependencyUnavailable` / `Timeout` 会重试）。
#[must_use]
pub fn map_error_code(code: &str, message: &str, request_id: Option<&str>) -> DomainError {
    let detail = match request_id {
        Some(id) => format!("{code}: {message} (RequestId={id})"),
        None => format!("{code}: {message}"),
    };
    // Provider subcodes keep their authorization meaning; messages are never classified.
    if ["Forbidden.", "NoPermission.", "UnauthorizedOperation."]
        .iter()
        .any(|prefix| code.strip_prefix(prefix).is_some_and(|suffix| !suffix.is_empty()))
    {
        return DomainError::Forbidden(detail);
    }
    match code {
        "InvalidAccessKeyId"
        | "SignatureDoesNotMatch"
        | "InvalidSecurityToken.Expired"
        | "InvalidSecurityToken.Malformed"
        | "Forbidden"
        | "NoPermission"
        | "UnauthorizedOperation" => DomainError::Forbidden(detail),
        "Throttling" | "Throttling.User" | "Throttling.Api" | "ServiceUnavailable" | "InternalError"
        | "ServerError" => DomainError::DependencyUnavailable { dependency: "alicloud.rpc".to_string(), cause: detail },
        "InvalidParameter" | "MissingParameter" | "InvalidAction" | "InvalidVersion" => DomainError::Validation(detail),
        "QuotaExceeded" | "LimitExceeded" => {
            DomainError::QuotaExceeded { scope: "cloud".to_string(), dimension: "api".to_string(), used: 1, limit: 0 }
        }
        _ => DomainError::DependencyUnavailable { dependency: "alicloud.rpc".to_string(), cause: detail },
    }
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("adapter", &self.config.adapter)
            .field("host", &self.endpoint.host)
            .field("style", &self.config.style.as_str())
            .field("credential", &self.credential)
            .field("has_async_transport", &self.async_transport.is_some())
            // 传输实现内部只有连接池；nonce/timestamp 覆盖是测试钩子，均无诊断价值
            .field("sync_transport", &"<transport>")
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// Security-group rules belong to ECS. Preserve the transport and short-lived identity.
    pub(crate) fn ecs_security_group_client(&self, explicit: Option<&str>) -> DomainResult<Self> {
        if self.endpoint.is_private() && explicit.is_none() {
            return Err(DomainError::Config(
                "私网模式检查安全组需要显式配置可达的 ECS ecs_endpoint；不会自动切换公网".into(),
            ));
        }
        let default = format!("https://ecs.{}.aliyuncs.com", self.config.region);
        let overrides = BTreeMap::from([("privatelink".into(), explicit.unwrap_or(&default).into())]);
        let endpoint = crate::endpoint::resolve(
            agf_core::enums::AliCloudService::Privatelink,
            &self.config.region,
            self.endpoint.style,
            &overrides,
        )?;
        let mut config = self.config.clone();
        config.adapter = "alicloud-ecs-security-groups".into();
        config.style = SignStyle::Rpc;
        Ok(Self {
            config,
            credential: self.credential.clone(),
            endpoint,
            sync_transport: self.sync_transport.clone(),
            async_transport: self.async_transport.clone(),
            nonce_override: None,
            timestamp_override: None,
        })
    }
    /// **唯一**的真实客户端构造入口：Mock 或缺凭据一律拒绝。
    ///
    /// # Errors
    /// - [`AdapterMode::Mocked`] → [`DomainError::Internal`]（编码错误，不是运行时故障）；
    /// - 未配置或凭据缺失 → [`DomainError::DependencyUnavailable`]。
    pub fn live(
        mode: AdapterMode,
        config: RpcClientConfig,
        credential: Option<CloudCredential>,
        endpoint: ResolvedEndpoint,
        transport: Arc<dyn Transport>,
    ) -> DomainResult<Self> {
        match mode {
            AdapterMode::Mocked => {
                return Err(DomainError::Internal(format!(
                    "适配器 {} 处于 Mock 模式，禁止构造真实 RPC 客户端（不变量：Mock 绝不触网）",
                    config.adapter
                )));
            }
            AdapterMode::Unconfigured => {
                return Err(DomainError::DependencyUnavailable {
                    dependency: config.adapter,
                    cause: "适配器未配置（缺少凭据），已阻断真实调用".to_string(),
                });
            }
            AdapterMode::Live => {}
        }
        let Some(credential) = credential else {
            return Err(DomainError::DependencyUnavailable {
                dependency: config.adapter,
                cause: "缺少 AccessKey/STS 凭据，已阻断真实调用".to_string(),
            });
        };
        credential.validate()?;
        Ok(Self {
            config,
            credential,
            endpoint,
            sync_transport: transport,
            async_transport: None,
            nonce_override: None,
            timestamp_override: None,
        })
    }

    /// 注入异步发送口（生产路径）。
    #[must_use]
    pub fn with_async_transport(mut self, transport: Arc<ReqwestTransport>) -> Self {
        self.async_transport = Some(transport);
        self
    }

    /// 注入固定 nonce（测试）。
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce_override = Some(nonce.into());
        self
    }

    /// 注入固定时间戳（测试）。
    #[must_use]
    pub const fn with_timestamp(mut self, at: Timestamp) -> Self {
        self.timestamp_override = Some(at);
        self
    }

    /// 客户端配置。
    #[must_use]
    pub const fn config(&self) -> &RpcClientConfig {
        &self.config
    }

    /// 解析出的 endpoint。
    #[must_use]
    pub const fn endpoint(&self) -> &ResolvedEndpoint {
        &self.endpoint
    }

    /// 凭据（**只在签名时读取明文**）。
    #[must_use]
    pub const fn credential(&self) -> &CloudCredential {
        &self.credential
    }

    /// 是否绑定了真实网络通道。
    #[must_use]
    pub const fn has_async_transport(&self) -> bool {
        self.async_transport.is_some()
    }

    /// RFC3339（秒精度）时间戳。
    pub(crate) fn timestamp_string(&self) -> String {
        let at = self.timestamp_override.unwrap_or_else(Timestamp::now);
        at.as_datetime().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    pub(crate) fn nonce(&self) -> String {
        self.nonce_override.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }

    /// 构造（已签名）的 RPC 请求。
    ///
    /// # Errors
    /// 目前不会失败，保留 `Result` 以便后续加入 V3 body 签名等校验。
    pub fn build(
        &self,
        action: &str,
        version: &str,
        method: &str,
        params: &[(String, String)],
    ) -> DomainResult<RpcRequest> {
        if self.credential.is_expired(Timestamp::now()) {
            return Err(DomainError::Forbidden("云临时凭据已过期，请刷新后重试".into()));
        }
        let mut all: Vec<(String, String)> = params.to_vec();
        all.push(("Action".to_string(), action.to_string()));
        all.push(("Version".to_string(), version.to_string()));
        let timestamp = self.timestamp_string();
        match self.config.style {
            SignStyle::Rpc => {
                if let Some(token) = &self.credential.security_token {
                    all.push(("SecurityToken".into(), token.clone()));
                }
                let signed = sign_rpc(&RpcSignInput {
                    method,
                    access_key_id: &self.credential.access_key_id,
                    access_key_secret: &self.credential.access_key_secret,
                    params: all,
                    timestamp: &timestamp,
                    signature_nonce: &self.nonce(),
                });
                Ok(RpcRequest {
                    method: method.to_uppercase(),
                    url: self.endpoint.url("/"),
                    style: SignStyle::Rpc,
                    query: signed.final_query,
                    headers: BTreeMap::new(),
                    body: String::new(),
                })
            }
            SignStyle::V3 => {
                let mut headers = BTreeMap::new();
                headers.insert("x-acs-action".to_string(), action.to_string());
                headers.insert("x-acs-version".to_string(), version.to_string());
                headers.insert("x-acs-date".to_string(), timestamp);
                headers.insert("x-acs-signature-nonce".to_string(), self.nonce());
                if let Some(token) = &self.credential.security_token {
                    headers.insert("x-acs-security-token".to_string(), token.clone());
                }
                let query = canonicalized_query(params);
                let signed = sign_v3(&V3SignInput {
                    method,
                    canonical_uri: "/",
                    canonical_query: &query,
                    headers,
                    host: &self.endpoint.host,
                    body: "",
                    access_key_id: &self.credential.access_key_id,
                    access_key_secret: &self.credential.access_key_secret,
                });
                let mut out_headers = signed.signed_headers.clone();
                out_headers.insert("Authorization".to_string(), signed.authorization);
                Ok(RpcRequest {
                    method: method.to_uppercase(),
                    url: self.endpoint.url("/"),
                    style: SignStyle::V3,
                    query,
                    headers: out_headers,
                    body: String::new(),
                })
            }
        }
    }

    /// 发送已构造的请求（同步，供测试替身使用；真实客户端会被拒绝）。
    ///
    /// # Errors
    /// 已绑定真实网络通道、网络失败或远端返回错误码。
    pub fn execute(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        if self.async_transport.is_some() {
            return Err(DomainError::Internal("该客户端已绑定真实异步通道，禁止走同步发送（会 panic）".to_string()));
        }
        let response = self.sync_transport.send(request)?;
        check_response(&response)?;
        Ok(response)
    }

    /// 发送已构造的请求（异步，真实网络）。
    ///
    /// # Errors
    /// 未注入真实通道、网络失败或远端返回错误码。
    pub async fn execute_async(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        let response = self.execute_async_raw(request).await?;
        check_response(&response)?;
        Ok(response)
    }

    /// Preserve structured vendor evidence for the restricted resource observer.
    pub(crate) async fn execute_async_raw(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        match self.async_transport.clone() {
            Some(transport) => transport.send_async(request).await,
            None => self.sync_transport.send(request),
        }
    }

    /// 一步到位：构造 + 同步发送。
    ///
    /// # Errors
    /// 见 [`Self::execute`]。
    pub fn call(
        &self,
        action: &str,
        version: &str,
        method: &str,
        params: &[(String, String)],
    ) -> DomainResult<RpcResponse> {
        let request = self.build(action, version, method, params)?;
        self.execute(&request)
    }

    /// 一步到位：构造 + 异步发送。
    ///
    /// # Errors
    /// 见 [`Self::execute_async`]。
    pub async fn call_async(
        &self,
        action: &str,
        version: &str,
        method: &str,
        params: &[(String, String)],
    ) -> DomainResult<RpcResponse> {
        let request = self.build(action, version, method, params)?;
        self.execute_async(&request).await
    }
}

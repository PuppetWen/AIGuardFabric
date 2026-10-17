//! 真实 mTLS 上行传输：rustls 客户端握手 + 最小 HTTP/1.1 POST。
//!
//! ## 为什么不用 `reqwest`
//!
//! `reqwest` 的 rustls 后端只暴露 `Identity::from_pem`，无法把"跳过校验"与
//! "客户端证书即身份对象"同时表达清楚；而采集器的上行面**只有一个 POST**，
//! 直接用 `tokio-rustls` 发一个 HTTP/1.1 请求既省依赖又能逐层给出可分类的错误
//! （[`TlsErrorKind`]）。响应体只用于回执校验，不做通用 HTTP 客户端。
//!
//! ## 同步接口与异步实现
//!
//! [`AgentTransport::send`] 是同步方法（`client` 模块的整体口径），而 rustls 需要异步
//! 驱动。这里按"当前是否已在 tokio 运行时里"分流：在线程池上 `block_on` 建立连接，
//! 避免在已有运行时上再建运行时（那会 panic）或阻塞 runtime worker。

use std::sync::Arc;

use agf_core::error::{DomainError, DomainResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;

use super::tls_rustls::{TlsMaterial, classify};
use super::{AgentTransport, TlsErrorKind, TlsMode};

/// 上行响应上限（防御服务端异常放大；回执 JSON 远小于此）。
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// URL 拆分结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsEndpoint {
    /// 是否 TLS。
    pub tls: bool,
    /// 主机名（TLS SNI / 主机名校验用）。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 请求目标（`/path`）。
    pub target: String,
}

impl TlsEndpoint {
    /// 解析 `http(s)://host[:port]/path`。
    ///
    /// # Errors
    /// scheme 不是 http/https、缺主机名或端口非法。
    pub fn parse(url: &str) -> DomainResult<Self> {
        let trimmed = url.trim();
        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| DomainError::Config("上行地址缺少 scheme（必须 http:// 或 https://）".to_string()))?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            other => {
                return Err(DomainError::Config(format!("上行地址 scheme 不支持: {other}（仅 http/https）")));
            }
        };
        if rest.is_empty() {
            return Err(DomainError::Config("上行地址缺少主机名".to_string()));
        }
        let (authority, target) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        // 去掉 userinfo（凭据不进日志：解析后直接丢弃）
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| DomainError::Config(format!("上行地址端口非法（{p}）")))?;
                (h, port)
            }
            None => (authority, if tls { 443 } else { 80 }),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(DomainError::Config("上行地址主机名为空".to_string()));
        }
        let target = if target.is_empty() { "/" } else { target };
        Ok(Self { tls, host: host.to_string(), port, target: target.to_string() })
    }
}

/// 一次上行响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsResponse {
    /// HTTP 状态码。
    pub status: u16,
    /// 响应体（UTF-8 有损解码）。
    pub body: String,
    /// 协商到的 TLS 协议版本（明文模式为 `None`）。
    pub protocol: Option<String>,
    /// 协商到的密码套件（明文模式为 `None`）。
    pub cipher: Option<String>,
}

impl TlsResponse {
    /// 是否 2xx。
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// 真实上行传输（TLS 与明文同一条实现，按 endpoint scheme 决定是否握手）。
pub struct TlsTransport {
    material: Option<TlsMaterial>,
    token: Option<String>,
    agent_id: Option<String>,
    mode: TlsMode,
    client_config: std::sync::Mutex<Option<Arc<ClientConfig>>>,
    last_response: std::sync::Mutex<Option<TlsResponse>>,
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // **绝不打印 token/私钥/证书内容**
        f.debug_struct("TlsTransport")
            .field("mode", &self.mode)
            .field("has_token", &self.token.is_some())
            .field("agent_id", &self.agent_id)
            .field("material", &self.material)
            .field("client_config", &self.client_config.lock().ok().map(|guard| guard.is_some()))
            .field("last_response", &self.last_response.lock().ok().and_then(|guard| guard.clone()))
            .finish()
    }
}

impl TlsTransport {
    /// 由 TLS 配置材料构造（`Plaintext` 模式下 `material` 可为 `None`）。
    ///
    /// # Errors
    /// rustls 客户端配置装配失败（PEM 非法、证书与私钥不匹配）。
    pub fn new(mode: TlsMode, material: Option<TlsMaterial>) -> DomainResult<Self> {
        let config = match &material {
            Some(material) if mode.is_tls() => Some(material.client_config()?),
            _ => None,
        };
        Ok(Self {
            material,
            token: None,
            agent_id: None,
            mode,
            client_config: std::sync::Mutex::new(config),
            last_response: std::sync::Mutex::new(None),
        })
    }

    /// 由配置装配（读盘 + rustls 配置；失败**明确报错**，不静默降级为明文）。
    ///
    /// # Errors
    /// 配置组合非法或 PEM 读取/装配失败。
    pub fn from_config(tls: &super::TlsConfig, server_url: Option<&str>) -> DomainResult<Self> {
        let mode = tls.validate(server_url)?;
        let material = if mode.is_tls() { Some(tls.load()?) } else { None };
        Self::new(mode, material)
    }

    /// 设置 Bearer 令牌（**不打印明文**）。
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// 设置 agent id（写 `X-AGF-Agent-Id` 便于服务端审计）。
    #[must_use]
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// TLS 模式。
    #[must_use]
    pub const fn mode(&self) -> TlsMode {
        self.mode
    }

    /// 最近一次响应（排障与自检用；`send` 成功/失败都会写入）。
    #[must_use]
    pub fn last_response(&self) -> Option<TlsResponse> {
        self.last_response.lock().ok().and_then(|guard| guard.clone())
    }

    /// 是否持有客户端证书（mTLS 身份是否已装配）。
    #[must_use]
    pub fn has_client_identity(&self) -> bool {
        self.material.as_ref().is_some_and(|m| !m.client_certs.is_empty() && m.client_key.is_some())
    }

    /// 发送并返回响应（供自检/端到端验证读取状态码与协商参数）。
    ///
    /// # Errors
    /// 网络/TLS/协议失败；非 2xx 由调用方判定（本方法不把 4xx 当错误）。
    pub fn send_with_response(&self, endpoint: &str, body: &str) -> DomainResult<TlsResponse> {
        if self.token.iter().chain(self.agent_id.iter()).any(|value| value.contains(['\r', '\n'])) {
            return Err(DomainError::Validation("认证头不能包含换行符".into()));
        }
        let endpoint = endpoint.to_string();
        let body = body.to_string();
        let token = self.token.clone();
        let agent_id = self.agent_id.clone();
        let config = self.client_config.lock().ok().and_then(|guard| guard.clone());
        let allow_insecure = self.material.as_ref().is_some_and(|m| m.insecure_skip_verify);
        let response = block_on_detached(async move {
            exchange(&endpoint, &body, token.as_deref(), agent_id.as_deref(), config, allow_insecure).await
        })?;
        if let Ok(mut slot) = self.last_response.lock() {
            *slot = Some(response.clone());
        }
        Ok(response)
    }
}

impl AgentTransport for TlsTransport {
    fn name(&self) -> &'static str {
        match self.mode {
            TlsMode::Mutual => "mtls",
            TlsMode::ServerAuth => "tls",
            TlsMode::Plaintext => "plaintext-http",
        }
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn last_response(&self) -> Option<TlsResponse> {
        self.last_response()
    }

    fn send(&self, endpoint: &str, body: &str) -> DomainResult<()> {
        let response = self.send_with_response(endpoint, body)?;
        if response.is_success() {
            return Ok(());
        }
        // **只回显状态码与截断后的响应体（problem+json）**，不回显请求头里的令牌
        let snippet: String = response.body.chars().take(400).collect();
        Err(classify(TlsErrorKind::Http, &format!("HTTP {} {}", response.status, snippet.trim())))
    }
}

/// 在独立线程上 `block_on`（避免嵌套运行时 panic，也不阻塞已有 runtime 的 worker）。
fn block_on_detached<F, T>(future: F) -> DomainResult<T>
where
    F: std::future::Future<Output = DomainResult<T>> + Send + 'static,
    T: Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name("agf-agent-uplink".to_string())
        .stack_size(256 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| classify(TlsErrorKind::Network, &format!("tokio 运行时构造失败: {e}")))?;
            runtime.block_on(future)
        })
        .map_err(|e| classify(TlsErrorKind::Network, &format!("上行线程创建失败: {e}")))?;
    handle.join().map_err(|_| classify(TlsErrorKind::Network, "上行线程 panic（不携带凭据）"))?
}

/// 建立连接 → 可选 TLS 握手 → 发 HTTP/1.1 POST → 读响应。
async fn exchange(
    endpoint: &str,
    body: &str,
    token: Option<&str>,
    agent_id: Option<&str>,
    config: Option<Arc<ClientConfig>>,
    allow_insecure: bool,
) -> DomainResult<TlsResponse> {
    let parsed = TlsEndpoint::parse(endpoint)?;
    let stream = tokio::net::TcpStream::connect((parsed.host.as_str(), parsed.port))
        .await
        .map_err(|e| classify(TlsErrorKind::Network, &format!("连接 {}:{} 失败: {e}", parsed.host, parsed.port)))?;
    let _ = stream.set_nodelay(true);
    if !parsed.tls {
        return plaintext_exchange(stream, &parsed, body, token, agent_id).await;
    }
    let config =
        config.ok_or_else(|| classify(TlsErrorKind::Config, "缺少 TLS 客户端配置（客户端证书/信任锚未装配）"))?;
    if allow_insecure {
        tracing::warn!(host = %parsed.host, "mTLS 客户端以跳过证书链校验的方式连接（仅排障）");
    }
    let server_name = TlsMaterial::server_name(&parsed.host)?;
    let connector = TlsConnector::from(config);
    let mut tls = connector.connect(server_name, stream).await.map_err(|e| io_error(&e, "握手失败"))?;
    let (protocol, cipher) = {
        let (_, session) = tls.get_ref();
        (
            session.protocol_version().map(|v| format!("{v:?}")),
            session.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())),
        )
    };
    let request = build_request(&parsed, body, token, agent_id);
    tls.write_all(request.as_bytes()).await.map_err(|e| io_error(&e, "写入请求失败"))?;
    tls.flush().await.map_err(|e| io_error(&e, "刷新请求失败"))?;
    let bytes = read_response_bytes(&mut tls).await?;
    let mut response = parse_response(&bytes)?;
    response.protocol = protocol;
    response.cipher = cipher;
    Ok(response)
}

/// 明文 HTTP（`http://`）：与 TLS 路径同一条请求/响应实现。
async fn plaintext_exchange(
    mut stream: tokio::net::TcpStream,
    parsed: &TlsEndpoint,
    body: &str,
    token: Option<&str>,
    agent_id: Option<&str>,
) -> DomainResult<TlsResponse> {
    let request = build_request(parsed, body, token, agent_id);
    stream.write_all(request.as_bytes()).await.map_err(|e| io_error(&e, "写入请求失败"))?;
    stream.flush().await.map_err(|e| io_error(&e, "刷新请求失败"))?;
    let bytes = read_response_bytes(&mut stream).await?;
    parse_response(&bytes)
}

/// 把 rustls/IO 错误归类（**不回显证书内容**），读写与握手共用。
///
/// 服务端要求客户端证书而本端没有配置时，rustls 报的是 fatal alert
/// `CertificateRequired`（TLS 1.3 下它可能在**首次读**时才出现，而不在 `connect` 里）；
/// 把它归到 [`TlsErrorKind::ClientCertMissing`]，让"配置漏了客户端证书"与"证书被拒"
/// 在日志/健康画像里可以一眼区分。
fn io_error(error: &std::io::Error, what: &str) -> DomainError {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("certificaterequired") {
        return classify(
            TlsErrorKind::ClientCertMissing,
            "服务端要求客户端证书，但本端未配置客户端证书（AGF_AGENT_TLS_CERT/_KEY）",
        );
    }
    let kind = if lower.contains("invalidcertificate") || lower.contains("certificate") {
        TlsErrorKind::Handshake
    } else {
        TlsErrorKind::Network
    };
    classify(kind, &format!("{what}: {text}"))
}

/// 构造 HTTP/1.1 请求（`Connection: close` 简化响应读取）。
fn build_request(parsed: &TlsEndpoint, body: &str, token: Option<&str>, agent_id: Option<&str>) -> String {
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nAccept: application/json\r\nConnection: close\r\n",
        parsed.target,
        parsed.host,
        parsed.port,
        body.len()
    );
    if let Some(token) = token {
        if token.starts_with("agf_") {
            request.push_str(&format!("X-AGF-Key: {token}\r\n"));
        } else {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
    }
    if let Some(agent_id) = agent_id {
        request.push_str(&format!("X-AGF-Agent-Id: {agent_id}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    request
}

/// 读取一条 HTTP/1.1 响应：先读到响应头结束，再按 `Content-Length` 补齐正文。
///
/// **为什么不读到 EOF**：读 EOF 要求服务端发 TLS `close_notify`；很多实现（包括本机
/// 进程内测试服务端）写完就关，会得到 `UnexpectedEof`。按 `Content-Length` 收满即返回，
/// 对服务端是否优雅关闭不作要求。
async fn read_response_bytes<S: AsyncReadExt + Unpin>(stream: &mut S) -> DomainResult<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0_u8; 16 * 1024];
    let mut head_end: Option<usize> = None;
    let mut want_total: Option<usize> = None;
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => out.extend_from_slice(&chunk[..read]),
            Err(error) => {
                // 已经收全正文时，服务端的粗暴断开不算错误
                if want_total.is_some_and(|total| out.len() >= total) {
                    break;
                }
                return Err(io_error(&error, "读取响应失败"));
            }
        }
        if out.len() > MAX_RESPONSE_BYTES {
            return Err(classify(TlsErrorKind::Http, "响应体超过 8 MiB 上限，已断开"));
        }
        if head_end.is_none() {
            if let Some(index) = find_head_end(&out) {
                head_end = Some(index);
                want_total = Some(index + content_length_of(&out[..index]));
            }
        }
        if let Some(total) = want_total {
            if out.len() >= total {
                break;
            }
        }
    }
    if head_end.is_none() && out.is_empty() {
        return Err(classify(TlsErrorKind::Http, "响应为空（对端未返回任何字节）"));
    }
    Ok(out)
}

/// 响应头结束位置（`\r\n\r\n` 之后）。
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4)
}

/// 从响应头里取 `Content-Length`（缺省 0 ⇒ 只等响应头）。
fn content_length_of(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// 解析 HTTP/1.1 响应（状态行 + 头 + body；支持 `chunked`）。
///
/// # Errors
/// 响应缺少状态行、状态码非法或分块编码损坏。
pub fn parse_response(bytes: &[u8]) -> DomainResult<TlsResponse> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| classify(TlsErrorKind::Http, "响应为空（无状态行）"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| classify(TlsErrorKind::Http, &format!("状态行非法: {status_line}")))?;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let body = if chunked { decode_chunked(body)? } else { body.to_string() };
    Ok(TlsResponse { status, body, protocol: None, cipher: None })
}

/// 解码 `Transfer-Encoding: chunked`。
fn decode_chunked(body: &str) -> DomainResult<String> {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, tail)) = rest.split_once("\r\n") {
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return Err(classify(TlsErrorKind::Http, &format!("分块长度非法: {size_text}")));
        };
        if size == 0 {
            break;
        }
        if tail.len() < size {
            return Err(classify(TlsErrorKind::Http, "分块数据被截断"));
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].strip_prefix("\r\n").unwrap_or(&tail[size..]);
    }
    Ok(out)
}

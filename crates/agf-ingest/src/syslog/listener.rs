//! Syslog 监听器：TCP（RFC6587 分帧）与 TLS（RFC5425，证书缺失只 warn 不监听）。

use super::*;

/// Syslog TCP 监听器（RFC6587 分帧，明文）。
///
/// **重要**：`accept_*` 只负责"接受一条连接"，收帧由 [`SyslogConnection::read_batch`]
/// 在连接生命周期内循环完成 —— 不要再引入"每连接最多 N 帧"的语义（历史缺陷：
/// 静默丢弃第 65 帧起的报文且不计失败，见 `tools/simulators/README.md` 第 7 节第 6 条）。
#[derive(Debug)]
pub struct SyslogTcpListener {
    listener: TcpListener,
}

impl SyslogTcpListener {
    /// 绑定监听地址（`0.0.0.0:5514`）。
    ///
    /// # Errors
    /// 地址非法或端口被占用。
    pub async fn bind(addr: &str) -> DomainResult<Self> {
        let listener = TcpListener::bind(addr).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "syslog-tcp".to_string(),
            cause: format!("绑定 {addr} 失败: {e}"),
        })?;
        debug!(addr, "Syslog TCP 监听已启动");
        Ok(Self { listener })
    }

    /// 实际监听地址（端口为 0 时用于取回内核分配端口）。
    ///
    /// # Errors
    /// 取本地地址失败。
    pub fn local_addr(&self) -> DomainResult<SocketAddr> {
        self.listener.local_addr().map_err(|e| DomainError::Internal(format!("读取监听地址失败: {e}")))
    }

    /// 接受一条连接（后续由调用方循环 [`SyslogConnection::read_batch`]）。
    ///
    /// # Errors
    /// 接受连接失败。
    pub async fn accept_connection(
        &self,
        max_message_bytes: usize,
        max_frames_per_read: usize,
        idle_timeout: Duration,
    ) -> DomainResult<(SyslogConnection<TcpStream>, SocketAddr)> {
        let (stream, peer) =
            self.listener.accept().await.map_err(|e| DomainError::Internal(format!("accept 失败: {e}")))?;
        let conn = SyslogConnection::new(stream, peer, max_message_bytes, max_frames_per_read, idle_timeout);
        Ok((conn, peer))
    }
}

/// Syslog over TLS 监听器（RFC5425）。
///
/// 证书链与私钥由调用方从 PEM 注入（PEM 解析在本模块内手写，只依赖 `base64`，
/// 不引入 `rustls-pemfile`）。**"永远可启动"策略**：证书/密钥非法时 [`Self::bind`]
/// 返回 [`DomainError::Config`]，由调用方决定"只 warn 不启用"，绝不让进程起不来。
pub struct SyslogTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for SyslogTlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TlsAcceptor 未实现 Debug（内含 rustls 配置），只打印监听地址。
        f.debug_struct("SyslogTlsListener")
            .field("listener", &self.listener)
            .field("acceptor", &"<tls-acceptor>")
            .finish()
    }
}

impl SyslogTlsListener {
    /// 绑定监听地址并构造 TLS 接受器（`cert_pem` / `key_pem` 为 PEM 字节）。
    ///
    /// # Errors
    /// - PEM 里没有可用证书/私钥，或证书与私钥不匹配 → [`DomainError::Config`]；
    /// - 地址非法或端口被占用 → [`DomainError::DependencyUnavailable`]。
    pub async fn bind(addr: &str, cert_pem: &[u8], key_pem: &[u8]) -> DomainResult<Self> {
        Self::bind_with_client_ca(addr, cert_pem, key_pem, None).await
    }

    /// Bind TLS with mandatory client verification when a PEM trust bundle is supplied.
    ///
    /// # Errors
    /// Invalid certificates, trust roots, key material or listener address.
    pub async fn bind_with_client_ca(
        addr: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        client_ca: Option<&[u8]>,
    ) -> DomainResult<Self> {
        let certs = parse_certificates(cert_pem)?;
        let key = parse_private_key(key_pem)?;
        // 显式指定 ring provider：与工作区 reqwest/rustls 的既有算法后端一致，
        // 避免"同时启用 aws-lc-rs 时 builder() 找不到默认 provider"的启动期 panic。
        let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| DomainError::Config(format!("TLS 协议版本配置失败: {e}")))?;
        let builder = if let Some(pem) = client_ca {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            for certificate in parse_certificates(pem)? {
                roots.add(certificate).map_err(|e| DomainError::Config(format!("Invalid client CA: {e}")))?;
            }
            let verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder_with_provider(
                std::sync::Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|e| DomainError::Config(format!("Invalid client trust store: {e}")))?;
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let config = builder
            .with_single_cert(certs, key)
            .map_err(|e| DomainError::Config(format!("TLS 服务端证书/私钥不可用: {e}")))?;
        let listener = TcpListener::bind(addr).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "syslog-tls".to_string(),
            cause: format!("绑定 {addr} 失败: {e}"),
        })?;
        debug!(addr, "Syslog TLS（RFC5425）监听已启动");
        Ok(Self { listener, acceptor: TlsAcceptor::from(std::sync::Arc::new(config)) })
    }

    /// 实际监听地址。
    ///
    /// # Errors
    /// 取本地地址失败。
    pub fn local_addr(&self) -> DomainResult<SocketAddr> {
        self.listener.local_addr().map_err(|e| DomainError::Internal(format!("读取监听地址失败: {e}")))
    }

    /// 接受一条 TLS 连接并完成握手。
    ///
    /// # Errors
    /// 接受连接失败或 TLS 握手失败（握手失败只影响该连接，不影响监听器）。
    pub async fn accept_connection(
        &self,
        max_message_bytes: usize,
        max_frames_per_read: usize,
        idle_timeout: Duration,
    ) -> DomainResult<(SyslogConnection<TlsFrameStream>, SocketAddr)> {
        self.accept_handshake().await?.complete(max_message_bytes, max_frames_per_read, idle_timeout).await
    }

    /// Accept the socket without waiting for TLS, so callers can bound concurrent handshakes.
    ///
    /// # Errors
    /// The listening socket failed to accept a connection.
    pub async fn accept_handshake(&self) -> DomainResult<SyslogTlsHandshake> {
        let (stream, peer) =
            self.listener.accept().await.map_err(|e| DomainError::Internal(format!("accept 失败: {e}")))?;
        Ok(SyslogTlsHandshake { stream, peer, acceptor: self.acceptor.clone() })
    }
}

/// Pending TLS negotiation. Drop it to reject an excess connection before cryptographic work.
pub struct SyslogTlsHandshake {
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for SyslogTlsHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogTlsHandshake").field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl SyslogTlsHandshake {
    /// Complete verification with a ten second deadline.
    ///
    /// # Errors
    /// The certificate is untrusted, absent when required, or the handshake fails/times out.
    pub async fn complete(
        self,
        max_message_bytes: usize,
        max_frames_per_read: usize,
        idle_timeout: Duration,
    ) -> DomainResult<(SyslogConnection<TlsFrameStream>, SocketAddr)> {
        let peer = self.peer;
        let tls =
            tokio::time::timeout(Duration::from_secs(10), self.acceptor.accept(FinHidingStream::new(self.stream)))
                .await
                .map_err(|_| DomainError::Validation("Syslog TLS handshake timed out".into()))?
                .map_err(|e| DomainError::Validation(format!("TLS 握手失败（{peer}）: {e}")))?;
        let mutual_tls = tls.get_ref().1.peer_certificates().is_some_and(|certificates| !certificates.is_empty());
        let mut conn =
            SyslogConnection::new(TlsFrameStream::new(tls), peer, max_message_bytes, max_frames_per_read, idle_timeout);
        conn.mutual_tls = mutual_tls;
        Ok((conn, peer))
    }
}

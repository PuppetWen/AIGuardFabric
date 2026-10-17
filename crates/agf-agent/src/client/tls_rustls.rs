//! mTLS 材料读取与 rustls `ClientConfig` 装配（客户端身份的唯一来源）。
//!
//! 刻意**不**复用 `reqwest` 的 `Identity`：那条路径无法表达"跳过校验"，也无法把
//! 客户端证书当作**可检查的身份对象**（subject/SAN）。这里直接用 rustls 装配，
//! 既满足"证书即身份"，也让传输层的失败可分类（见 [`super::TlsErrorKind`]）。

use std::fs;
use std::sync::Arc;

use agf_core::error::{DomainError, DomainResult};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::{TlsConfig, TlsErrorKind, TlsMode};

/// 已读取的 TLS 材料（PEM 字节）。`Debug` 刻意隐藏私钥内容。
#[derive(Default)]
pub struct TlsMaterial {
    /// 客户端证书链（DER）。
    pub client_certs: Vec<CertificateDer<'static>>,
    /// 客户端私钥（**绝不进日志/Debug**）。
    pub client_key: Option<PrivateKeyDer<'static>>,
    /// 服务端校验 CA（DER；空 ⇒ 用内置公共根）。
    pub ca_certs: Vec<CertificateDer<'static>>,
    /// 跳过服务端证书链校验。
    pub insecure_skip_verify: bool,
}

impl Clone for TlsMaterial {
    fn clone(&self) -> Self {
        // `PrivateKeyDer` 不是 `Clone`（私钥副本必须显式声明），用其官方的 `clone_key()`。
        Self {
            client_certs: self.client_certs.clone(),
            client_key: self.client_key.as_ref().map(PrivateKeyDer::clone_key),
            ca_certs: self.ca_certs.clone(),
            insecure_skip_verify: self.insecure_skip_verify,
        }
    }
}

impl std::fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("client_certs", &format!("<{} cert(s):redacted>", self.client_certs.len()))
            .field("client_key", &if self.client_key.is_some() { "<PRIVATE KEY:REDACTED>" } else { "none" })
            .field("ca_certs", &format!("<{} CA cert(s)>", self.ca_certs.len()))
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

impl TlsConfig {
    /// 读取 PEM 文件并解析成 TLS 材料。
    ///
    /// # Errors
    /// 组合非法（见 [`TlsConfig::validate`]）、文件不存在/不可读、PEM 无内容或解析失败。
    pub fn load(&self) -> DomainResult<TlsMaterial> {
        let _ = self.validate(None)?;
        let client_certs = match &self.client_cert_pem {
            Some(path) => parse_certs(&read_file(path)?, "客户端证书")?,
            None => Vec::new(),
        };
        let client_key = match &self.client_key_pem {
            Some(path) => Some(parse_key(&read_file(path)?)?),
            None => None,
        };
        let ca_certs = match &self.ca_pem {
            Some(path) => parse_certs(&read_file(path)?, "CA 证书")?,
            None => Vec::new(),
        };
        Ok(TlsMaterial { client_certs, client_key, ca_certs, insecure_skip_verify: self.insecure_skip_verify })
    }
}

impl TlsMaterial {
    /// 装配 rustls 客户端配置。
    ///
    /// * 提供 CA ⇒ 只信任该 CA；未提供 ⇒ 内置 `webpki-roots` 公共根证书；
    /// * 提供客户端证书 + 私钥 ⇒ mTLS（证书/私钥不匹配 ⇒ `KeyMismatch`）；
    /// * `insecure_skip_verify` ⇒ 自定义校验器接受任意服务端证书（调用方已 `warn!`）。
    ///
    /// # Errors
    /// rustls 协议版本/信任锚/客户端身份装配失败。
    pub fn client_config(&self) -> DomainResult<Arc<rustls::ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        if self.ca_certs.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            let added = roots.add_parsable_certificates(self.ca_certs.clone());
            if added.0 == 0 {
                return Err(DomainError::Config("TLS：CA 文件中没有可用的证书".to_string()));
            }
            tracing::debug!(added = added.0, ignored = added.1, "TLS 信任锚已装配");
        }
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| DomainError::Config(format!("TLS：rustls 协议版本配置失败: {e}")))?;
        // 「跳过校验」必须在装入信任锚**之前**替换校验器（rustls 的类型状态如此约束）
        let builder = if self.insecure_skip_verify {
            builder.dangerous().with_custom_certificate_verifier(Arc::new(SkipServerVerification::new(provider)))
        } else {
            builder.with_root_certificates(roots)
        };
        let config = match &self.client_key {
            Some(key) if !self.client_certs.is_empty() => {
                builder.with_client_auth_cert(self.client_certs.clone(), key.clone_key()).map_err(|_| {
                    // **不回显 rustls 的原始错误文本**：其中可能含证书/私钥派生的细节。
                    DomainError::Config("TLS：客户端证书与私钥不匹配（KeyMismatch）".to_string())
                })?
            }
            _ => builder.with_no_client_auth(),
        };
        Ok(Arc::new(config))
    }

    /// 由服务端地址推导 [`ServerName`]（用于 TLS SNI 与主机名校验）。
    ///
    /// # Errors
    /// URL 无法解析出主机名。
    pub fn server_name(host: &str) -> DomainResult<ServerName<'static>> {
        ServerName::try_from(host.trim().to_string())
            .map_err(|_| DomainError::Config(format!("TLS：服务端主机名非法（{host}）")))
    }
}

/// 读取 PEM 文件（**错误信息只含路径，不含内容**）。
fn read_file(path: &std::path::Path) -> DomainResult<Vec<u8>> {
    fs::read(path).map_err(|e| {
        // 只报 path + 错误种类：`e` 不会包含文件内容
        DomainError::Config(format!("TLS：PEM 文件不可读（{}）：{e}", path.display()))
    })
}

/// 解析 PEM 证书链。
///
/// # Errors
/// PEM 解析失败、没有证书或证书内容为空。
pub fn parse_certs(pem: &[u8], what: &str) -> DomainResult<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DomainError::Config(format!("TLS：{what} PEM 解析失败（PemInvalid）")))?;
    if certs.is_empty() {
        return Err(DomainError::Config(format!("TLS：{what} PEM 中没有证书")));
    }
    // `rustls-pemfile` 对 `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----` 会产出
    // 一个**空 DER** 的条目（长度 0）；那种"看着有证书其实没有"的输入必须当场拒绝，
    // 否则会在握手阶段变成一个难以定位的 UnknownIssuer。
    if certs.iter().any(|cert| cert.as_ref().is_empty()) {
        return Err(DomainError::Config(format!("TLS：{what} PEM 中证书为空（0 字节 DER）")));
    }
    Ok(certs)
}

/// 解析 PEM 私钥（PKCS#8 / PKCS#1 / SEC1）。
///
/// # Errors
/// PEM 解析失败或没有私钥。
pub fn parse_key(pem: &[u8]) -> DomainResult<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|_| DomainError::Config("TLS：客户端私钥 PEM 解析失败（PemInvalid）".to_string()))?
        .ok_or_else(|| DomainError::Config("TLS：客户端私钥 PEM 中没有私钥（支持 PKCS#8/PKCS#1/SEC1）".to_string()))?;
    if key.secret_der().is_empty() {
        return Err(DomainError::Config("TLS：客户端私钥 PEM 中私钥为空（0 字节 DER）".to_string()));
    }
    Ok(key)
}

/// 由错误文本/分类构造**不含凭据**的上行错误。
#[must_use]
pub fn classify(kind: TlsErrorKind, what: &str) -> DomainError {
    match kind {
        TlsErrorKind::Handshake => DomainError::Unauthenticated(format!("mTLS 握手失败：{what}")),
        TlsErrorKind::ClientCertMissing => {
            DomainError::Unauthenticated(format!("{}：{what}", super::CLIENT_CERT_MISSING_PREFIX))
        }
        TlsErrorKind::Network => DomainError::DependencyUnavailable {
            dependency: "agf-server".to_string(),
            cause: format!("TLS 上行失败：{what}"),
        },
        TlsErrorKind::Http => DomainError::DependencyUnavailable {
            dependency: "agf-server".to_string(),
            cause: format!("上行被服务端拒绝：{what}"),
        },
        TlsErrorKind::KeyMismatch | TlsErrorKind::BadPem | TlsErrorKind::MissingFile | TlsErrorKind::Config => {
            DomainError::Config(format!("mTLS 配置错误（{}）：{what}", kind.as_str()))
        }
    }
}

/// `AGF_AGENT_TLS_INSECURE_SKIP_VERIFY` 时才装配的校验器：接受任意服务端证书
/// （**签名仍按 rustls 算法校验**，只是不验证信任链与主机名）。
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self(provider)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 模式 → 是否需要真实 TLS 传输（`Plaintext` 走明文实现）。
#[must_use]
pub const fn needs_tls(mode: TlsMode) -> bool {
    mode.is_tls()
}

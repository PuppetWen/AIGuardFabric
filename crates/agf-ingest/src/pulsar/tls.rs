//! 原生 Pulsar 的 TLS/mTLS 装配（`pulsar+ssl://`）：rustls 客户端配置 + 可选的"跳过校验"。
//!
//! 与 [`crate::mqtt::tls`] 同一套原语（rustls ring provider + `rustls-pemfile`），
//! 但**独立成文件**：Pulsar 侧的信任锚、mTLS 与排障开关互不影响 MQTT/Syslog 的既有行为。
//!
//! 语义：
//! * 给了 `AGF_INGEST_PULSAR_TLS_CA` ⇒ **只**信任该 CA（自签 CA 场景）；
//! * 没给 CA ⇒ 用内置 webpki 公共根证书；
//! * 给了 `..._TLS_CERT` + `..._TLS_KEY` ⇒ mTLS（`config.validate()` 已保证成对）；
//! * `..._TLS_INSECURE_SKIP_VERIFY=1` ⇒ 接受任意服务端证书（调用方必须先 `warn!`）。

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use super::config::ConfigError;

/// 读取 PEM 里**全部**证书。
fn parse_certs(pem: &[u8], what: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, ConfigError> {
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ConfigError::IncompleteTls(format!("{what} PEM 解析失败: {e}")))?;
    if certs.is_empty() {
        return Err(ConfigError::IncompleteTls(format!("{what} PEM 中没有证书")));
    }
    Ok(certs)
}

/// 读取 PEM 私钥（PKCS#8 / PKCS#1 / SEC1）。
fn parse_private_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, ConfigError> {
    rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|e| ConfigError::IncompleteTls(format!("客户端私钥 PEM 解析失败: {e}")))?
        .ok_or_else(|| ConfigError::IncompleteTls("客户端私钥 PEM 中没有私钥".to_string()))
}

/// `pulsar+ssl://` 的 rustls 客户端配置来源（**只持有路径**，读取在 [`build_client_config`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulsarTlsPlan {
    /// CA 证书（PEM 路径）；`None` ⇒ webpki 公共根。
    pub ca_pem: Option<std::path::PathBuf>,
    /// 客户端证书（mTLS）。
    pub client_cert_pem: Option<std::path::PathBuf>,
    /// 客户端私钥（mTLS）。
    pub client_key_pem: Option<std::path::PathBuf>,
    /// 跳过证书链校验（仅排障）。
    pub insecure_skip_verify: bool,
}

/// 读文件（失败即配置错误——TLS 材料缺失不能静默降级成明文）。
fn read(path: &std::path::Path, what: &str) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(path).map_err(|e| ConfigError::IncompleteTls(format!("{what} {} 读取失败: {e}", path.display())))
}

/// 装配 rustls `ClientConfig`。
///
/// # Errors
/// PEM 不可读/解析失败、证书与私钥不匹配、rustls 协议版本配置失败。
pub fn build_client_config(plan: &PulsarTlsPlan) -> Result<Arc<rustls::ClientConfig>, ConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    match &plan.ca_pem {
        Some(path) => {
            let pem = read(path, "CA 证书")?;
            let certs = parse_certs(&pem, "CA 证书")?;
            let added = roots.add_parsable_certificates(certs);
            if added.0 == 0 {
                return Err(ConfigError::IncompleteTls("CA 文件里没有可用证书".to_string()));
            }
            tracing::debug!(added = added.0, ignored = added.1, "Pulsar TLS 信任锚已装配");
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ConfigError::IncompleteTls(format!("rustls 协议版本配置失败: {e}")))?;
    let builder = if plan.insecure_skip_verify {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(SkipServerVerification::new(provider)))
    } else {
        builder.with_root_certificates(roots)
    };
    let config = match (&plan.client_cert_pem, &plan.client_key_pem) {
        (Some(cert_path), Some(key_path)) => {
            let certs = parse_certs(&read(cert_path, "客户端证书")?, "客户端证书")?;
            let key = parse_private_key(&read(key_path, "客户端私钥")?)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| ConfigError::IncompleteTls(format!("客户端证书/私钥不匹配: {e}")))?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// 把一条已建好的 TCP 流升级成 TLS（`pulsar+ssl://`）。
///
/// # Errors
/// rustls 配置失败或 TLS 握手失败（含 SNI 非法）。
pub async fn upgrade<S>(
    stream: S,
    plan: &PulsarTlsPlan,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<S>, ConfigError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = build_client_config(plan)?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| ConfigError::IncompleteTls(format!("SNI 主机名 {host:?} 非法: {e}")))?;
    TlsConnector::from(config)
        .connect(server_name, stream)
        .await
        .map_err(|e| ConfigError::IncompleteTls(format!("TLS 握手失败: {e}")))
}

/// `AGF_INGEST_PULSAR_TLS_INSECURE_SKIP_VERIFY=1` 时才装配的校验器：
/// 接受任意服务端证书（签名算法仍由 rustls 校验，只是不验证信任链/主机名）。
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
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 一个满足 `AsyncRead + AsyncWrite` 的流对象别名（明文 TCP 与 TLS 共用读取循环）。
pub trait PulsarStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> PulsarStream for T {}

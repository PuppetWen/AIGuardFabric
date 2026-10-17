//! MQTT over TLS（`mqtts://`）：`AGF_INGEST_MQTT_TLS*` 环境开关、CA/客户端证书/私钥装配与（显式）跳过校验。

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

use super::*;

/// 环境变量：TLS 总开关。
pub const ENV_TLS: &str = "AGF_INGEST_MQTT_TLS";
/// 环境变量：CA 证书 PEM 路径。
pub const ENV_TLS_CA: &str = "AGF_INGEST_MQTT_TLS_CA";
/// 环境变量：客户端证书 PEM 路径（mTLS）。
pub const ENV_TLS_CERT: &str = "AGF_INGEST_MQTT_TLS_CERT";
/// 环境变量：客户端私钥 PEM 路径（mTLS）。
pub const ENV_TLS_KEY: &str = "AGF_INGEST_MQTT_TLS_KEY";
/// 环境变量：跳过证书链校验（**必须显式开启**）。
pub const ENV_TLS_INSECURE_SKIP_VERIFY: &str = "AGF_INGEST_MQTT_TLS_INSECURE_SKIP_VERIFY";

/// MQTT over TLS 配置（**引用 PEM 文件路径**，真正读取在 [`Self::load`]）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MqttTlsConfig {
    /// 是否启用 TLS（`AGF_INGEST_MQTT_TLS=1` 或 broker 用 `mqtts://`）。
    pub enabled: bool,
    /// CA 证书（PEM 文件路径）；`None` ⇒ 用内置 webpki 公共根证书。
    pub ca_pem: Option<PathBuf>,
    /// 客户端证书链（PEM 文件路径）；与 [`Self::client_key_pem`] 必须成对出现。
    pub client_cert_pem: Option<PathBuf>,
    /// 客户端私钥（PEM 文件路径）。
    pub client_key_pem: Option<PathBuf>,
    /// 跳过服务端证书链校验（仅排障；默认 `false` = 校验证书链）。
    pub insecure_skip_verify: bool,
}

impl MqttTlsConfig {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取（单测注入用）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            enabled: flag(&lookup, ENV_TLS, false),
            ca_pem: path(&lookup, ENV_TLS_CA),
            client_cert_pem: path(&lookup, ENV_TLS_CERT),
            client_key_pem: path(&lookup, ENV_TLS_KEY),
            insecure_skip_verify: flag(&lookup, ENV_TLS_INSECURE_SKIP_VERIFY, false),
        }
    }

    /// scheme 声明了 TLS（`mqtts://`）时启用（与 `AGF_INGEST_MQTT_TLS` 取或）。
    #[must_use]
    pub fn for_scheme(mut self, endpoint: &MqttEndpoint) -> Self {
        if endpoint.tls {
            self.enabled = true;
        }
        self
    }

    /// 校验组合合法性（mTLS 证书/私钥必须成对；跳过校验必须 `warn!`）。
    ///
    /// # Errors
    /// 只提供了证书或只提供了私钥。
    pub fn validate(&self) -> DomainResult<()> {
        if self.client_cert_pem.is_some() != self.client_key_pem.is_some() {
            return Err(DomainError::Config(format!(
                "MQTT mTLS 配置不完整：{ENV_TLS_CERT} 与 {ENV_TLS_KEY} 必须同时提供（当前只给了其中一个）"
            )));
        }
        if self.enabled && self.insecure_skip_verify {
            warn!(
                ca = ?self.ca_pem,
                "MQTT TLS：{ENV_TLS_INSECURE_SKIP_VERIFY}=1 —— 服务端证书链校验被关闭，仅可用于排障，生产环境必须关闭"
            );
        }
        Ok(())
    }

    /// 读取 PEM 文件，得到可装配的 TLS 材料。
    ///
    /// # Errors
    /// 组合非法（见 [`Self::validate`]）或 PEM 文件不可读/为空。
    pub fn load(&self) -> DomainResult<MqttTlsMaterial> {
        self.validate()?;
        Ok(MqttTlsMaterial {
            ca_pem: read_pem(self.ca_pem.as_deref(), ENV_TLS_CA)?,
            client_cert_pem: read_pem(self.client_cert_pem.as_deref(), ENV_TLS_CERT)?,
            client_key_pem: read_pem(self.client_key_pem.as_deref(), ENV_TLS_KEY)?,
            insecure_skip_verify: self.insecure_skip_verify,
        })
    }

    /// 人读描述（`/readyz` 的 notes 用；**不含任何密钥内容**）。
    #[must_use]
    pub fn describe(&self) -> String {
        if !self.enabled {
            // 措辞刻意涵盖两种明文传输：`mqtt://`（TCP）与 `ws://`（WebSocket）
            return "明文（未启用 TLS：TCP 与 WebSocket 均不加密）".to_string();
        }
        let trust = match &self.ca_pem {
            Some(path) => format!("CA={}", path.display()),
            None => "CA=系统/内置公共根证书(webpki)".to_string(),
        };
        let mtls = if self.client_cert_pem.is_some() { "，mTLS=开启" } else { "" };
        let insecure = if self.insecure_skip_verify { "，**证书链校验已跳过**" } else { "，校验证书链" };
        format!("TLS（{trust}{mtls}{insecure}）")
    }
}

/// 已读取的 TLS 材料（PEM 字节）。`Debug` 刻意隐藏私钥内容。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MqttTlsMaterial {
    /// CA 证书 PEM（`None` ⇒ 用内置 webpki 公共根）。
    pub ca_pem: Option<Vec<u8>>,
    /// 客户端证书链 PEM。
    pub client_cert_pem: Option<Vec<u8>>,
    /// 客户端私钥 PEM（**绝不进日志/指标/Debug**）。
    pub client_key_pem: Option<Vec<u8>>,
    /// 跳过证书链校验。
    pub insecure_skip_verify: bool,
}

impl std::fmt::Debug for MqttTlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttTlsMaterial")
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "<PEM:redacted>"))
            .field("client_cert_pem", &self.client_cert_pem.as_ref().map(|_| "<PEM:redacted>"))
            .field("client_key_pem", &self.client_key_pem.as_ref().map(|_| "<PEM:REDACTED>"))
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

impl MqttTlsMaterial {
    /// 装配 `rumqttc` 传输层（rustls）。
    ///
    /// * 提供 CA ⇒ 只信任该 CA；未提供 ⇒ 用内置 webpki 公共根证书；
    /// * 提供客户端证书/私钥 ⇒ mTLS；
    /// * `insecure_skip_verify` ⇒ 自定义校验器**接受任意服务端证书**（调用方必须先 `warn!`）。
    ///
    /// # Errors
    /// PEM 解析失败、证书/私钥缺失或 rustls 配置失败。
    pub fn transport(&self) -> DomainResult<Transport> {
        Ok(Transport::Tls(TlsConfiguration::Rustls(self.rustls_config()?)))
    }

    /// 底层 rustls `ClientConfig`（TCP+TLS 与 **WSS** 共用同一份信任锚/客户端证书装配）。
    ///
    /// # Errors
    /// PEM 解析失败、证书/私钥缺失或 rustls 配置失败。
    pub fn rustls_config(&self) -> DomainResult<Arc<rustls::ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        match &self.ca_pem {
            Some(pem) => {
                let certs = parse_certs(pem, "CA")?;
                let added = roots.add_parsable_certificates(certs);
                if added.0 == 0 {
                    return Err(DomainError::Config("MQTT TLS：CA 文件中没有可用的证书".to_string()));
                }
                debug!(added = added.0, ignored = added.1, "MQTT TLS 信任锚已装配");
            }
            None => {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
        }
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| DomainError::Config(format!("MQTT TLS：rustls 协议版本配置失败: {e}")))?;
        // 「跳过校验」必须在装入信任锚**之前**替换校验器（rustls 的类型状态如此约束）
        let builder = if self.insecure_skip_verify {
            builder.dangerous().with_custom_certificate_verifier(Arc::new(SkipServerVerification::new(provider)))
        } else {
            builder.with_root_certificates(roots)
        };
        let config = match (&self.client_cert_pem, &self.client_key_pem) {
            (Some(cert_pem), Some(key_pem)) => {
                let certs = parse_certs(cert_pem, "客户端证书")?;
                let key = parse_private_key(key_pem)?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| DomainError::Config(format!("MQTT TLS：客户端证书/私钥不匹配: {e}")))?
            }
            _ => builder.with_no_client_auth(),
        };
        Ok(Arc::new(config))
    }
}

/// 解析 PEM 证书链。
fn parse_certs(pem: &[u8], what: &str) -> DomainResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DomainError::Config(format!("MQTT TLS：{what} PEM 解析失败: {e}")))?;
    if certs.is_empty() {
        return Err(DomainError::Config(format!("MQTT TLS：{what} PEM 中没有证书")));
    }
    Ok(certs)
}

/// 解析 PEM 私钥。
fn parse_private_key(pem: &[u8]) -> DomainResult<rustls::pki_types::PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|e| DomainError::Config(format!("MQTT TLS：客户端私钥 PEM 解析失败: {e}")))?
        .ok_or_else(|| {
            DomainError::Config("MQTT TLS：客户端私钥 PEM 中没有私钥（支持 PKCS#8/PKCS#1/SEC1）".to_string())
        })
}

/// `AGF_INGEST_MQTT_TLS_INSECURE_SKIP_VERIFY=1` 时才装配的证书校验器：
/// 接受任意服务端证书（**签名仍按 rustls 算法校验**，只是不验证信任链/主机名）。
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

// ---------------------------------------------------------------------------
// 遗嘱消息（LWT）
// ---------------------------------------------------------------------------

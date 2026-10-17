//! Kafka 安全配置：SASL 机制与凭据脱敏（PLAIN/SCRAM）、TLS（rustls）信任库装配，含显式的"跳过校验"开关。

use super::*;

/// SASL 机制（Kafka 服务端与 KoP 均支持）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum KafkaSaslMechanism {
    /// `SASL/PLAIN`（KoP 的 token 鉴权走此机制）。
    #[default]
    Plain,
    /// `SASL/SCRAM-SHA-256`。
    ScramSha256,
    /// `SASL/SCRAM-SHA-512`。
    ScramSha512,
}

impl KafkaSaslMechanism {
    /// 解析文本（大小写不敏感；`SCRAM-SHA-256` / `SCRAM_SHA_256` / `scram256` 均可）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized = text.trim().to_ascii_uppercase().replace('_', "-");
        match normalized.as_str() {
            "PLAIN" => Some(Self::Plain),
            "SCRAM-SHA-256" | "SCRAM256" | "SCRAM-SHA256" => Some(Self::ScramSha256),
            "SCRAM-SHA-512" | "SCRAM512" | "SCRAM-SHA512" => Some(Self::ScramSha512),
            _ => None,
        }
    }

    /// Kafka 的机制名（与 broker 配置一致）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

/// SASL 凭据。
///
/// **安全约定**：`password` 只能来自环境变量/settings；本类型的 `Debug` 输出、
/// [`Self::redacted`] 与错误文本一律以 `<redacted>` 占位——任何日志、`/readyz`、
/// `/stats`、`/metrics` 都不可能拿到明文（明文只在建连瞬间由 [`Self::to_rskafka`] 取用）。
#[derive(Clone, PartialEq, Eq)]
pub struct KafkaSaslConfig {
    /// 机制。
    pub mechanism: KafkaSaslMechanism,
    /// 用户名（KoP token 鉴权时固定为 `token`）。
    pub username: String,
    /// 口令 / Pulsar token（**绝不进日志**）。
    password: String,
}

impl KafkaSaslConfig {
    /// 构造。
    #[must_use]
    pub fn new(mechanism: KafkaSaslMechanism, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self { mechanism, username: username.into(), password: password.into() }
    }

    /// 口令（仅供建连使用；**调用方不得写入日志/错误文本/响应体**）。
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// 可日志描述（口令占位）。
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("SASL {} user={} password=<redacted>", self.mechanism.as_str(), self.username)
    }

    /// 转换为 `rskafka` 的 SASL 配置（唯一取用明文口令的出口）。
    #[must_use]
    pub fn to_rskafka(&self) -> rskafka::client::SaslConfig {
        let credentials = rskafka::client::Credentials::new(self.username.clone(), self.password.clone());
        match self.mechanism {
            KafkaSaslMechanism::Plain => rskafka::client::SaslConfig::Plain(credentials),
            KafkaSaslMechanism::ScramSha256 => rskafka::client::SaslConfig::ScramSha256(credentials),
            KafkaSaslMechanism::ScramSha512 => rskafka::client::SaslConfig::ScramSha512(credentials),
        }
    }
}

impl std::fmt::Debug for KafkaSaslConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaSaslConfig")
            .field("mechanism", &self.mechanism)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// TLS 配置（PEM 路径 + 是否跳过校验）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaTlsConfig {
    /// 私有 CA（PEM）；与内置 webpki 公共根一起构成信任库。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<PathBuf>,
    /// 客户端证书链（PEM，双向 TLS）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_pem: Option<PathBuf>,
    /// 客户端私钥（PEM）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_pem: Option<PathBuf>,
    /// **跳过证书链校验**（默认 `false`；仅显式开关且必 `warn!`）。
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

impl KafkaTlsConfig {
    /// 可日志描述（不含私钥内容）。
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = vec!["TLS(证书链校验开启)".to_string()];
        if let Some(ca) = &self.ca_pem {
            parts.push(format!("ca={}", ca.display()));
        }
        if self.client_cert_pem.is_some() && self.client_key_pem.is_some() {
            parts.push("mTLS".to_string());
        }
        if self.insecure_skip_verify {
            parts.push("**证书链校验已关闭（insecure_skip_verify）**".to_string());
        }
        parts.join(",")
    }

    /// 构造 `rustls` 客户端配置（rustls 0.23 + ring provider，与 workspace 同版本栈）。
    ///
    /// # Errors
    /// CA/客户端证书/私钥文件不可读、PEM 非法、无可用客户端证书与私钥组合。
    pub fn build_client_config(&self) -> DomainResult<Arc<rustls::ClientConfig>> {
        use rustls::pki_types::pem::PemObject as _;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca_path) = &self.ca_pem {
            let certs = CertificateDer::pem_file_iter(ca_path)
                .map_err(|e| tls_err(format!("读取 Kafka TLS CA {} 失败: {e}", ca_path.display())))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| tls_err(format!("解析 Kafka TLS CA {} 失败: {e}", ca_path.display())))?;
            if certs.is_empty() {
                return Err(tls_err(format!("Kafka TLS CA {} 不含任何证书", ca_path.display())));
            }
            for cert in certs {
                roots.add(cert).map_err(|e| tls_err(format!("Kafka TLS CA {} 证书非法: {e}", ca_path.display())))?;
            }
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_err(format!("初始化 TLS 协议版本失败: {e}")))?;

        let mut config = match (&self.client_cert_pem, &self.client_key_pem) {
            (Some(cert_path), Some(key_path)) => {
                let certs = CertificateDer::pem_file_iter(cert_path)
                    .map_err(|e| tls_err(format!("读取 Kafka TLS 客户端证书 {} 失败: {e}", cert_path.display())))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| tls_err(format!("解析 Kafka TLS 客户端证书 {} 失败: {e}", cert_path.display())))?;
                let key = PrivateKeyDer::from_pem_file(key_path)
                    .map_err(|e| tls_err(format!("读取 Kafka TLS 客户端私钥 {} 失败: {e}", key_path.display())))?;
                builder
                    .with_root_certificates(roots)
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| tls_err(format!("加载客户端证书失败: {e}")))?
            }
            (None, None) => builder.with_root_certificates(roots).with_no_client_auth(),
            _ => {
                return Err(DomainError::Config(
                    "Kafka TLS：AGF_INGEST_KAFKA_TLS_CERT 与 AGF_INGEST_KAFKA_TLS_KEY 必须成对配置".to_string(),
                ));
            }
        };

        if self.insecure_skip_verify {
            warn!("Kafka TLS：insecure_skip_verify 已启用——证书链校验被关闭，仅可用于排障，生产环境必须关闭");
            config.dangerous().set_certificate_verifier(Arc::new(InsecureSkipVerify));
        }
        Ok(Arc::new(config))
    }
}

/// 组合的安全配置（SASL + TLS）。
#[derive(Debug, Clone, Default)]
pub struct KafkaSecurity {
    /// SASL（`None` = 匿名）。
    pub sasl: Option<KafkaSaslConfig>,
    /// TLS（`None` = 明文）。
    pub tls: Option<KafkaTlsConfig>,
}

impl KafkaSecurity {
    /// 由拉取配置提取。
    #[must_use]
    pub fn from_config(config: &KafkaPullConfig) -> Self {
        Self { sasl: config.sasl.clone(), tls: config.tls.clone() }
    }

    /// 可日志描述（**不含任何凭据**）。
    #[must_use]
    pub fn describe(&self) -> String {
        let sasl = self.sasl.as_ref().map_or_else(|| "SASL 关闭".to_string(), KafkaSaslConfig::redacted);
        let tls = self.tls.as_ref().map_or("TLS 关闭".to_string(), KafkaTlsConfig::describe);
        format!("{sasl}；{tls}")
    }
}

/// TLS 配置错误。
fn tls_err(message: String) -> DomainError {
    DomainError::Config(format!("Kafka {message}"))
}

/// 跳过校验的 `ServerCertVerifier`（**只在显式开关下装配**）。
#[derive(Debug)]
struct InsecureSkipVerify;

impl rustls::client::danger::ServerCertVerifier for InsecureSkipVerify {
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
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// 数据源
// ---------------------------------------------------------------------------

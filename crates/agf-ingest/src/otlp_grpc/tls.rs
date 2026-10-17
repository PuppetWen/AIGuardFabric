//! OTLP/gRPC 端口**自身**的 TLS/mTLS：`AGF_INGEST_OTLP_GRPC_TLS*` 环境开关、模式判定
//! 与 `tonic` 的 [`ServerTlsConfig`] 装配（rustls）。
//!
//! ## 启动行为
//!
//! 默认不配置 TLS 时使用明文。指定 TLS 或证书/CA 后，配置必须完整且通过校验；
//! 无效配置使本接收器拒绝启动，不允许自动回退明文。其他协议接收器继续运行。
//! `/readyz` 的 notes 记录失败原因，错误中不包含密钥材料。
//!
//! ## mTLS
//!
//! `AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA` 一旦配置（且 TLS 已启用）即走 mTLS：
//! tonic 的 `client_ca_root` 会装 `WebPkiClientVerifier`（`client_auth_optional` 默认 `false`），
//! **不带客户端证书的握手会被拒**，而不是"可选校验"。
//!
//! ## 环境变量
//!
//! | 变量 | 默认 | 说明 |
//! |---|---|---|
//! | `AGF_INGEST_OTLP_GRPC_TLS` | `0` | `1`/`true`/`yes`/`on` ⇒ 启用端口 TLS |
//! | `AGF_INGEST_OTLP_GRPC_TLS_CERT` | 空 | 服务端证书链（PEM 文件路径，**必填**） |
//! | `AGF_INGEST_OTLP_GRPC_TLS_KEY` | 空 | 服务端私钥（PEM 文件路径，**必填**） |
//! | `AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA` | 空 | 客户端 CA（PEM 路径）；配置 ⇒ **要求并校验客户端证书**（mTLS） |

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use super::*;

/// 环境变量：TLS 总开关（默认关闭）。
pub const ENV_TLS: &str = "AGF_INGEST_OTLP_GRPC_TLS";
/// 环境变量：服务端证书链 PEM 路径。
pub const ENV_TLS_CERT: &str = "AGF_INGEST_OTLP_GRPC_TLS_CERT";
/// 环境变量：服务端私钥 PEM 路径。
pub const ENV_TLS_KEY: &str = "AGF_INGEST_OTLP_GRPC_TLS_KEY";
/// 环境变量：客户端 CA PEM 路径（配置即要求客户端证书 ⇒ mTLS）。
pub const ENV_TLS_CLIENT_CA: &str = "AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA";

/// 端口传输形态（`/readyz` 的 notes 与能力矩阵按此如实标注）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtlpGrpcTlsMode {
    /// 明文 gRPC（默认；也是"配了 TLS 但证书不可用"的降级结果）。
    Plaintext,
    /// 单向 TLS：只出示服务端证书，不校验客户端。
    ServerTls,
    /// mTLS：服务端证书 + **强制**客户端证书。
    MutualTls,
}

impl OtlpGrpcTlsMode {
    /// 稳定短标识（日志/响应体用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::ServerTls => "tls",
            Self::MutualTls => "mtls",
        }
    }

    /// 是否启用了 TLS（任一形态）。
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        !matches!(self, Self::Plaintext)
    }
}

/// OTLP/gRPC 端口 TLS 配置（**只记 PEM 路径**；读取发生在 [`OtlpGrpcTlsConfig::load`]）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtlpGrpcTlsConfig {
    /// 是否请求启用 TLS（`AGF_INGEST_OTLP_GRPC_TLS`，默认 `false`）。
    pub enabled: bool,
    /// 服务端证书链 PEM 路径。
    pub cert_pem: Option<PathBuf>,
    /// 服务端私钥 PEM 路径。
    pub key_pem: Option<PathBuf>,
    /// 客户端 CA PEM 路径（配置 ⇒ 要求客户端证书）。
    pub client_ca_pem: Option<PathBuf>,
}

/// 模式判定结果：**实际生效**的形态 + 降级原因 + 人读描述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpGrpcTlsResolution {
    /// 实际生效的传输形态。
    pub mode: OtlpGrpcTlsMode,
    /// 配了 TLS 但**没能启用**时的如实原因（`None` = 无降级）。
    pub degraded: Option<String>,
    /// 人读描述（`/readyz` notes 用；**不含任何密钥内容**）。
    pub summary: String,
}

impl OtlpGrpcTlsConfig {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取（单测注入用；不碰进程环境）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            enabled: bool_of(&lookup, ENV_TLS, false),
            cert_pem: path_of(&lookup, ENV_TLS_CERT),
            key_pem: path_of(&lookup, ENV_TLS_KEY),
            client_ca_pem: path_of(&lookup, ENV_TLS_CLIENT_CA),
        }
    }

    /// 是否做过任何 TLS 相关配置（用于"配了但没开"的提醒）。
    #[must_use]
    pub fn configured_any(&self) -> bool {
        self.cert_pem.is_some() || self.key_pem.is_some() || self.client_ca_pem.is_some()
    }

    /// 判定**实际生效**的传输形态：证书齐备且 PEM 合法才启用，否则给出不可启动的原因。
    #[must_use]
    pub fn resolve(&self) -> OtlpGrpcTlsResolution {
        if !self.enabled {
            let degraded = if self.configured_any() {
                Some(format!("已提供 OTLP/gRPC TLS 证书/CA，但 {ENV_TLS} 未置 1 ⇒ TLS 未启用（该接收器不启用）"))
            } else {
                None
            };
            return OtlpGrpcTlsResolution {
                mode: OtlpGrpcTlsMode::Plaintext,
                degraded,
                summary: "明文 gRPC（未启用 TLS；单向 TLS/mTLS 见 AGF_INGEST_OTLP_GRPC_TLS*）".to_string(),
            };
        }
        match (&self.cert_pem, &self.key_pem) {
            (None, None) => Self::degraded(format!(
                "{ENV_TLS}=1 但未提供 {ENV_TLS_CERT}/{ENV_TLS_KEY} ⇒ TLS 未启用（该接收器不启用）"
            )),
            (Some(_), None) => Self::degraded(format!(
                "{ENV_TLS_CERT} 已提供但缺少 {ENV_TLS_KEY}（服务端证书与私钥必须成对）⇒ TLS 未启用（该接收器不启用）"
            )),
            (None, Some(_)) => Self::degraded(format!(
                "{ENV_TLS_KEY} 已提供但缺少 {ENV_TLS_CERT}（服务端证书与私钥必须成对）⇒ TLS 未启用（该接收器不启用）"
            )),
            (Some(cert), Some(key)) => {
                let cert_pem = match read_pem(cert, ENV_TLS_CERT) {
                    Ok(pem) => pem,
                    Err(e) => return Self::degraded(e),
                };
                let key_pem = match read_pem(key, ENV_TLS_KEY) {
                    Ok(pem) => pem,
                    Err(e) => return Self::degraded(e),
                };
                if let Err(e) = check_pem(&cert_pem, &key_pem) {
                    return Self::degraded(e);
                }
                match &self.client_ca_pem {
                    Some(ca) => match read_pem(ca, ENV_TLS_CLIENT_CA) {
                        Ok(ca_pem) => {
                            if let Err(e) = check_ca_pem(&ca_pem) {
                                return Self::degraded(e);
                            }
                            OtlpGrpcTlsResolution {
                                mode: OtlpGrpcTlsMode::MutualTls,
                                degraded: None,
                                summary: format!(
                                    "mTLS（证书={}，客户端 CA={}；**要求并校验客户端证书**，不带证书的握手会被拒）",
                                    cert.display(),
                                    ca.display()
                                ),
                            }
                        }
                        Err(e) => Self::degraded(e),
                    },
                    None => OtlpGrpcTlsResolution {
                        mode: OtlpGrpcTlsMode::ServerTls,
                        degraded: None,
                        summary: format!(
                            "TLS（证书={}；单向：不校验客户端证书；如需 mTLS 请配 {ENV_TLS_CLIENT_CA}）",
                            cert.display()
                        ),
                    },
                }
            }
        }
    }

    /// 降级：一律回退**明文**（并带上报错原因），绝不让进程起不来。
    fn degraded(reason: String) -> OtlpGrpcTlsResolution {
        OtlpGrpcTlsResolution {
            mode: OtlpGrpcTlsMode::Plaintext,
            degraded: Some(reason.clone()),
            summary: format!("接收器不启用（TLS 配置无效：{reason}）"),
        }
    }

    /// 人读描述（`/readyz` notes 用）。
    #[must_use]
    pub fn describe(&self) -> String {
        let resolution = self.resolve();
        match resolution.degraded {
            Some(reason) => format!("接收器不启用（TLS 配置无效：{reason}）"),
            None => resolution.summary,
        }
    }

    /// 读取 PEM 并装配 tonic [`ServerTlsConfig`]（只在模式为 TLS/mTLS 时调用）。
    ///
    /// # Errors
    /// PEM 不可读/非法，或 rustls 服务端配置失败（证书与私钥不匹配等）。
    pub fn load(&self) -> DomainResult<ServerTlsConfig> {
        let resolution = self.resolve();
        if !resolution.mode.is_encrypted() {
            return Err(DomainError::Config(resolution.degraded.unwrap_or_else(|| "OTLP/gRPC TLS 未启用".to_string())));
        }
        let cert = self.cert_pem.as_deref().ok_or_else(|| DomainError::Config(format!("缺少 {ENV_TLS_CERT}")))?;
        let key = self.key_pem.as_deref().ok_or_else(|| DomainError::Config(format!("缺少 {ENV_TLS_KEY}")))?;
        let cert_pem = read_pem(cert, ENV_TLS_CERT).map_err(DomainError::Config)?;
        let key_pem = read_pem(key, ENV_TLS_KEY).map_err(DomainError::Config)?;
        // rustls 0.23 的 `ServerConfig::builder()`（tonic 内部使用）要求**进程默认 provider**；
        // 本仓库同时开了 ring 与 aws-lc-rs 两个 provider 特性，未显式安装默认 provider 时会 panic。
        // 这里装 ring（与 syslog TLS / Kafka TLS / MQTT TLS 用的同一 provider），已安装则忽略返回值。
        let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(&cert_pem, &key_pem));
        if let Some(ca_path) = &self.client_ca_pem {
            let ca_pem = read_pem(ca_path, ENV_TLS_CLIENT_CA).map_err(DomainError::Config)?;
            // `client_ca_root` 装的是**强制**客户端校验（`client_auth_optional=false`）
            tls = tls.client_ca_root(Certificate::from_pem(&ca_pem));
        }
        // 立刻试装一次：把"证书与私钥不匹配/PEM 形态不对"这类错误暴露在**启用阶段**，
        // 而不是等第一条连接进来才失败。
        Server::builder().tls_config(tls.clone()).map_err(|e| {
            DomainError::Config(format!(
                "OTLP/gRPC TLS 装配失败（{ENV_TLS_CERT}/{ENV_TLS_KEY} 不匹配或 PEM 非法）: {e}"
            ))
        })?;
        Ok(tls)
    }
}

/// 已装配的端口 TLS 运行态（`serve` 用它决定是否给 tonic 装 `tls_config`）。
#[derive(Debug)]
pub struct OtlpGrpcTlsState {
    /// 实际生效的传输形态。
    pub mode: OtlpGrpcTlsMode,
    /// 装配好的服务端 TLS 配置（明文时为 `None`）。
    pub config: Option<ServerTlsConfig>,
    /// 降级原因（明文且配过 TLS 时非空）。
    pub degraded: Option<String>,
}

impl OtlpGrpcTlsState {
    /// Assemble the requested transport; invalid TLS must never serve plaintext.
    ///
    /// # Errors
    /// Incomplete TLS configuration, unreadable/invalid certificates, or key mismatch.
    pub fn from_config(config: &OtlpGrpcTlsConfig) -> DomainResult<Self> {
        let resolution = config.resolve();
        if let Some(reason) = resolution.degraded {
            return Err(DomainError::Config(format!("OTLP/gRPC TLS 配置无效，接收器不启用：{reason}")));
        }
        if !resolution.mode.is_encrypted() {
            return Ok(Self::plaintext());
        }
        let tls = config.load()?;
        info!(mode = resolution.mode.as_str(), "OTLP/gRPC TLS configuration validated");
        Ok(Self { mode: resolution.mode, config: Some(tls), degraded: None })
    }

    /// 明文（不启用 TLS）。
    #[must_use]
    pub fn plaintext() -> Self {
        Self { mode: OtlpGrpcTlsMode::Plaintext, config: None, degraded: None }
    }
}

/// 路径型环境变量（空串 ⇒ `None`）。
fn path_of(lookup: &impl Fn(&str) -> Option<String>, key: &str) -> Option<PathBuf> {
    lookup(key).map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// 布尔环境变量（`0/false/no/off` 为假；无法识别 ⇒ `warn` + 默认值）。
///
/// 与 `config.rs` 的同名工具同口径，但**故意各留一份**：`otlp_grpc` 的两个子模块彼此
/// 只通过 `super::*` 共享类型，不共享私有助手，避免一处改动意外影响另一处的降级语义。
fn bool_of(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: bool) -> bool {
    match lookup(key) {
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "" => default,
            "0" | "false" | "no" | "off" => false,
            "1" | "true" | "yes" | "on" => true,
            other => {
                warn!(key, value = other, "布尔环境变量取值无法识别，使用默认值");
                default
            }
        },
        None => default,
    }
}

/// 读 PEM 文件（路径给错是部署常态：必须给出明确原因，而不是静默"没配"）。
fn read_pem(path: &Path, key: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{key}={} 读取失败: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{key}={} 是空文件", path.display()));
    }
    Ok(bytes)
}

/// 证书/私钥 PEM 形态检查（不匹配由 [`OtlpGrpcTlsConfig::load`] 的试装兜底）。
fn check_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{ENV_TLS_CERT} PEM 解析失败: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{ENV_TLS_CERT} PEM 中没有证书"));
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..]).map_err(|e| format!("{ENV_TLS_KEY} PEM 解析失败: {e}"))?;
    if key.is_none() {
        return Err(format!("{ENV_TLS_KEY} PEM 中没有私钥（支持 PKCS#8/PKCS#1/SEC1）"));
    }
    Ok(())
}

/// 客户端 CA PEM 形态检查。
fn check_ca_pem(ca_pem: &[u8]) -> Result<(), String> {
    let certs = rustls_pemfile::certs(&mut &ca_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{ENV_TLS_CLIENT_CA} PEM 解析失败: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{ENV_TLS_CLIENT_CA} PEM 中没有证书"));
    }
    Ok(())
}

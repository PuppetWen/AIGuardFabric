//! OTLP/gRPC 配置：`AGF_INGEST_OTLP_GRPC_*` 环境开关、监听地址/上限默认值与解读。

use super::*;

/// 环境变量：总开关（`0` = 不监听）。
pub const ENV_ENABLED: &str = "AGF_INGEST_OTLP_GRPC_ENABLED";
/// 环境变量：监听地址。
pub const ENV_LISTEN: &str = "AGF_INGEST_OTLP_GRPC_LISTEN";
/// 环境变量：单请求最大记录数。
pub const ENV_MAX_RECORDS: &str = "AGF_INGEST_OTLP_GRPC_MAX_RECORDS";
/// 环境变量：单条消息解码上限（字节）。
pub const ENV_MAX_MESSAGE_BYTES: &str = "AGF_INGEST_OTLP_GRPC_MAX_MESSAGE_BYTES";

/// OTLP/gRPC 默认监听地址（OTLP 规范的 4317）。
pub const DEFAULT_LISTEN: &str = "0.0.0.0:4317";
/// 默认单请求上限：与 HTTP 通道一致（`OtlpLogsReceiver::new` 的默认值）。
pub const DEFAULT_MAX_RECORDS: usize = 10_000;
/// 默认单条 gRPC 消息解码上限（16 MiB；tonic 缺省只有 4 MiB，偏小）。
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// OTLP/gRPC 监听配置（全部来自环境变量；非法值只 `warn` 并回退默认，绝不让进程起不来）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpGrpcConfig {
    /// 是否启用（`AGF_INGEST_OTLP_GRPC_ENABLED`，默认启用）。
    pub enabled: bool,
    /// 监听地址原文（`AGF_INGEST_OTLP_GRPC_LISTEN`，默认 `0.0.0.0:4317`）。
    pub listen: String,
    /// 单请求最大记录数（超出部分如实计入 `partial_success`）。
    pub max_records: usize,
    /// 单条 gRPC 消息解码上限。
    pub max_message_bytes: usize,
    /// 端口自身的 TLS/mTLS（`AGF_INGEST_OTLP_GRPC_TLS*`，默认**明文**）。
    pub tls: OtlpGrpcTlsConfig,
}

impl Default for OtlpGrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: DEFAULT_LISTEN.to_string(),
            max_records: DEFAULT_MAX_RECORDS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            tls: OtlpGrpcTlsConfig::default(),
        }
    }
}

impl OtlpGrpcConfig {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取（单测注入用；**不碰进程环境**，避免并行测试互相干扰）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        let enabled = flag(&lookup, ENV_ENABLED, defaults.enabled);
        let listen = match lookup(ENV_LISTEN) {
            Some(raw) if !raw.trim().is_empty() => raw.trim().to_string(),
            _ => defaults.listen,
        };
        let max_records = number(&lookup, ENV_MAX_RECORDS, defaults.max_records).max(1);
        let max_message_bytes = number(&lookup, ENV_MAX_MESSAGE_BYTES, defaults.max_message_bytes).max(1024);
        let tls = OtlpGrpcTlsConfig::from_lookup(&lookup);
        Self { enabled, listen, max_records, max_message_bytes, tls }
    }

    /// 解析监听地址。
    ///
    /// # Errors
    /// 地址不是合法的 `IP:PORT`。
    pub fn socket_addr(&self) -> DomainResult<SocketAddr> {
        parse_listen(&self.listen)
    }

    /// 人读描述（`/readyz` 的 notes 用；含**端口传输形态**：明文 / TLS / mTLS）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "OTLP/gRPC {}：LogsService/Export（单请求上限 {} 条，消息上限 {} 字节，端口传输={}）",
            self.listen,
            self.max_records,
            self.max_message_bytes,
            self.tls.describe()
        )
    }
}

/// 布尔环境变量读取（`0/false/no/off` 为假；无法识别 ⇒ `warn` + 默认值）。
fn flag(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: bool) -> bool {
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

/// 数值环境变量读取（非法 ⇒ `warn` + 默认值；不 panic、不让进程起不来）。
fn number(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: usize) -> usize {
    match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => match raw.trim().parse::<usize>() {
            Ok(value) => value,
            Err(e) => {
                warn!(key, value = %raw, error = %e, "环境变量不是合法数字，使用默认值");
                default
            }
        },
        _ => default,
    }
}

// ---------------------------------------------------------------------------
// 映射：ExportLogsServiceRequest → OTLP/JSON → 既有中间形态
// ---------------------------------------------------------------------------

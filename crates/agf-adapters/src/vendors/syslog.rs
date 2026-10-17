//! Syslog 转发适配器（RFC 5424，真实 TCP/UDP 发包）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | `syslog://host:514`（`protocol` 取 `udp`（默认）/ `tcp`）；**真实发包** |
//! | 凭据 | 无（Syslog 无鉴权；**因此 endpoint 是必需设置而非凭据**） |
//! | 设置 | `endpoint`（必需）、`facility`（可选，默认 10 = `authpriv`）、`app_name`（可选，默认 `aiguardfabric`）、`protocol` |
//! | 报文 | RFC 5424：`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG` |
//! | 结构化数据 | `[agf@32473 event_type="…" idempotency_key="…" severity="…"]`，按 RFC 5424 转义 |
//! | 分帧 | UDP 一报文一条；TCP 采用 RFC 6587 非透明分帧（`LF` 结尾） |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `endpoint` | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件仍落平台内，可由人工导出或走 Webhook 通道 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发包** |
//! | endpoint scheme 非 `syslog`/`udp`/`tcp` 或缺端口 | `init()` 返回 `Config`，旧配置保持不变 |
//! | `facility > 23` / `protocol` 非 `udp`/`tcp` | `init()` 返回 `Config` |
//! | 目标不可达 / 超时 | `DependencyUnavailable` / `Timeout`，**按 `RetryConfig` 重试**（注意：UDP 无连接确认，`Ok` 仅表示本机已发出） |

use agf_core::enums::Severity;
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;
use tokio::io::AsyncWriteExt as _;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 允许的传输协议。
pub const ALLOWED_PROTOCOLS: [&str; 2] = ["udp", "tcp"];

/// 默认 facility（10 = `authpriv`，安全审计类日志的常用取值）。
pub const DEFAULT_FACILITY: u8 = 10;

/// facility 上限（RFC 5424 定义 0..=23）。
pub const MAX_FACILITY: u8 = 23;

/// 结构化数据 ID（私有企业号 32473 为 RFC 5612 示例保留值）。
pub const SD_ID: &str = "agf@32473";

/// Syslog 转发适配器标记类型。
#[derive(Debug)]
pub struct SyslogForwarder;

impl SyslogForwarder {
    /// 等级 → Syslog severity（0..=7）。
    #[must_use]
    pub const fn syslog_severity(severity: Severity) -> u8 {
        match severity {
            Severity::Critical => 2, // Critical
            Severity::High => 4,     // Warning
            Severity::Medium => 5,   // Notice
            Severity::Low => 6,      // Informational
            Severity::Info => 7,     // Debug
        }
    }

    /// PRI = facility × 8 + severity。
    #[must_use]
    pub const fn pri(facility: u8, severity: Severity) -> u8 {
        facility * 8 + Self::syslog_severity(severity)
    }

    /// RFC 5424 结构化数据参数转义（`"`、`\`、`]` 前加 `\`）。
    #[must_use]
    pub fn escape_sd_value(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            if matches!(c, '"' | '\\' | ']') {
                out.push('\\');
            }
            out.push(c);
        }
        out
    }

    /// 组装 RFC 5424 行。
    #[must_use]
    pub fn rfc5424_line(
        pri: u8,
        at: agf_core::time::Timestamp,
        hostname: &str,
        app_name: &str,
        procid: &str,
        msg_id: &str,
        structured_data: &str,
        message: &str,
    ) -> String {
        let timestamp = at.to_rfc3339();
        if structured_data.is_empty() {
            format!("<{pri}>1 {timestamp} {hostname} {app_name} {procid} {msg_id} - {message}")
        } else {
            format!("<{pri}>1 {timestamp} {hostname} {app_name} {procid} {msg_id} {structured_data} {message}")
        }
    }

    /// 结构化数据段。
    #[must_use]
    pub fn structured_data(msg: &AdapterMessage) -> String {
        let mut params: Vec<String> = vec![
            format!("event_type=\"{}\"", Self::escape_sd_value(&msg.event_type)),
            format!("severity=\"{}\"", msg.severity.as_str()),
            format!("idempotency_key=\"{}\"", Self::escape_sd_value(&msg.idempotency_key)),
        ];
        if let Some(asset) = &msg.asset {
            params.push(format!("asset=\"{}\"", Self::escape_sd_value(asset)));
        }
        for (k, v) in &msg.labels {
            params.push(format!("{}=\"{}\"", k.replace([' ', '=', ']', '"'], "_"), Self::escape_sd_value(v)));
        }
        format!("[{SD_ID} {}]", params.join(" "))
    }

    /// facility 设置值。
    ///
    /// # Errors
    /// 取值越界或非整数时返回 `DomainError::Config`。
    pub fn facility(settings: &AdapterSettings) -> DomainResult<u8> {
        match settings.settings.get("facility").and_then(serde_json::Value::as_u64) {
            None => Ok(DEFAULT_FACILITY),
            Some(value) if value <= u64::from(MAX_FACILITY) => Ok(u8::try_from(value).unwrap_or(DEFAULT_FACILITY)),
            Some(value) => {
                Err(DomainError::Config(format!("syslog facility 越界: {value}（允许 0..={MAX_FACILITY}）")))
            }
        }
    }

    /// 协议设置值。
    ///
    /// # Errors
    /// 取值不在 `udp` / `tcp` 时返回 `DomainError::Config`。
    pub fn protocol(settings: &AdapterSettings) -> DomainResult<String> {
        let protocol = settings.get_str("protocol").unwrap_or("udp").to_ascii_lowercase();
        if !ALLOWED_PROTOCOLS.contains(&protocol.as_str()) {
            return Err(DomainError::Config(format!(
                "syslog protocol 非法: {protocol:?}（允许 {ALLOWED_PROTOCOLS:?}）"
            )));
        }
        Ok(protocol)
    }

    /// 解析 `syslog://host:port`（也接受 `udp://` / `tcp://`）为 `(host, port, protocol)`。
    ///
    /// scheme 为 `udp`/`tcp` 时**以 scheme 为准**（显式协议优先于 `protocol` 设置）。
    ///
    /// # Errors
    /// URL 非法、缺主机或缺端口时返回 `DomainError::Config`。
    pub fn socket_target(endpoint: &str) -> DomainResult<(String, u16, String)> {
        let parsed =
            url::Url::parse(endpoint).map_err(|e| DomainError::Config(format!("syslog endpoint 非法: {e}")))?;
        let host = parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| DomainError::Config(format!("syslog endpoint 缺少主机: {endpoint}")))?
            .to_string();
        let port =
            parsed.port().ok_or_else(|| DomainError::Config(format!("syslog endpoint 必须带端口: {endpoint}")))?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        let protocol = if ALLOWED_PROTOCOLS.contains(&scheme.as_str()) { scheme } else { "udp".to_string() };
        Ok((host, port, protocol))
    }

    /// 真实发包：UDP 一报文一条；TCP 按 RFC 6587 非透明分帧（`LF` 结尾）。
    ///
    /// # Errors
    /// 目标不可达、写失败或超时（`settings.timeout_secs`）时返回
    /// `DependencyUnavailable` / `Timeout`（均可按 `RetryConfig` 重试）。
    async fn send_line(endpoint: &str, line: &str, settings: &AdapterSettings) -> DomainResult<()> {
        let (host, port, protocol) = Self::socket_target(endpoint)?;
        let budget = std::time::Duration::from_secs(settings.timeout_secs);
        let target = format!("{host}:{port}");
        let outcome = tokio::time::timeout(budget, async move {
            if protocol == "tcp" {
                let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                stream.write_all(line.as_bytes()).await?;
                stream.write_all(b"\n").await?;
                stream.flush().await?;
            } else {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                socket.send_to(line.as_bytes(), (host.as_str(), port)).await?;
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
        match outcome {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(DomainError::DependencyUnavailable {
                dependency: Self::NAME.to_string(),
                cause: format!("syslog 发包失败（{target}）: {e}"),
            }),
            Err(_) => Err(DomainError::Timeout(format!("syslog 发包超时（{target}，{}s）", settings.timeout_secs))),
        }
    }
}

#[async_trait::async_trait]
impl VendorSpec for SyslogForwarder {
    const NAME: &'static str = "syslog-forwarder";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["endpoint"];

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new(
            "syslog-forwarder",
            "Syslog 转发（RFC 5424）",
            "标准协议",
            AdapterCategory::SecurityPlatform,
        )
        .with_secrets(&[], &[])
        .with_endpoint_key("endpoint")
        .with_capabilities(vec![
            agf_core::adapter::AdapterCapability::PushEvents,
            agf_core::adapter::AdapterCapability::SelfCheck,
        ])
        .with_semantics(crate::contract::SemanticProfile::send_only(
            crate::vendors::SYSLOG_PUSH_UNSUPPORTED,
            crate::vendors::SYSLOG_READ_UNSUPPORTED,
            crate::vendors::SYSLOG_READ_UNSUPPORTED,
        ))
        .with_degradation(
            "未配置 endpoint 时不转发任何 Syslog（事件仍落平台内，可由人工导出或走 Webhook 通道）；\
                 TCP/UDP 发包失败按 RetryConfig 重试，连续失败由熔断器开路",
        )
        .with_mock_location(
            "crates/agf-adapters/src/vendors/syslog.rs#MockSyslogForwarderAdapter（注册名 syslog-forwarder）",
        )
        .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(endpoint) = settings.get_str("endpoint") {
            crate::settings::validate_endpoint(endpoint)?;
            let parsed =
                url::Url::parse(endpoint).map_err(|e| DomainError::Config(format!("syslog endpoint 非法: {e}")))?;
            if !matches!(parsed.scheme(), "syslog" | "udp" | "tcp") {
                return Err(DomainError::Config(format!(
                    "syslog endpoint scheme 必须为 syslog/udp/tcp，收到 {}",
                    parsed.scheme()
                )));
            }
            if parsed.port().is_none() {
                return Err(DomainError::Config(format!("syslog endpoint 必须带端口: {endpoint}")));
            }
        }
        Self::facility(settings)?;
        Self::protocol(settings)?;
        Ok(())
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = settings.resolve_endpoint(None)?;
        let facility = Self::facility(settings)?;
        let protocol = Self::protocol(settings)?;
        let app_name = settings.get_str("app_name").unwrap_or("aiguardfabric");
        let hostname = settings.get_str("hostname").unwrap_or("-");
        let pri = Self::pri(facility, msg.severity);
        let line = Self::rfc5424_line(
            pri,
            msg.occurred_at,
            hostname,
            app_name,
            "-",
            "agf-event",
            &Self::structured_data(msg),
            &msg.summary.replace(['\r', '\n'], " "),
        );
        Ok(VendorRequest::channel(
            "SEND",
            endpoint,
            json!({ "protocol": protocol, "facility": facility, "pri": pri, "rfc5424": line }),
        ))
    }

    /// 真实发包（覆写默认 HTTP 实现：Syslog 是 UDP/TCP 通道，非 HTTP）。
    ///
    /// Syslog 无回执协议，因此远端 id 为空；`Ok(None)` 表示**本机已把报文交给网络栈**
    /// （UDP 无连接确认，这是协议本身的上限，不夸大语义）。
    ///
    /// # Errors
    /// 报文体缺 `rfc5424` 时返回 `Validation`；发包失败/超时见 `send_line`。
    async fn invoke_live(
        req: &crate::transport::VendorRequest,
        settings: &AdapterSettings,
    ) -> DomainResult<Option<String>> {
        let line = req
            .body
            .get("rfc5424")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| DomainError::Validation("syslog 请求体缺少 rfc5424 报文字段".to_string()))?;
        Self::send_line(&req.endpoint, line, settings).await?;
        Ok(None)
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockSyslogForwarderAdapter = crate::vendor::VendorAdapterImpl<SyslogForwarder>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::time::Timestamp;

    fn message() -> AdapterMessage {
        AdapterMessage::event("ai.policy.denied", Severity::High, "策略拒绝", "命中 PA-DENY-002\n第二行", json!({}))
            .with_asset("gw-1")
            .with_label("policy", "PA-DENY-002")
    }

    fn settings(extra: &[(&str, serde_json::Value)]) -> AdapterSettings {
        let mut base: Vec<(&str, serde_json::Value)> = vec![("endpoint", json!("syslog://10.0.0.1:514"))];
        base.extend_from_slice(extra);
        settings_for(&SyslogForwarder::metadata(), &base, &[]).expect("测试设置必须可构造")
    }

    #[test]
    fn pri_math_matches_rfc5424() {
        assert_eq!(SyslogForwarder::syslog_severity(Severity::Critical), 2);
        assert_eq!(SyslogForwarder::syslog_severity(Severity::Info), 7);
        assert_eq!(SyslogForwarder::pri(10, Severity::High), 84, "10*8+4=84");
        assert_eq!(SyslogForwarder::pri(0, Severity::Critical), 2);
        assert_eq!(SyslogForwarder::pri(23, Severity::Info), 191, "上限 facility 不得溢出 u8");
    }

    #[test]
    fn rfc5424_line_shape() {
        let line = SyslogForwarder::rfc5424_line(
            SyslogForwarder::pri(10, Severity::High),
            Timestamp::now(),
            "host-1",
            "aiguardfabric",
            "-",
            "agf-event",
            "[agf@32473 event_type=\"x\"]",
            "摘要",
        );
        assert!(line.starts_with("<84>1 "), "{line}");
        assert!(line.contains(" host-1 aiguardfabric - agf-event [agf@32473 event_type=\"x\"] 摘要"));
        let without_sd = SyslogForwarder::rfc5424_line(84, Timestamp::now(), "h", "a", "-", "m", "", "msg");
        assert!(without_sd.contains(" - msg"), "无结构化数据时使用 NILVALUE: {without_sd}");
    }

    #[test]
    fn structured_data_escaping_is_rfc_compliant() {
        assert_eq!(SyslogForwarder::escape_sd_value("a\"b\\c]d"), "a\\\"b\\\\c\\]d");
        let msg = AdapterMessage::event("x", Severity::Low, "t", "s", json!({})).with_label("k", "v\"1]");
        let sd = SyslogForwarder::structured_data(&msg);
        assert!(sd.starts_with("[agf@32473 "));
        assert!(sd.contains("idempotency_key=\""), "{sd}");
        assert!(sd.contains("k=\"v\\\"1\\]\""), "{sd}");
    }

    #[test]
    fn encode_uses_settings_and_drops_newlines_in_message() {
        let req =
            SyslogForwarder::encode(&message(), &settings(&[("protocol", json!("tcp")), ("facility", json!(13))]))
                .expect("编码应成功");
        assert_eq!(req.method, "SEND");
        assert_eq!(req.endpoint, "syslog://10.0.0.1:514");
        assert_eq!(req.body["protocol"], "tcp");
        assert_eq!(req.body["facility"], 13);
        assert_eq!(req.body["pri"], 13 * 8 + 4);
        let line = req.body["rfc5424"].as_str().unwrap_or_default();
        assert!(!line.contains('\n'), "RFC 5424 行内不得含换行: {line}");
        assert!(line.contains("policy=\"PA-DENY-002\""));
    }

    #[test]
    fn validation_rejects_bad_facility_protocol_and_endpoint() {
        assert!(SyslogForwarder::validate_settings(&settings(&[])).is_ok());
        assert!(SyslogForwarder::validate_settings(&settings(&[("facility", json!(24))])).is_err());
        assert!(SyslogForwarder::validate_settings(&settings(&[("protocol", json!("sctp"))])).is_err());
        assert!(SyslogForwarder::validate_settings(&settings(&[("endpoint", json!("https://10.0.0.1:514"))])).is_err());
        assert!(
            SyslogForwarder::validate_settings(&settings(&[("endpoint", json!("syslog://10.0.0.1"))])).is_err(),
            "必须带端口"
        );
    }

    #[tokio::test]
    async fn mock_send_deterministic_and_unconfigured_blocks() {
        let mut mock = crate::vendor::VendorAdapterImpl::<SyslogForwarder>::mocked();
        let first = mock.send(&message()).await.expect("Mock 发送");
        assert_eq!(first.remote_id, mock.send(&message()).await.expect("Mock 发送").remote_id);
        assert_eq!(first.origin, "mock://syslog-forwarder");

        let mut adapter = crate::vendor::VendorAdapterImpl::<SyslogForwarder>::new();
        adapter
            .init_with(
                &crate::test_support::config_for("syslog-forwarder", &[], false),
                &crate::settings::NoSecrets,
                false,
            )
            .await
            .expect("未配置不得失败");
        assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
        assert!(adapter.send(&message()).await.is_err());
    }

    #[tokio::test]
    async fn live_mode_has_real_transport_and_validates_target() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<SyslogForwarder>::new();
        adapter
            .init_with(
                &crate::test_support::config_for(
                    "syslog-forwarder",
                    &[("endpoint", json!("syslog://10.0.0.1:514"))],
                    false,
                ),
                &crate::settings::NoSecrets,
                false,
            )
            .await
            .expect("合法配置");
        assert_eq!(adapter.mode(), AdapterMode::Live);
        assert!(adapter.descriptor().real_implementation, "Syslog 已实现真实 UDP/TCP 发包");
        assert!(!adapter.build_record().message.unwrap_or_default().contains("TODO("));
        assert!(adapter.encode(&message()).is_ok(), "编码本身必须可用");
    }

    #[test]
    fn socket_target_parses_scheme_host_port() {
        assert_eq!(
            SyslogForwarder::socket_target("syslog://10.0.0.1:514").ok(),
            Some(("10.0.0.1".to_string(), 514, "udp".to_string()))
        );
        assert_eq!(
            SyslogForwarder::socket_target("udp://10.0.0.1:5514").ok(),
            Some(("10.0.0.1".to_string(), 5514, "udp".to_string()))
        );
        assert_eq!(
            SyslogForwarder::socket_target("tcp://syslog.internal.example:601").ok(),
            Some(("syslog.internal.example".to_string(), 601, "tcp".to_string())),
            "scheme 为 tcp 时显式协议优先"
        );
        assert!(SyslogForwarder::socket_target("syslog://10.0.0.1").is_err(), "缺端口必须报错");
        assert!(SyslogForwarder::socket_target("not-a-url").is_err());
    }

    #[tokio::test]
    async fn send_line_reports_unreachable_target_without_panicking() {
        let settings = settings(&[]);
        // 127.0.0.1:1 上无监听者：TCP 建连被拒（用 TCP 断言失败路径，UDP 无连接语义）
        let error = SyslogForwarder::send_line("tcp://127.0.0.1:1", "<84>1 - - - - - - 测试", &settings)
            .await
            .expect_err("不可达目标必须如实报错");
        assert!(matches!(error, DomainError::DependencyUnavailable { .. }), "{error}");
    }
}

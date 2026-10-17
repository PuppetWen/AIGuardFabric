//! 链路健康：错误分类（鉴权/网络/TLS/协议）、链路计数器与 `link_prometheus` 指标，以及环境读取小工具。

// ---------------------------------------------------------------------------
// 链路错误分类计数（Prometheus）
// ---------------------------------------------------------------------------

use super::*;

/// 环境变量：MQTT 链路指标在 Prometheus 里的 `receiver` 标签值。
const LINK_RECEIVER_LABEL: &str = "mqtt";

/// 链路错误分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MqttLinkError {
    /// TLS 握手/证书链/主机名校验失败（`AGF_INGEST_MQTT_TLS_*` 配错、证书过期…）。
    Tls,
    /// 鉴权失败（CONNACK 返回 NotAuthorized / BadUsernameOrPassword / IdentifierRejected）。
    Auth,
    /// 网络层（连接被拒、超时、连接被重置）。
    Network,
    /// MQTT 协议层（畸形报文、未收到 CONNACK）。
    Protocol,
    /// 其他（无法归类，**不吞掉**）。
    Other,
}

impl MqttLinkError {
    /// Prometheus 标签值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Auth => "auth",
            Self::Network => "network",
            Self::Protocol => "protocol",
            Self::Other => "other",
        }
    }

    /// 全部类别（渲染 Prometheus 时保证每个类别都有样本）。
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [Self::Tls, Self::Auth, Self::Network, Self::Protocol, Self::Other]
    }
}

/// 把 `rumqttc` 的连接错误文本归类（**纯函数**；文本形态见 `ConnectionError` 的 `Display`）。
#[must_use]
pub fn classify_link_error(error: &str) -> MqttLinkError {
    let lower = error.to_ascii_lowercase();
    // 鉴权优先于网络：CONNACK 的拒绝码里带 "NotAuthorized"/"BadUsernameOrPassword"
    for needle in ["notauthorized", "badusernameorpassword", "identifierrejected", "not authorized", "unauthorized"] {
        if lower.contains(needle) {
            return MqttLinkError::Auth;
        }
    }
    for needle in [
        "tls",
        "web pki",
        "webpki",
        "certificate",
        "no valid ca",
        "invalid dns name",
        "handshake",
        "unknownissuer",
        "expired",
    ] {
        if lower.contains(needle) {
            return MqttLinkError::Tls;
        }
    }
    for needle in ["i/o", "connection refused", "network timeout", "flush timeout", "timed out", "reset by peer"] {
        if lower.contains(needle) {
            return MqttLinkError::Network;
        }
    }
    for needle in ["mqtt state", "expected connack", "malformed"] {
        if lower.contains(needle) {
            return MqttLinkError::Protocol;
        }
    }
    MqttLinkError::Other
}

/// MQTT 链路计数（按错误类别 + 重连次数）。
#[derive(Debug, Default)]
pub struct MqttLinkCounters {
    tls: AtomicU64,
    auth: AtomicU64,
    network: AtomicU64,
    protocol: AtomicU64,
    other: AtomicU64,
    reconnects: AtomicU64,
}

/// 链路计数快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MqttLinkSnapshot {
    /// TLS 类错误。
    pub tls_errors: u64,
    /// 鉴权类错误。
    pub auth_errors: u64,
    /// 网络类错误。
    pub network_errors: u64,
    /// 协议类错误。
    pub protocol_errors: u64,
    /// 其他错误。
    pub other_errors: u64,
    /// 退避重连次数。
    pub reconnects: u64,
}

impl MqttLinkCounters {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记一次连接错误（按类别累加）。
    pub fn record_error(&self, kind: MqttLinkError) {
        let cell = match kind {
            MqttLinkError::Tls => &self.tls,
            MqttLinkError::Auth => &self.auth,
            MqttLinkError::Network => &self.network,
            MqttLinkError::Protocol => &self.protocol,
            MqttLinkError::Other => &self.other,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    /// 记一次退避重连。
    pub fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// 快照。
    #[must_use]
    pub fn snapshot(&self) -> MqttLinkSnapshot {
        MqttLinkSnapshot {
            tls_errors: self.tls.load(Ordering::Relaxed),
            auth_errors: self.auth.load(Ordering::Relaxed),
            network_errors: self.network.load(Ordering::Relaxed),
            protocol_errors: self.protocol.load(Ordering::Relaxed),
            other_errors: self.other.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
        }
    }
}

impl MqttLinkSnapshot {
    /// 按类别取值。
    #[must_use]
    pub const fn errors(&self, kind: MqttLinkError) -> u64 {
        match kind {
            MqttLinkError::Tls => self.tls_errors,
            MqttLinkError::Auth => self.auth_errors,
            MqttLinkError::Network => self.network_errors,
            MqttLinkError::Protocol => self.protocol_errors,
            MqttLinkError::Other => self.other_errors,
        }
    }

    /// 错误总数。
    #[must_use]
    pub const fn total_errors(&self) -> u64 {
        self.tls_errors + self.auth_errors + self.network_errors + self.protocol_errors + self.other_errors
    }
}

/// 进程内链路计数单例（`/metrics` 与 `/readyz` 共用；MQTT 链路只有一条，无需按名字索引）。
static LINK_COUNTERS: OnceLock<Arc<MqttLinkCounters>> = OnceLock::new();

/// 取进程内 MQTT 链路计数器。
#[must_use]
pub fn link_counters() -> Arc<MqttLinkCounters> {
    Arc::clone(LINK_COUNTERS.get_or_init(|| Arc::new(MqttLinkCounters::new())))
}

/// 渲染 MQTT 链路指标的 Prometheus 文本（挂在 `/metrics` 末尾）。
#[must_use]
pub fn link_prometheus() -> String {
    let snapshot = link_counters().snapshot();
    let mut out = String::from(
        "# HELP agf_ingest_mqtt_link_errors_total MQTT 链路连接错误（按类别：tls/auth/network/protocol/other）\n\
         # TYPE agf_ingest_mqtt_link_errors_total counter\n",
    );
    for kind in MqttLinkError::all() {
        out.push_str(&format!(
            "agf_ingest_mqtt_link_errors_total{{receiver=\"{LINK_RECEIVER_LABEL}\",kind=\"{}\"}} {}\n",
            kind.as_str(),
            snapshot.errors(kind)
        ));
    }
    out.push_str(
        "# HELP agf_ingest_mqtt_reconnects_total MQTT 退避重连次数（连接异常后重试）\n\
         # TYPE agf_ingest_mqtt_reconnects_total counter\n",
    );
    out.push_str(&format!(
        "agf_ingest_mqtt_reconnects_total{{receiver=\"{LINK_RECEIVER_LABEL}\"}} {}\n",
        snapshot.reconnects
    ));
    out
}

// ---------------------------------------------------------------------------
// 环境变量工具
// ---------------------------------------------------------------------------

/// 布尔环境变量（`0/false/no/off` 为假；无法识别 ⇒ `warn` + 默认值）。
pub(crate) fn flag(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: bool) -> bool {
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

/// 正整数环境变量（非法 ⇒ `warn` + 默认值）。
pub(crate) fn number(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: u64) -> u64 {
    match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => match raw.trim().parse::<u64>() {
            Ok(value) => value,
            Err(e) => {
                warn!(key, value = %raw, error = %e, "环境变量不是合法数字，使用默认值");
                default
            }
        },
        _ => default,
    }
}

/// 路径型环境变量（空串 ⇒ `None`）。
pub(crate) fn path(lookup: &impl Fn(&str) -> Option<String>, key: &str) -> Option<PathBuf> {
    lookup(key).map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// 读 PEM 文件（`.env` 风格部署常见"路径给错"，必须给出明确错误而不是静默降级成"不校验"）。
pub(super) fn read_pem(path: Option<&Path>, key: &str) -> DomainResult<Option<Vec<u8>>> {
    let Some(path) = path else { return Ok(None) };
    let bytes = std::fs::read(path)
        .map_err(|e| DomainError::Config(format!("MQTT TLS：读取 {key}={} 失败: {e}", path.display())))?;
    if bytes.is_empty() {
        return Err(DomainError::Config(format!("MQTT TLS：{key}={} 是空文件", path.display())));
    }
    Ok(Some(bytes))
}

// ---------------------------------------------------------------------------
// 订阅抽象
// ---------------------------------------------------------------------------

//! 原生 Pulsar 消费者的配置模型与校验（**纯逻辑**，不读环境变量以外的东西、不发网络）。
//!
//! ## 环境变量（全部以 `AGF_INGEST_PULSAR_` 前缀；与 KoP 路径的
//! `AGF_INGEST_PULSAR_SERVICE_URL` 并存且**互不影响**）
//!
//! | 变量 | 默认 | 说明 |
//! |---|---|---|
//! | `AGF_INGEST_PULSAR_URL` | 空 | **原生入口**：`pulsar://host:6650[,host2:6650]` 或 `pulsar+ssl://host:6651`；配置了就走原生（优先于 KoP） |
//! | `..._TOPIC` | 空 | `persistent://public/default/x`；写短名 `x` 会自动补 `persistent://public/default/` |
//! | `..._SUBSCRIPTION` | `agf-ingest` | 订阅名（broker 侧持久游标，重启不丢） |
//! | `..._SUB_TYPE` | `exclusive` | `exclusive` / `shared` / `failover` / `key_shared` |
//! | `..._INITIAL_POSITION` | `latest` | `latest` / `earliest`（首次建订阅时的游标位置） |
//! | `..._RECEIVER_QUEUE_SIZE` | `1000` | FLOW 许可数（信用） |
//! | `..._TOKEN` | 空 | JWT；配了就发 `auth_method_name="token"` + `auth_data=<jwt>` |
//! | `..._CONNECT_TIMEOUT_SECS` | `10` | TCP + 握手超时 |
//! | `..._BATCH` | `1` | `0` = **不拆** batch（整段算一条，见 [`super::batch`] 的如实说明） |
//! | `..._ACK_MODE` | `individual` | `individual` / `cumulative` |
//! | `..._ACK_EVERY` | `1` | 每处理 N 条发一次 ack（`individual` 时攒批；`1` = 逐条真发） |
//! | `..._TLS_CA` / `..._TLS_CERT` / `..._TLS_KEY` | 空 | CA(PEM) / 客户端证书(mTLS) / 私钥；`pulsar+ssl://` 时生效 |
//! | `..._TLS_INSECURE_SKIP_VERIFY` | `0` | `1` = 跳过证书链校验（**只允许排障**，会 warn） |
//! | `..._RECONNECT_INITIAL_MS` / `..._RECONNECT_MAX_MS` | `500` / `30000` | 指数退避重连区间 |
//! | `..._RECONNECT_MAX_ATTEMPTS` | `0` | `0` = 永不放弃 |
//!
//! 凭据（token / 私钥）**只从环境变量取**，绝不写进日志、指标或错误文本。

use std::path::PathBuf;
use std::time::Duration;

mod enums;

pub use enums::{ConfigError, PulsarAckMode, PulsarEndpoint, PulsarInitialPosition, PulsarSubscriptionType};

/// 客户端版本串（写进 `CommandConnect.client_version`，broker 只用于展示/兼容判断）。
pub const CLIENT_VERSION: &str = concat!("agf-ingest-pulsar-native/", env!("CARGO_PKG_VERSION"));

/// 本消费者声明的协议版本。
///
/// 取 **12**（`ProtocolVersion.v12`：包含 v6 的 metadata+payload 校验和、v5 的"不关连接即下线"、
/// v4 的 batch、v7~v12 的 lookup/last-message-id 等）。**不**声明更高的 v13+（schema/事务/
/// ack receipt 相关），避免让 broker 认为我们会用本实现没有的能力。
pub const PROTOCOL_VERSION: i32 = 12;

/// 原生 Pulsar 消费者配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulsarNativeConfig {
    /// broker 端点列表（按顺序尝试，重连时轮换）。
    pub endpoints: Vec<PulsarEndpoint>,
    /// 是否 TLS（`pulsar+ssl://`）。
    pub tls: bool,
    /// CA 证书（PEM）。
    pub tls_ca: Option<PathBuf>,
    /// 客户端证书（PEM，mTLS）。
    pub tls_cert: Option<PathBuf>,
    /// 客户端私钥（PEM）。
    pub tls_key: Option<PathBuf>,
    /// 跳过证书链校验（**只允许排障**）。
    pub tls_insecure_skip_verify: bool,
    /// 原始 URL（日志/能力矩阵展示用，**不含**凭据）。
    pub url: String,
    /// 完整 topic（`persistent://tenant/ns/topic`）。
    pub topic: String,
    /// 订阅名。
    pub subscription: String,
    /// 订阅类型。
    pub subscription_type: PulsarSubscriptionType,
    /// 首次订阅的游标位置。
    pub initial_position: PulsarInitialPosition,
    /// FLOW 许可数。
    pub receiver_queue_size: u32,
    /// token（JWT）；`Some` ⇒ 发 `auth_method_name="token"`。
    pub token: Option<String>,
    /// TCP + 握手超时。
    pub connect_timeout: Duration,
    /// 是否拆 batch。
    pub batch_split: bool,
    /// ack 模式。
    pub ack_mode: PulsarAckMode,
    /// 攒批 ack 的条数阈值（`1` = 逐条发）。
    pub ack_every: usize,
    /// 指数退避初值。
    pub reconnect_initial: Duration,
    /// 指数退避上限。
    pub reconnect_max: Duration,
    /// 最大重连次数（`0` = 永不放弃）。
    pub reconnect_max_attempts: u32,
}

impl PulsarNativeConfig {
    /// 从环境变量构造并校验。
    ///
    /// # Errors
    /// URL 非法/为空、缺 topic、枚举或数值取值非法、TLS 配置不完整。
    pub fn from_env() -> Result<Self, ConfigError> {
        let url = env_str("AGF_INGEST_PULSAR_URL").unwrap_or_default();
        let topic = env_str("AGF_INGEST_PULSAR_TOPIC").ok_or(ConfigError::Missing("AGF_INGEST_PULSAR_TOPIC"))?;
        let mut config = Self::new(&url, &topic)?;
        if let Some(value) = env_str("AGF_INGEST_PULSAR_SUBSCRIPTION") {
            config.subscription = value;
        }
        if let Some(value) = env_str("AGF_INGEST_PULSAR_SUB_TYPE") {
            config.subscription_type = PulsarSubscriptionType::parse(&value)?;
        }
        if let Some(value) = env_str("AGF_INGEST_PULSAR_INITIAL_POSITION") {
            config.initial_position = PulsarInitialPosition::parse(&value)?;
        }
        if let Some(value) = env_str("AGF_INGEST_PULSAR_ACK_MODE") {
            config.ack_mode = PulsarAckMode::parse(&value)?;
        }
        if let Some(value) = env_num::<u32>("AGF_INGEST_PULSAR_RECEIVER_QUEUE_SIZE") {
            config.receiver_queue_size = value;
        }
        if let Some(value) = env_num::<u64>("AGF_INGEST_PULSAR_CONNECT_TIMEOUT_SECS") {
            config.connect_timeout = Duration::from_secs(value.max(1));
        }
        if let Some(value) = env_num::<u64>("AGF_INGEST_PULSAR_ACK_EVERY") {
            config.ack_every = usize::try_from(value.max(1)).unwrap_or(1);
        }
        if let Some(value) = env_num::<u64>("AGF_INGEST_PULSAR_RECONNECT_INITIAL_MS") {
            config.reconnect_initial = Duration::from_millis(value.max(1));
        }
        if let Some(value) = env_num::<u64>("AGF_INGEST_PULSAR_RECONNECT_MAX_MS") {
            config.reconnect_max = Duration::from_millis(value.max(1));
        }
        if let Some(value) = env_num::<u32>("AGF_INGEST_PULSAR_RECONNECT_MAX_ATTEMPTS") {
            config.reconnect_max_attempts = value;
        }
        // `_BATCH=0` 才是关；未配置/其它值都按开（与既有 `env_flag` 语义一致）
        if let Some(value) = env_str("AGF_INGEST_PULSAR_BATCH") {
            config.batch_split = !matches!(value.trim(), "0" | "false" | "no" | "off");
        }
        config.token = env_str("AGF_INGEST_PULSAR_TOKEN");
        config.tls_ca = env_path("AGF_INGEST_PULSAR_TLS_CA");
        config.tls_cert = env_path("AGF_INGEST_PULSAR_TLS_CERT");
        config.tls_key = env_path("AGF_INGEST_PULSAR_TLS_KEY");
        config.tls_insecure_skip_verify = env_str("AGF_INGEST_PULSAR_TLS_INSECURE_SKIP_VERIFY")
            .is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"));
        config.validate()?;
        Ok(config)
    }

    /// 由 URL + topic 构造（其余取默认值；不读环境变量，便于单测）。
    ///
    /// # Errors
    /// URL 非法/为空、topic 为空。
    pub fn new(url: &str, topic: &str) -> Result<Self, ConfigError> {
        let (endpoints, tls) = parse_pulsar_url(url)?;
        let topic = normalize_topic(topic);
        if topic.is_empty() {
            return Err(ConfigError::Missing("AGF_INGEST_PULSAR_TOPIC"));
        }
        let config = Self {
            endpoints,
            tls,
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            tls_insecure_skip_verify: false,
            url: url.trim().to_string(),
            topic,
            subscription: "agf-ingest".to_string(),
            subscription_type: PulsarSubscriptionType::Exclusive,
            initial_position: PulsarInitialPosition::Latest,
            receiver_queue_size: 1000,
            token: None,
            connect_timeout: Duration::from_secs(10),
            batch_split: true,
            ack_mode: PulsarAckMode::Individual,
            ack_every: 1,
            reconnect_initial: Duration::from_millis(500),
            reconnect_max: Duration::from_secs(30),
            reconnect_max_attempts: 0,
        };
        config.validate()?;
        Ok(config)
    }

    /// 校验（构造后调用；`from_env`/`new` 都会调）。
    ///
    /// # Errors
    /// 订阅名为空、许可数为 0、退避区间倒置、topic 域名非法、TLS 证书/私钥不成对。
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.subscription.trim().is_empty() {
            return Err(ConfigError::Missing("AGF_INGEST_PULSAR_SUBSCRIPTION"));
        }
        if self.receiver_queue_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "RECEIVER_QUEUE_SIZE",
                value: "0".to_string(),
                expected: ">= 1",
            });
        }
        if self.reconnect_max < self.reconnect_initial {
            return Err(ConfigError::InvalidValue {
                field: "RECONNECT_MAX_MS",
                value: self.reconnect_max.as_millis().to_string(),
                expected: ">= RECONNECT_INITIAL_MS",
            });
        }
        if !topic_is_valid(&self.topic) {
            return Err(ConfigError::BadUrl(format!("topic 名非法：{}", self.topic)));
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err(ConfigError::IncompleteTls(
                "mTLS 必须同时提供 AGF_INGEST_PULSAR_TLS_CERT 与 AGF_INGEST_PULSAR_TLS_KEY".to_string(),
            ));
        }
        if !self.tls && (self.tls_ca.is_some() || self.tls_cert.is_some()) {
            return Err(ConfigError::IncompleteTls(
                "配置了 TLS 证书但 URL 不是 pulsar+ssl://（证书会被忽略；请改正 scheme 或去掉证书）".to_string(),
            ));
        }
        Ok(())
    }

    /// 首个端点（连接用）。
    #[must_use]
    pub fn primary(&self) -> Option<&PulsarEndpoint> {
        self.endpoints.first()
    }

    /// 按尝试序号轮换端点（`attempt=0` 取第一个）。
    #[must_use]
    pub fn endpoint_for_attempt(&self, attempt: usize) -> Option<&PulsarEndpoint> {
        if self.endpoints.is_empty() {
            return None;
        }
        self.endpoints.get(attempt % self.endpoints.len())
    }

    /// 能力/日志用的一行摘要（**不含** token）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}（topic={} subscription={} sub_type={} initial={} queue={} ack={}/{} batch={} tls={}）",
            self.url,
            self.topic,
            self.subscription,
            self.subscription_type.as_str(),
            self.initial_position.as_str(),
            self.receiver_queue_size,
            self.ack_mode.as_str(),
            self.ack_every,
            if self.batch_split { "split" } else { "whole" },
            if self.tls { "on" } else { "off" }
        )
    }
}

/// 解析 `pulsar://host:6650[,host2:6650]` 或 `pulsar+ssl://host:6651`。
///
/// **拒绝** `kafka://` 等 KoP 端点（写错了要立刻看见，而不是静默按 6650 连）。
///
/// # Errors
/// URL 为空、scheme 不认识、缺端口、含空项。
pub fn parse_pulsar_url(url: &str) -> Result<(Vec<PulsarEndpoint>, bool), ConfigError> {
    let raw = url.trim();
    if raw.is_empty() {
        return Err(ConfigError::Missing("AGF_INGEST_PULSAR_URL"));
    }
    let mut endpoints = Vec::new();
    let mut tls = false;
    for (index, item) in raw.split(',').enumerate() {
        let item = item.trim();
        if item.is_empty() {
            return Err(ConfigError::BadUrl(format!("第 {} 个地址为空（逗号分隔列表里不允许空项）", index + 1)));
        }
        let (scheme, rest) = item
            .split_once("://")
            .ok_or_else(|| ConfigError::BadUrl(format!("{item:?} 缺少 scheme（应为 pulsar:// 或 pulsar+ssl://）")))?;
        let scheme = scheme.to_ascii_lowercase();
        match scheme.as_str() {
            "pulsar" => {}
            "pulsar+ssl" | "pulsar+mtls" => tls = true,
            other => {
                return Err(ConfigError::BadUrl(format!(
                    "不认识的 scheme `{other}`：原生 Pulsar 只接受 pulsar:// 或 pulsar+ssl://\
                     （KoP 的 Kafka 协议监听请用 AGF_INGEST_PULSAR_SERVICE_URL=kafka://host:19092）"
                )));
            }
        }
        let host_port = rest.trim_end_matches('/');
        let (host, port) = host_port.rsplit_once(':').ok_or_else(|| {
            ConfigError::BadUrl(format!("{item:?} 缺端口（原生 binary protocol 默认 6650 / TLS 6651）"))
        })?;
        let port: u16 =
            port.parse().map_err(|_| ConfigError::BadUrl(format!("{item:?} 的端口不是合法 u16：{port:?}")))?;
        let host = host.trim();
        if host.is_empty() {
            return Err(ConfigError::BadUrl(format!("{item:?} 缺主机名")));
        }
        endpoints.push(PulsarEndpoint { host: host.to_string(), port });
    }
    if endpoints.is_empty() {
        return Err(ConfigError::Missing("AGF_INGEST_PULSAR_URL"));
    }
    Ok((endpoints, tls))
}

/// topic 名归一化（短名 → `persistent://public/default/<短名>`）。
///
/// **保留** `persistent://` / `non-persistent://` 完整写法；`non-persistent://`
/// 本实现**不拒绝**（原生协议支持它），但会在能力矩阵里如实标注"未真测"。
#[must_use]
pub fn normalize_topic(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("persistent://") || trimmed.starts_with("non-persistent://") {
        return trimmed.to_string();
    }
    let stripped = trimmed.trim_start_matches('/');
    if stripped.contains('/') {
        // 形如 `public/default/x` 或缺 domain 的 `tenant/ns/topic` ⇒ 补 persistent://
        return format!("persistent://{stripped}");
    }
    format!("persistent://public/default/{stripped}")
}

/// topic 分段结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicParts {
    /// `persistent` / `non-persistent`。
    pub domain: String,
    /// 租户。
    pub tenant: String,
    /// 命名空间。
    pub namespace: String,
    /// topic 本地名。
    pub topic: String,
}

impl TopicParts {
    /// 完整名。
    #[must_use]
    pub fn full(&self) -> String {
        format!("{}://{}/{}/{}", self.domain, self.tenant, self.namespace, self.topic)
    }
}

/// 拆 topic 名；不合法时 `None`（调用方按配置错误处理）。
#[must_use]
pub fn topic_parts(raw: &str) -> Option<TopicParts> {
    let normalized = normalize_topic(raw);
    let (domain, rest) = normalized.split_once("://")?;
    let mut segments = rest.split('/');
    let tenant = segments.next()?.to_string();
    let namespace = segments.next()?.to_string();
    let topic = segments.next()?.to_string();
    if tenant.is_empty() || namespace.is_empty() || topic.is_empty() {
        return None;
    }
    Some(TopicParts { domain: domain.to_string(), tenant, namespace, topic })
}

/// topic 名合法性（`domain://tenant/ns/topic`，四段都非空）。
#[must_use]
pub fn topic_is_valid(raw: &str) -> bool {
    topic_parts(raw).is_some()
}

/// 两条 Pulsar 路径的选择结果（**与既有 KoP 路径并存**的判据，纯函数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PulsarRoute {
    /// 配了 `AGF_INGEST_PULSAR_URL` ⇒ 走**原生二进制协议**（显式配置优先）。
    Native,
    /// 没配原生 URL 但配了 `AGF_INGEST_PULSAR_SERVICE_URL` ⇒ 回落 **KoP**。
    Kop,
    /// 两条都没配 ⇒ 不启用。
    Disabled,
}

impl PulsarRoute {
    /// 小写名（日志/测试/能力矩阵）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Kop => "kop",
            Self::Disabled => "disabled",
        }
    }
}

/// 原生 URL 优先、KoP 兜底的路由判定（纯函数，`None`/空白 视为未配置）。
#[must_use]
pub fn pulsar_route(native_url: Option<&str>, kop_service_url: Option<&str>) -> PulsarRoute {
    let configured = |value: Option<&str>| value.map(str::trim).is_some_and(|text| !text.is_empty());
    if configured(native_url) {
        PulsarRoute::Native
    } else if configured(kop_service_url) {
        PulsarRoute::Kop
    } else {
        PulsarRoute::Disabled
    }
}

/// 能力矩阵里的 **`pulsar-native` 行**（与 KoP 行 `pulsar` **分别列出**）。
///
/// 状态口径（如实，不谎报）：
/// * `AGF_INGEST_PULSAR_URL` 未配置 ⇒ [`ReceiverStatus::NotWired`]（**代码已实现**，
///   但本进程没装配它——不说 `not-implemented`，那会让读者以为代码不存在）；
/// * 配置了且能通过校验 ⇒ [`ReceiverStatus::Ready`]，note 带出实际参数；
/// * 配置了但非法（scheme 写错 / 缺 topic / TLS 不成对）⇒ [`ReceiverStatus::NotWired`]，
///   note 一字不差带出错误原因（配置错误必须让人看见）。
#[must_use]
pub fn pulsar_native_descriptor(native_url: Option<&str>) -> crate::receiver::ReceiverDescriptor {
    use crate::receiver::{ReceiverDescriptor, ReceiverStatus};
    let configured = native_url.map(str::trim).is_some_and(|text| !text.is_empty());
    if !configured {
        return ReceiverDescriptor {
            name: "pulsar-native".to_string(),
            protocol: agf_core::enums::IngestProtocol::Pulsar,
            status: ReceiverStatus::NotWired,
            note: "**Pulsar 原生二进制协议**（binary protocol `pulsar://host:6650`）**已实现**\
                   （手写 PulsarApi 消息子集 + 帧/CRC32C + token 鉴权 + batch 拆条 + 真 ACK + 退避重连），\
                   但本进程**未装配**：未配置 `AGF_INGEST_PULSAR_URL`。\
                   与上面的 KoP 行（`AGF_INGEST_PULSAR_SERVICE_URL`）是**两条独立路径**，配了原生 URL 即优先走原生"
                .to_string(),
            todo: Some(crate::pulsar::PULSAR_NATIVE_REMAINING_TODO.to_string()),
            mock_replay: false,
        };
    }
    match PulsarNativeConfig::from_env() {
        Ok(config) => ReceiverDescriptor {
            name: "pulsar-native".to_string(),
            protocol: agf_core::enums::IngestProtocol::Pulsar,
            status: ReceiverStatus::Ready,
            note: format!(
                "**Pulsar 原生二进制协议**（`pulsar://`，非 KoP，`AGF_INGEST_PULSAR_URL`）：{}；\
                 CONNECT/CONNECTED + SUBSCRIBE/SUCCESS + FLOW + MESSAGE + `CommandAck`（真发，可用 \
                 `pulsar-admin topics stats` 的 msgBacklog 归零证明）+ batch 拆条 + CRC32C 校验 + \
                 `CommandError` 分类 + 指数退避重连；{}",
                config.describe(),
                crate::pulsar::PULSAR_NATIVE_REMAINING_TODO
            ),
            todo: Some(crate::pulsar::PULSAR_NATIVE_REMAINING_TODO.to_string()),
            mock_replay: false,
        },
        Err(error) => ReceiverDescriptor {
            name: "pulsar-native".to_string(),
            protocol: agf_core::enums::IngestProtocol::Pulsar,
            status: ReceiverStatus::NotWired,
            note: format!("Pulsar 原生协议已实现，但配置非法 ⇒ 未装配：{error}"),
            todo: Some(crate::pulsar::PULSAR_NATIVE_REMAINING_TODO.to_string()),
            mock_replay: false,
        },
    }
}

/// 解析 LOOKUP 应答里的 broker URL（`pulsar://host:6650` / `pulsar+ssl://host:6651` / `host:6650`）。
///
/// 与 [`parse_pulsar_url`] 的区别：这里**只有单个地址**、且允许没有 scheme
/// （部分 broker/代理会返回裸 `host:port`）；解析不了返回 `None`（调用方按协议错误处理）。
#[must_use]
pub fn parse_lookup_url(url: &str) -> Option<(PulsarEndpoint, bool)> {
    let raw = url.trim().trim_end_matches('/');
    if raw.is_empty() {
        return None;
    }
    let (rest, tls) = match raw.split_once("://") {
        Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
            "pulsar" => (rest, false),
            "pulsar+ssl" | "pulsar+mtls" => (rest, true),
            _ => return None,
        },
        None => (raw, false),
    };
    let (host, port) = rest.rsplit_once(':')?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.trim().parse().ok()?;
    Some((PulsarEndpoint { host: host.to_string(), port }, tls))
}

/// 读字符串型环境变量（空串视为未配置）。
fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

/// 读路径型环境变量。
fn env_path(key: &str) -> Option<PathBuf> {
    env_str(key).map(PathBuf::from)
}

/// 读数字型环境变量（缺失/非法 ⇒ `None`，由调用方决定默认值与是否 warn）。
fn env_num<T: std::str::FromStr>(key: &str) -> Option<T> {
    env_str(key).and_then(|value| match value.parse::<T>() {
        Ok(parsed) => Some(parsed),
        Err(_) => {
            tracing::warn!(key, raw = %value, "Pulsar 原生配置项不是合法数字，忽略该值并使用默认");
            None
        }
    })
}

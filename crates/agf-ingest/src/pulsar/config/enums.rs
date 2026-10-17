//! 原生 Pulsar 的配置取值类型：错误分类、端点、订阅类型、起始位置、ack 模式。
//!
//! 从 `pulsar/config.rs` 拆出来（该文件会被仓库的**单文件 500 行**门禁卡住）；
//! 这里只有取值类型与解析/渲染，不含 env 读取与校验逻辑。

use crate::pulsar::proto;

/// 配置错误（**分类**：非法 URL / 缺必填 / 数值非法）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// URL 为空或 scheme 不认识。
    BadUrl(String),
    /// 缺必填项（如 topic）。
    Missing(&'static str),
    /// 数值/枚举取值非法。
    InvalidValue {
        /// 字段名（env 名后缀）。
        field: &'static str,
        /// 原始取值。
        value: String,
        /// 期望形式。
        expected: &'static str,
    },
    /// TLS 配置不完整（`pulsar+ssl://` 但客户端证书/私钥只给了一个）。
    IncompleteTls(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(reason) => write!(f, "Pulsar 原生 URL 非法：{reason}"),
            Self::Missing(field) => write!(f, "Pulsar 原生消费者缺少必填配置：{field}"),
            Self::InvalidValue { field, value, expected } => {
                write!(f, "Pulsar 配置 {field}={value:?} 非法（期望 {expected}）")
            }
            Self::IncompleteTls(reason) => write!(f, "Pulsar TLS 配置不完整：{reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// 单个 broker 端点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulsarEndpoint {
    /// 主机名或 IP。
    pub host: String,
    /// 端口。
    pub port: u16,
}

impl PulsarEndpoint {
    /// `host:port`。
    #[must_use]
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// 订阅类型（`CommandSubscribe.SubType`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PulsarSubscriptionType {
    /// `Exclusive = 0`（默认）：同订阅只允许一个消费者。
    Exclusive,
    /// `Shared = 1`：多副本竞争消费（**多副本推荐**）。
    Shared,
    /// `Failover = 2`：主备。
    Failover,
    /// `Key_Shared = 3`：按 key 分派（本消费者**不**做 key 分派假设，仅向 broker 声明）。
    KeyShared,
}

impl PulsarSubscriptionType {
    /// 解析（大小写不敏感；`key-shared`/`key_shared` 都接受）。
    ///
    /// # Errors
    /// 取值不认识。
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "exclusive" => Ok(Self::Exclusive),
            "shared" => Ok(Self::Shared),
            "failover" => Ok(Self::Failover),
            "key_shared" | "keyshared" => Ok(Self::KeyShared),
            other => Err(ConfigError::InvalidValue {
                field: "SUB_TYPE",
                value: other.to_string(),
                expected: "exclusive|shared|failover|key_shared",
            }),
        }
    }

    /// 协议枚举值。
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Exclusive => proto::sub_type::EXCLUSIVE,
            Self::Shared => proto::sub_type::SHARED,
            Self::Failover => proto::sub_type::FAILOVER,
            Self::KeyShared => proto::sub_type::KEY_SHARED,
        }
    }

    /// 小写名（日志/指标/能力矩阵）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::Shared => "shared",
            Self::Failover => "failover",
            Self::KeyShared => "key_shared",
        }
    }
}

/// 首次建订阅时的游标位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PulsarInitialPosition {
    /// `Latest = 0`
    Latest,
    /// `Earliest = 1`
    Earliest,
}

impl PulsarInitialPosition {
    /// 解析（`latest` / `earliest`）。
    ///
    /// # Errors
    /// 取值不认识。
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "latest" => Ok(Self::Latest),
            "earliest" => Ok(Self::Earliest),
            other => Err(ConfigError::InvalidValue {
                field: "INITIAL_POSITION",
                value: other.to_string(),
                expected: "latest|earliest",
            }),
        }
    }

    /// 协议枚举值。
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Latest => proto::initial_position::LATEST,
            Self::Earliest => proto::initial_position::EARLIEST,
        }
    }

    /// 小写名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latest => "latest",
            Self::Earliest => "earliest",
        }
    }
}

/// ack 模式（`CommandAck.AckType`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PulsarAckMode {
    /// `Individual = 0`：逐条 ack（默认；`message_id` 列表可攒批）。
    Individual,
    /// `Cumulative = 1`：累积 ack（只需发最新一条 id，broker 把之前的都算已读）。
    Cumulative,
}

impl PulsarAckMode {
    /// 解析（`individual` / `cumulative`）。
    ///
    /// # Errors
    /// 取值不认识。
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "individual" => Ok(Self::Individual),
            "cumulative" => Ok(Self::Cumulative),
            other => Err(ConfigError::InvalidValue {
                field: "ACK_MODE",
                value: other.to_string(),
                expected: "individual|cumulative",
            }),
        }
    }

    /// 协议枚举值。
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Individual => proto::ack_type::INDIVIDUAL,
            Self::Cumulative => proto::ack_type::CUMULATIVE,
        }
    }

    /// 小写名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Cumulative => "cumulative",
        }
    }
}

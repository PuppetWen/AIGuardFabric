//! JetStream 纯数据 / 纯函数层：订阅模式、应答动作、durable stream/consumer 幂等计划。
//!
//! 本模块**不**触碰 `async-nats`，可在无连接下直接断言（离线单测）。

use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use serde::{Deserialize, Serialize};

/// 默认流名前缀。
pub const DEFAULT_STREAM_PREFIX: &str = "AGF_INGEST";
/// 默认消费者名前缀（durable 名 = `前缀-日志源 id`，进程重启可续投）。
pub const DEFAULT_CONSUMER_PREFIX: &str = "agf-ingest";
/// 默认每批最多拉取条数（背压阀）。
pub const DEFAULT_BATCH_SIZE: usize = 256;

/// 订阅模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JetMode {
    /// 批量拉取（durable pull consumer）。
    Pull,
    /// 服务端推送（durable push consumer，显式应答）。
    Push,
}

impl JetMode {
    /// 文本形式（日志 / 能力矩阵用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
        }
    }
}

/// 消息应答动作（映射 JetStream `AckKind` 语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JetAckAction {
    /// 处理完成。
    Ack,
    /// 暂态失败，稍后重投。
    Nak,
    /// 终止投递（毒消息 / 超过最大重投次数）。
    Term,
}

impl JetAckAction {
    /// 文本形式（指标与日志用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Nak => "nak",
            Self::Term => "term",
        }
    }

    /// 按接入结果决定应答动作（纯函数）：
    /// - 落库失败 ⇒ [`JetAckAction::Nak`]（暂态错误重投）；
    /// - 无记录可拆（空载荷/超限）⇒ [`JetAckAction::Term`]（永远不会有内容，重投无意义）；
    /// - 已重投达 `max_deliver` 次仍解析/拆分失败 ⇒ [`JetAckAction::Term`]（毒消息）；
    /// - 其余 ⇒ [`JetAckAction::Ack`]。
    #[must_use]
    pub const fn decide(report: &super::JetIngestReport, delivered: i64, max_deliver: i64) -> Self {
        if report.persist_failed {
            Self::Nak
        } else if report.records == 0 || (max_deliver > 0 && delivered >= max_deliver) {
            Self::Term
        } else {
            Self::Ack
        }
    }
}

/// 解析 NATS 服务器地址列表（纯函数；逗号分隔，形如 `nats://host:4222`）。
///
/// # Errors
/// 列表为空或含空项。
pub fn parse_nats_urls(endpoint: &str) -> DomainResult<Vec<String>> {
    let urls: Vec<String> =
        endpoint.split(',').map(str::trim).filter(|u| !u.is_empty()).map(ToString::to_string).collect();
    if urls.is_empty() {
        return Err(DomainError::Config("JetStream 需要 connection.endpoint（NATS 地址列表，逗号分隔）".to_string()));
    }
    Ok(urls)
}

/// JetStream 单条消息（协议无关快照：可注入实现与 `async-nats` 共用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetMessage {
    /// 投递主题。
    pub subject: String,
    /// 载荷。
    pub payload: Vec<u8>,
    /// 已投递次数（1 = 首次；>1 为 nak/超时重投）。
    pub delivered: i64,
    /// 流内序号（幂等游标观测用）。
    pub stream_sequence: u64,
}
/// durable stream 声明（幂等：同名重复创建返回既有 stream）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPlan {
    /// stream 名。
    pub name: String,
    /// 绑定的 subject 列表。
    pub subjects: Vec<String>,
    /// 保留策略（`limits` / `interest` / `workqueue`）。
    pub retention: String,
    /// 存储（`file` / `memory`）。
    pub storage: String,
    /// 最大消息数（-1 = 不限）。
    pub max_messages: i64,
    /// 去重窗口（纳秒）。
    pub duplicate_window_nanos: u64,
}

impl StreamPlan {
    /// 默认计划：`AGF_INGEST-<sanitized 日志源 id>` 绑定 `<subject 前缀>.<日志源 id>`。
    ///
    /// 缺省 subject 前缀为 `agf.ingest`（即默认绑定 `agf.ingest.<日志源 id>`）。
    ///
    /// **注意**：`LogSource::id` 是每次进程启动新生成的 UUID，因此本函数**只适合离线测试/一次性场景**。
    /// 真机装配（要求"中断重启不丢"）必须用 [`StreamPlan::for_identity`]。
    #[must_use]
    pub fn for_source(source: &LogSource, subject_prefix: &str) -> Self {
        let prefix = if subject_prefix.trim().is_empty() { "agf.ingest" } else { subject_prefix.trim() };
        Self {
            name: format!("{DEFAULT_STREAM_PREFIX}-{}", sanitize_token(&source.id.to_string())),
            subjects: vec![format!("{prefix}.{}", source.id)],
            retention: "limits".to_string(),
            storage: "file".to_string(),
            max_messages: -1,
            duplicate_window_nanos: 120_000_000_000,
        }
    }

    /// 由**稳定标识**构造计划（进程重启后 stream/consumer 名不变 ⇒ durable 续投成立）。
    ///
    /// `identity` 来自配置（`AGF_INGEST_JETSTREAM_IDENTITY`，默认 `default`），
    /// **不**来自 `LogSource::id`。stream 名 = `AGF_INGEST-<sanitized identity>`，
    /// 与 [`ConsumerPlan::for_identity`] 的 durable 名（`agf-ingest-<sanitized identity>`）
    /// 满足 `nats_impl` 的 `stream(durable)` 约定（有单测钉住）。
    #[must_use]
    pub fn for_identity(identity: &str, subject: &str) -> Self {
        let token = sanitize_token(identity);
        Self {
            name: format!("{DEFAULT_STREAM_PREFIX}-{token}"),
            subjects: vec![subject.to_string()],
            retention: "limits".to_string(),
            storage: "file".to_string(),
            max_messages: -1,
            duplicate_window_nanos: 120_000_000_000,
        }
    }
}

/// durable consumer 声明（幂等：同名重复创建返回既有 consumer）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerPlan {
    /// durable 名。
    pub durable_name: String,
    /// 订阅模式。
    pub mode: JetMode,
    /// 过滤 subject（空 = stream 全量）。
    pub filter_subject: String,
    /// push 模式的 deliver subject（pull 模式为空）。
    pub deliver_subject: String,
    /// 应答策略（`explicit`；ack/nak/term 均由接收器显式发出）。
    pub ack_policy: String,
    /// 投递起始（`all`）。
    pub deliver_policy: String,
    /// 应答超时（秒）：超时未 ack 自动重投。
    pub ack_wait_secs: u64,
    /// 最大重投次数（<=0 = 不限）。
    pub max_deliver: i64,
    /// 拉取批次上限（pull 模式背压阀；push 模式作流控提示）。
    pub batch_size: usize,
}

impl ConsumerPlan {
    /// 默认计划：`agf-ingest-<sanitized 日志源 id>`，显式应答，30s 应答窗口。
    ///
    /// 同 [`StreamPlan::for_source`]：依赖随机 `LogSource::id`，真机装配请用
    /// [`ConsumerPlan::for_identity`]。
    #[must_use]
    pub fn for_source(source: &LogSource, mode: JetMode, filter_subject: &str, batch_size: usize) -> Self {
        let durable = format!("{DEFAULT_CONSUMER_PREFIX}-{}", sanitize_token(&source.id.to_string()));
        let deliver_subject = match mode {
            JetMode::Push => format!("agf.deliver.{}", source.id),
            JetMode::Pull => String::new(),
        };
        Self {
            durable_name: durable,
            mode,
            filter_subject: filter_subject.to_string(),
            deliver_subject,
            ack_policy: "explicit".to_string(),
            deliver_policy: "all".to_string(),
            ack_wait_secs: 30,
            max_deliver: 8,
            batch_size: batch_size.max(1),
        }
    }

    /// 由**稳定标识**构造计划（durable 名 = `agf-ingest-<sanitized identity>`）。
    ///
    /// 名字只由配置决定 ⇒ 进程重启后服务端**复用同一个 durable consumer**，
    /// 从 ack floor 续投（已 ack 的不重投、未 ack 的不丢）——这是"中断重启不丢"的前提。
    #[must_use]
    pub fn for_identity(identity: &str, mode: JetMode, filter_subject: &str, batch_size: usize) -> Self {
        let token = sanitize_token(identity);
        let deliver_subject = match mode {
            JetMode::Push => format!("agf.deliver.{token}"),
            JetMode::Pull => String::new(),
        };
        Self {
            durable_name: format!("{DEFAULT_CONSUMER_PREFIX}-{token}"),
            mode,
            filter_subject: filter_subject.to_string(),
            deliver_subject,
            ack_policy: "explicit".to_string(),
            deliver_policy: "all".to_string(),
            ack_wait_secs: 30,
            max_deliver: 8,
            batch_size: batch_size.max(1),
        }
    }
}

/// stream / consumer 名 token 清洗（NATS token 不允许 `.` / 空白 / `*` / `>`）。
#[must_use]
pub fn sanitize_token(raw: &str) -> String {
    raw.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect()
}

/// durable consumer 名 → 它所属的 stream 名（`agf-ingest-x` ⇒ `AGF_INGEST-x`）。
///
/// 这是 `nats_impl` 里 `ensure_consumer`/`fetch_batch`/`next_push` 与
/// [`StreamPlan::for_identity`] 共用的**唯一命名约定**；单测钉住，避免两处各写一套。
#[must_use]
pub fn stream_name_for_durable(durable: &str) -> String {
    let suffix = durable.strip_prefix(DEFAULT_CONSUMER_PREFIX).unwrap_or(durable).trim_start_matches('-');
    format!("{DEFAULT_STREAM_PREFIX}-{suffix}")
}

/// stream 状态快照（`/readyz` 与日志用）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JetStreamState {
    /// 流内消息数。
    pub messages: u64,
    /// 流内字节数。
    pub bytes: u64,
    /// 最新序号。
    pub last_sequence: u64,
    /// consumer 数。
    pub consumer_count: usize,
}

/// consumer 投递统计快照（真机排障与"至少一次"验证的**判据**）。
///
/// * [`Self::num_pending`]：还没投出去的消息数（ack 后应归零）；
/// * [`Self::num_ack_pending`]：已投出但**尚未应答**的数量（`ack()` 空实现时它会一直 > 0）；
/// * [`Self::num_redelivered`]：累计重投次数（`ack()` 空实现 / nak 会让它单调增长）；
/// * [`Self::ack_floor_stream_seq`]：应答水位（term/ack 后前进；nak 不动）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JetConsumerStats {
    /// 未投递消息数。
    pub num_pending: u64,
    /// 已投递未应答数。
    pub num_ack_pending: u64,
    /// 累计重投数。
    pub num_redelivered: u64,
    /// 已投递到的流内序号。
    pub delivered_stream_seq: u64,
    /// 应答水位（流内序号）。
    pub ack_floor_stream_seq: u64,
    /// 等待中的 pull 请求数。
    pub num_waiting: usize,
}

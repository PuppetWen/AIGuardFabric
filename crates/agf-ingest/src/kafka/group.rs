//! Kafka **真消费者组协议**（broker 侧协调器 + 组内分区分配），作为 `rskafka` 本地游标路径之上的可选模式。
//!
//! ## 与既有"本地游标 + 自研 lease"路径的关系（两条路径的差异，如实）
//!
//! | 维度 | 组协议路径（本模块，需配 `AGF_INGEST_KAFKA_GROUP_ID`） | 本地游标路径（默认，`rskafka`） |
//! |---|---|---|
//! | 分区分配 | **组协调器 + 组长下发**（`JoinGroup`→`SyncGroup`，本模块实现 range/roundrobin 分配器） | 本接收器自己算：静态取模 `p % instance_count`，配 `LEASE_DIR` 后升级为心跳租约接管 |
//! | offset 存放 | **broker 侧 `__consumer_offsets`**（`OffsetCommit`/`OffsetFetch`），`kafka-consumer-groups.sh` 可见 | 本地/共享目录里的 JSON 游标文件 |
//! | 代际栅栏 | **有**：`generation_id` + `member_id`，过期成员的提交被协调器拒绝 | 无：副本增减的瞬时重分片存在 ≤1 个轮询间隔的重叠窗口（靠流水线去重兜住） |
//! | 成员判活 | `session.timeout.ms` + `heartbeat.interval.ms`（协调器判定并触发 rebalance） | `LEASE_TTL_MS` 租约文件判活（共享目录可达性是前提） |
//! | 接管延迟 | 主动 `LeaveGroup` ⇒ 立即 rebalance；否则 `session.timeout.ms` 封顶 | `LEASE_TTL_MS` + 一个轮询间隔 |
//! | 适用面 | 真 Kafka、KoP（Kafka on Pulsar，已实测） | 任何 Kafka 协议实现；**离线/无协调器也不影响启动** |
//! | 依赖 | `kafka-protocol`（报文编解码）+ 自实现的连接/协商/状态机 | `rskafka`（wire 直连，无消费者组） |
//!
//! **降级规则**：`AGF_INGEST_KAFKA_GROUP_ID` 未配置（或为空）⇒ 行为与历史版本**逐字节一致**
//! （走 `RskafkaSource` + 本地游标）；配置了才走本模块。两条路径的**至少一次语义与流水线去重口径相同**。
//!
//! ## 协议闭环（全部落在本模块）
//!
//! `ApiVersions` → `FindCoordinator` → `JoinGroup` → `SyncGroup` → `Heartbeat` → `OffsetFetch` →
//! `Fetch` → `OffsetCommit` → `LeaveGroup`。逐步骤的实现与语义见 [`session`]。
//!
//! ## 配置
//!
//! | 环境变量 | 默认 | 说明 |
//! |---|---|---|
//! | `AGF_INGEST_KAFKA_GROUP_ID` | 空 | **空 = 关闭组协议**（走本地游标）；非空 = 启用 |
//! | `..._SESSION_TIMEOUT_MS` | 45000 | 协调器判成员死亡的超时 |
//! | `..._HEARTBEAT_INTERVAL_MS` | 3000 | 心跳间隔（必须 < session/3） |
//! | `..._MAX_POLL_INTERVAL_MS` | 300000 | 单轮处理上限；超过则主动退组重入 |
//! | `..._REBALANCE_TIMEOUT_MS` | 60000 | JoinGroup 等待成员到齐的上限 |
//! | `..._ASSIGNOR` | `range` | `range` / `roundrobin` |
//! | `..._GROUP_MEMBER_ID` | 空 | 预置成员 id（一般留空，由协调器分配） |
//!
//! KoP（`--profile pulsar`）用同一套开关，前缀换成 `AGF_INGEST_PULSAR`。

use super::*;

mod assign;
mod codec;
mod session;
mod session_join;
mod session_offset;
mod wire;

pub use assign::{
    AssignmentPlan, GroupAssignor, GroupMember, RebalanceTrigger, assign_partitions, choose_start_offset, error_code,
    heartbeat_due, poll_interval_exceeded, rebalance_trigger, validate_group_timing, verify_plan,
};
pub use session::KafkaGroupSnapshot;

use session::GroupSession;

// ---------------------------------------------------------------------------
// 消费者协议编解码的公开镜像（单测与端到端自检用；实现仍只有 `codec` 里那一份）
// ---------------------------------------------------------------------------

/// 编码成员订阅元数据（`ConsumerProtocolSubscription` v0）为原始字节。
#[must_use]
pub fn encode_subscription_metadata(topics: &[String]) -> Vec<u8> {
    codec::encode_subscription(topics).to_vec()
}

/// 解码成员订阅元数据；返回订阅的 topic 列表。
///
/// # Errors
/// 字节串不是合法的 `ConsumerProtocolSubscription`。
pub fn decode_subscription_metadata(bytes: &[u8]) -> DomainResult<Vec<String>> {
    codec::decode_subscription(&bytes::Bytes::copy_from_slice(bytes))
}

/// 编码分区分配（`ConsumerProtocolAssignment` v0）为原始字节。
#[must_use]
pub fn encode_assignment_metadata(assigned: &[(String, i32)]) -> Vec<u8> {
    codec::encode_assignment(assigned).to_vec()
}

/// 解码分区分配；返回 `[(topic, partition)]`。
///
/// # Errors
/// 字节串不是合法的 `ConsumerProtocolAssignment`。
pub fn decode_assignment_metadata(bytes: &[u8]) -> DomainResult<Vec<(String, i32)>> {
    codec::decode_assignment(&bytes::Bytes::copy_from_slice(bytes))
}

/// 消费者组配置（`AGF_INGEST_KAFKA_GROUP_ID` 系列）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaGroupConfig {
    /// `group.id`（**组协议的开关**：非空才启用）。
    pub group_id: String,
    /// 客户端 id（broker 侧排障用；与 `KafkaPullConfig::client_id` 一致）。
    pub client_id: String,
    /// `session.timeout.ms`。
    pub session_timeout_ms: i32,
    /// `heartbeat.interval.ms`。
    pub heartbeat_interval_ms: i32,
    /// `max.poll.interval.ms`。
    pub max_poll_interval_ms: i32,
    /// `rebalance.timeout.ms`（JoinGroup 等待成员到齐的上限）。
    pub rebalance_timeout_ms: i32,
    /// 分配器（组长用它计算分配）。
    pub assignor: GroupAssignor,
    /// 预置成员 id（`None`/空 = 由协调器分配，正常路径）。
    pub member_id: Option<String>,
}

impl Default for KafkaGroupConfig {
    fn default() -> Self {
        Self {
            group_id: String::new(),
            client_id: "agf-ingest".to_string(),
            session_timeout_ms: 45_000,
            heartbeat_interval_ms: 3_000,
            max_poll_interval_ms: 300_000,
            rebalance_timeout_ms: 60_000,
            assignor: GroupAssignor::Range,
            member_id: None,
        }
    }
}

impl KafkaGroupConfig {
    /// 是否启用组协议（`group.id` 非空）。
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.group_id.trim().is_empty()
    }

    /// 从环境变量读取（`prefix` 形如 `AGF_INGEST_KAFKA` / `AGF_INGEST_PULSAR`）。
    ///
    /// **未配置 `{prefix}_GROUP_ID` ⇒ 返回 `None`**：这正是"未配置时行为不变"的判定点。
    #[must_use]
    pub fn from_env(prefix: &str, default_client_id: &str) -> Option<Self> {
        let group_id = std::env::var(format!("{prefix}_GROUP_ID")).ok()?;
        if group_id.trim().is_empty() {
            return None;
        }
        let number = |suffix: &str, fallback: i32| -> i32 {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .and_then(|value| value.trim().parse::<i32>().ok())
                .unwrap_or(fallback)
        };
        let assignor = std::env::var(format!("{prefix}_ASSIGNOR"))
            .ok()
            .and_then(|value| GroupAssignor::parse(&value))
            .unwrap_or_default();
        Some(Self {
            group_id: group_id.trim().to_string(),
            client_id: std::env::var(format!("{prefix}_GROUP_CLIENT_ID"))
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| default_client_id.to_string()),
            session_timeout_ms: number("SESSION_TIMEOUT_MS", 45_000),
            heartbeat_interval_ms: number("HEARTBEAT_INTERVAL_MS", 3_000),
            max_poll_interval_ms: number("MAX_POLL_INTERVAL_MS", 300_000),
            rebalance_timeout_ms: number("REBALANCE_TIMEOUT_MS", 60_000),
            assignor,
            member_id: std::env::var(format!("{prefix}_MEMBER_ID")).ok().filter(|value| !value.trim().is_empty()),
        })
    }

    /// 一句话描述（日志 / `/readyz` / 能力矩阵）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "消费者组 {}（session={}ms，heartbeat={}ms，max.poll={}ms，rebalance={}ms，分配器={}，成员 id={}）",
            self.group_id,
            self.session_timeout_ms,
            self.heartbeat_interval_ms,
            self.max_poll_interval_ms,
            self.rebalance_timeout_ms,
            self.assignor.as_str(),
            self.member_id.as_deref().unwrap_or("<协调器分配>")
        )
    }
}

/// 组协议数据源：实现 [`KafkaSource`]，因此**接收器的拉取/落库/停机逻辑一行不改**。
pub struct KafkaGroupSource {
    session: tokio::sync::Mutex<GroupSession>,
    config: KafkaPullConfig,
    group: KafkaGroupConfig,
    label: String,
}

impl std::fmt::Debug for KafkaGroupSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaGroupSource")
            .field("label", &self.label)
            .field("group", &self.group.group_id)
            .field("assignor", &self.group.assignor.as_str())
            .finish_non_exhaustive()
    }
}

impl KafkaGroupSource {
    /// 建连并进入组协议路径（真正的 `JoinGroup` 在第一次 `partitions()` 时发生）。
    ///
    /// # Errors
    /// `group.id` 为空、时长参数非法、broker 列表为空，或 TLS/SASL 配置错误。
    pub fn connect(config: KafkaPullConfig, group: KafkaGroupConfig) -> DomainResult<Self> {
        if config.brokers.is_empty() {
            return Err(DomainError::Config("Kafka 需要至少一个 broker".to_string()));
        }
        let security = KafkaSecurity::from_config(&config);
        let label = format!("kafka://{}（组 {}）", config.brokers.join(","), group.group_id);
        let session = GroupSession::new(config.brokers.clone(), security, config.client_id(), group.clone())?;
        Ok(Self { session: tokio::sync::Mutex::new(session), config, group, label })
    }

    /// 组配置。
    #[must_use]
    pub const fn group_config(&self) -> &KafkaGroupConfig {
        &self.group
    }

    /// 组会话快照（`/stats` 与端到端断言用）。
    pub async fn snapshot(&self) -> KafkaGroupSnapshot {
        self.session.lock().await.snapshot()
    }

    /// 订阅的 topic（组订阅集）。
    fn topics(&self) -> Vec<String> {
        vec![self.config.topic.clone()]
    }
}

#[async_trait]
impl KafkaSource for KafkaGroupSource {
    async fn partitions(&self, topic: &str) -> DomainResult<Vec<i32>> {
        let mut session = self.session.lock().await;
        session.ensure_joined(&self.topics()).await?;
        let mut partitions: Vec<i32> = session
            .snapshot()
            .assignment
            .into_iter()
            .filter(|(assigned, _)| assigned == topic)
            .map(|(_, partition)| partition)
            .collect();
        partitions.sort_unstable();
        partitions.dedup();
        Ok(partitions)
    }

    async fn resolve_offset(&self, topic: &str, partition: i32, at: KafkaStartFrom) -> DomainResult<i64> {
        self.session.lock().await.resolve_offset(topic, partition, at).await
    }

    async fn fetch(
        &self,
        topic: &str,
        partition: i32,
        offset: i64,
        max_bytes: i32,
        max_wait_ms: i32,
    ) -> DomainResult<KafkaBatch> {
        self.session.lock().await.fetch(topic, partition, offset, max_bytes, max_wait_ms).await
    }

    fn describe(&self) -> String {
        format!("{}；{}", self.label, self.group.describe())
    }

    fn commits_to_broker(&self) -> bool {
        true
    }

    async fn maintain_session(&self) -> DomainResult<()> {
        let topics = self.topics();
        self.session.lock().await.maintain(&topics).await
    }

    async fn commit_offsets(&self, commits: &[KafkaOffsetCommit]) -> DomainResult<()> {
        let entries: Vec<(String, i32, i64)> =
            commits.iter().map(|commit| (commit.topic.clone(), commit.partition, commit.offset)).collect();
        self.session.lock().await.commit(&entries).await
    }

    async fn close_session(&self) -> DomainResult<()> {
        // 停机：先把内存里的进度提交一次，再 LeaveGroup（同伴立即 rebalance 接管）
        let mut session = self.session.lock().await;
        session.commit_pending().await?;
        session.leave().await;
        Ok(())
    }
}

/// `KafkaGroupSource` 的唯一构造入口（按 `KafkaPullConfig` 里的 brokers/安全配置装配）。
///
/// # Errors
/// 配置非法（见 [`KafkaGroupSource::connect`]）。
pub fn group_source(config: KafkaPullConfig, group: KafkaGroupConfig) -> DomainResult<KafkaGroupSource> {
    KafkaGroupSource::connect(config, group)
}

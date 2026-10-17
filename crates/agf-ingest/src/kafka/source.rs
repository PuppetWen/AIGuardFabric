//! Kafka 数据源抽象 `KafkaSource` 与 `rskafka` 纯 Rust 实现 `RskafkaSource`（broker 列表解析、分区探测、错误映射）。

use super::group::{KafkaGroupConfig, KafkaGroupSource};
use super::*;

/// 一次 broker 侧 offset 提交（组协议路径专用；本地游标路径不用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaOffsetCommit {
    /// topic。
    pub topic: String,
    /// 分区号。
    pub partition: i32,
    /// **下一个待消费 offset**（= 最后一条已消费记录 offset + 1，与 Kafka 语义一致）。
    pub offset: i64,
}

/// Kafka 数据源抽象（真实实现走 `rskafka`；测试注入内存实现，**测试不依赖 docker**）。
///
/// **组协议扩展点**（默认实现 = 本地游标路径的既有行为，逐字节不变）：
/// [`Self::commits_to_broker`] / [`Self::maintain_session`] / [`Self::commit_offsets`] /
/// [`Self::close_session`]。只有 `KafkaGroupSource` 覆写它们。
#[async_trait]
pub trait KafkaSource: Send + Sync + std::fmt::Debug {
    /// 列出 topic 的分区号（升序）。
    ///
    /// 组协议路径下这里返回的是**协调器分配（SyncGroup）给本成员的分区**，不是 topic 全部分区。
    ///
    /// # Errors
    /// broker 不可达或 topic 不存在。
    async fn partitions(&self, topic: &str) -> DomainResult<Vec<i32>>;

    /// 解析起始 offset。
    ///
    /// # Errors
    /// broker 不可达或分区不存在。
    async fn resolve_offset(&self, topic: &str, partition: i32, at: KafkaStartFrom) -> DomainResult<i64>;

    /// 从 `offset` 拉取一批记录。
    ///
    /// # Errors
    /// broker 不可达、offset 越界（超出保留窗口）或分区不存在。
    async fn fetch(
        &self,
        topic: &str,
        partition: i32,
        offset: i64,
        max_bytes: i32,
        max_wait_ms: i32,
    ) -> DomainResult<KafkaBatch>;

    /// 描述（`/readyz` 与日志用）。
    fn describe(&self) -> String;

    /// 进度是否提交到 **broker**（`true` = 消费者组协议路径）。
    ///
    /// 默认 `false`：本地游标路径（游标落盘，不提交）。组协议路径覆写为 `true`，
    /// 接收器据此在 `/stats` 与日志里如实标注"offset 在 `__consumer_offsets`"。
    fn commits_to_broker(&self) -> bool {
        false
    }

    /// 会话续期（组协议路径 = 心跳与 rebalance 处理；本地游标路径 = 空操作）。
    ///
    /// # Errors
    /// 组协议路径下协调器不可达或入组失败。
    async fn maintain_session(&self) -> DomainResult<()> {
        Ok(())
    }

    /// 把已消费进度提交到 broker（本地游标路径 = 空操作，行为不变）。
    ///
    /// # Errors
    /// 协调器拒绝提交（代际过期）或连接失败。
    async fn commit_offsets(&self, commits: &[KafkaOffsetCommit]) -> DomainResult<()> {
        let _ = commits;
        Ok(())
    }

    /// 关闭会话（组协议路径 = 补提交 + `LeaveGroup`；本地游标路径 = 空操作）。
    ///
    /// # Errors
    /// 补提交失败。
    async fn close_session(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// `rskafka` 真实实现。
pub struct RskafkaSource {
    client: rskafka::client::Client,
    label: String,
    security: String,
    /// 分区探测上限（回退路径用；`topic 级 metadata` 探测的最大分区数）。
    max_partition_probe: i32,
}

/// 分区探测区间（纯函数，便于单测）：`0..max`，上限至少 1、最多 1024。
#[must_use]
pub fn partition_probe_range(max_partition_probe: i32) -> std::ops::Range<i32> {
    0..max_partition_probe.clamp(1, 1024)
}

impl std::fmt::Debug for RskafkaSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RskafkaSource")
            .field("label", &self.label)
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}
impl RskafkaSource {
    /// 连接 broker 列表（`bootstrap` 形如 `kafka-1:9092`；KoP 则是 KoP 的 Kafka 协议监听）。
    ///
    /// `security` 携带 SASL/TLS；错误文本**只**含 broker 列表与安全配置的脱敏描述。
    ///
    /// # Errors
    /// broker 列表为空、TLS 配置非法或连接握手/鉴权失败。
    pub async fn connect(brokers: Vec<String>, client_id: &str, security: &KafkaSecurity) -> DomainResult<Self> {
        Self::connect_with_probe(brokers, client_id, security, 64).await
    }

    /// 同 [`Self::connect`]，但可指定分区探测上限（`max_partition_probe`）。
    ///
    /// # Errors
    /// 同 [`Self::connect`]。
    pub async fn connect_with_probe(
        brokers: Vec<String>,
        client_id: &str,
        security: &KafkaSecurity,
        max_partition_probe: i32,
    ) -> DomainResult<Self> {
        if brokers.is_empty() {
            return Err(DomainError::Config("Kafka 需要至少一个 broker".to_string()));
        }
        let label = brokers.join(",");
        let security_label = security.describe();
        let mut builder = rskafka::client::ClientBuilder::new(brokers)
            .client_id(client_id)
            .max_message_size(16 * 1024 * 1024)
            // 客户端内部重试同样指数退避且有上限：与本接收器的外层退避叠加，
            // 保证"broker 抖一下"不会瞬间打满重试。
            .backoff_config(rskafka::BackoffConfig {
                init_backoff: Duration::from_millis(100),
                max_backoff: Duration::from_secs(10),
                base: 2.0,
                deadline: None,
            });
        if let Some(tls) = &security.tls {
            builder = builder.tls_config(tls.build_client_config()?);
        }
        if let Some(sasl) = &security.sasl {
            builder = builder.sasl_config(sasl.to_rskafka());
        }
        let client = builder.build().await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "kafka".to_string(),
            // 注意：这里**只能**用 security.describe()，绝不能拼接 sasl 明文
            cause: format!("连接 {label} 失败（{security_label}）: {e}"),
        })?;
        Ok(Self { client, label, security: security_label, max_partition_probe })
    }
}

/// `rskafka` 的错误映射（错误文本不含凭据：broker 列表 + 动作 + 原始错误）。
fn map_kafka_err(label: &str, action: &str, error: &rskafka::client::error::Error) -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "kafka".to_string(),
        cause: format!("{label} {action} 失败: {error}"),
    }
}

#[async_trait]
impl KafkaSource for RskafkaSource {
    async fn partitions(&self, topic: &str) -> DomainResult<Vec<i32>> {
        // 快路径：broker 的**全量 topic 列表**（真实 Kafka 走这条）
        if let Ok(topics) = self.client.list_topics().await {
            if let Some(found) = topics.into_iter().find(|candidate| candidate.name == topic) {
                return Ok(found.partitions.into_iter().collect());
            }
        }
        // 回退：按分区号递增探测 **topic 级 metadata**。
        //
        // 为什么需要（实测）：KoP（Kafka on Pulsar）等"协议兼容层"对"列出全部 topic"
        // （Metadata 请求不带 topic）返回空，于是快路径看不到 topic；但它们对
        // **指定 topic 的 metadata** 是正常的。逐个分区探测即可发现全部分区，
        // 这也是"多分区自动发现"在兼容层上的兜底路径。
        let mut partitions = Vec::new();
        for partition in partition_probe_range(self.max_partition_probe) {
            if self
                .client
                .partition_client(topic.to_string(), partition, rskafka::client::partition::UnknownTopicHandling::Error)
                .await
                .is_ok()
            {
                partitions.push(partition);
            } else {
                break;
            }
        }
        if partitions.is_empty() {
            return Err(DomainError::NotFound { entity: "kafka-topic", id: topic.to_string() });
        }
        debug!(topic, ?partitions, "Kafka 分区通过 topic 级 metadata 探测发现（broker 不支持全量 topic 列表）");
        Ok(partitions)
    }

    async fn resolve_offset(&self, topic: &str, partition: i32, at: KafkaStartFrom) -> DomainResult<i64> {
        let client = self
            .client
            .partition_client(topic.to_string(), partition, rskafka::client::partition::UnknownTopicHandling::Error)
            .await
            .map_err(|e| map_kafka_err(&self.label, "partition_client", &e))?;
        let offset_at = match at {
            KafkaStartFrom::Earliest => rskafka::client::partition::OffsetAt::Earliest,
            KafkaStartFrom::Latest => rskafka::client::partition::OffsetAt::Latest,
        };
        client.get_offset(offset_at).await.map_err(|e| map_kafka_err(&self.label, "get_offset", &e))
    }

    async fn fetch(
        &self,
        topic: &str,
        partition: i32,
        offset: i64,
        max_bytes: i32,
        max_wait_ms: i32,
    ) -> DomainResult<KafkaBatch> {
        let client = self
            .client
            .partition_client(topic.to_string(), partition, rskafka::client::partition::UnknownTopicHandling::Error)
            .await
            .map_err(|e| map_kafka_err(&self.label, "partition_client", &e))?;
        let (records, high_watermark) = client
            .fetch_records(offset, 1..max_bytes.max(1), max_wait_ms.max(0))
            .await
            .map_err(|e| map_kafka_err(&self.label, "fetch_records", &e))?;
        Ok(KafkaBatch {
            records: records
                .into_iter()
                .map(|item| KafkaRecord {
                    offset: item.offset,
                    key: item.record.key.clone(),
                    value: item.record.value.clone(),
                    timestamp_millis: Some(item.record.timestamp.timestamp_millis()),
                })
                .collect(),
            high_watermark,
        })
    }

    fn describe(&self) -> String {
        format!("kafka://{}（{}）", self.label, self.security)
    }
}

/// 解析 broker 列表（纯函数）。
///
/// # Errors
/// 列表为空或含空项。
pub fn parse_brokers(endpoint: &str) -> DomainResult<Vec<String>> {
    let brokers: Vec<String> =
        endpoint.split(',').map(str::trim).filter(|b| !b.is_empty()).map(ToString::to_string).collect();
    if brokers.is_empty() {
        return Err(DomainError::Config("Kafka 需要 connection.endpoint（broker 列表，逗号分隔）".to_string()));
    }
    for broker in &brokers {
        if !broker.contains(':') {
            return Err(DomainError::Config(format!("Kafka broker {broker:?} 缺少端口（形如 host:9092）")));
        }
    }
    Ok(brokers)
}

/// 按配置装配 Kafka 数据源 —— **唯一的"要不要走消费者组协议"判定点**。
///
/// * `env_prefix` 对应的 `{prefix}_GROUP_ID` **未配置/为空** ⇒ [`RskafkaSource`]
///   （本地游标路径，行为与历史版本逐字节一致）；
/// * 已配置 ⇒ [`KafkaGroupSource`]（broker 侧消费者组协议：协调器分配 + offset 提交到 broker）。
///
/// # Errors
/// broker 列表为空、组时长参数非法、TLS/SASL 配置错误或建连握手失败。
pub async fn connect_kafka_source(
    config: &KafkaPullConfig,
    client_id: &str,
    env_prefix: &str,
) -> DomainResult<Arc<dyn KafkaSource>> {
    match KafkaGroupConfig::from_env(env_prefix, client_id) {
        Some(group) => {
            info!(
                group = %group.group_id,
                assignor = group.assignor.as_str(),
                "Kafka 消费者组协议已启用：组内分区分配由协调器下发，offset 提交到 broker"
            );
            Ok(Arc::new(KafkaGroupSource::connect(config.clone(), group)?))
        }
        None => {
            info!(
                prefix = env_prefix,
                "Kafka 未配置 {env_prefix}_GROUP_ID ⇒ 走**本地游标**路径（rskafka，行为与历史版本一致）"
            );
            let security = KafkaSecurity::from_config(config);
            Ok(Arc::new(RskafkaSource::connect(config.brokers.clone(), client_id, &security).await?))
        }
    }
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

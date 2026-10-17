//! 组会话的**基础设施**：状态容器、broker 连接、版本协商调用、协调器定位与 Metadata。
//!
//! 成员生命周期（入组/心跳/退组）在 [`super::session_join`]，
//! offset 与取数在 [`super::session_offset`]，消费者协议编解码在 [`super::codec`]。

use std::collections::BTreeMap;
use std::time::Instant;

use agf_core::error::{DomainError, DomainResult};
use kafka_protocol::messages::metadata_request::MetadataRequestTopic;
use kafka_protocol::messages::{
    FindCoordinatorRequest, FindCoordinatorResponse, MetadataRequest, MetadataResponse, TopicName,
};
use kafka_protocol::protocol::StrBytes;
use tracing::{debug, info, warn};

use super::assign::validate_group_timing;
use super::wire::Wire;
use crate::kafka::{KafkaGroupConfig, KafkaSecurity};

/// `FindCoordinator` 版本偏好（v3+ 改走 `coordinators[]` 且是 flexible 版本，这里停在 v2）。
pub(super) const FIND_COORDINATOR_PREFERRED: i16 = 2;
/// `Metadata` 版本偏好（v10+ flexible）。
pub(super) const METADATA_PREFERRED: i16 = 9;
/// `COORDINATOR_NOT_AVAILABLE`：新组首次使用时 broker 正在建 `__consumer_offsets` 分区。
const COORDINATOR_NOT_AVAILABLE: i16 = 15;

/// 组会话的可观测快照（`/stats`、日志与端到端断言用）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KafkaGroupSnapshot {
    /// 消费者组 id。
    pub group_id: String,
    /// 协调器地址（`host:port`）。
    pub coordinator: Option<String>,
    /// 当前成员 id（协调器分配；未入组为 `None`）。
    pub member_id: Option<String>,
    /// 当前代际号。
    pub generation_id: i32,
    /// 分配到的分区（`[(topic, partition)]`，升序）。
    pub assignment: Vec<(String, i32)>,
    /// 本成员是否被协调器指定为组长。
    pub leader: bool,
    /// 最近一次 JoinGroup 看到的组成员数。
    pub member_count: usize,
    /// 累计 rebalance 次数（每次重新入组 +1）。
    pub rebalances: u64,
    /// 累计心跳次数。
    pub heartbeats: u64,
    /// 累计 offset 提交次数。
    pub commits: u64,
    /// 累计提交的分区次数。
    pub committed_partitions: u64,
    /// 已提交 offset 的内存镜像（rebalance 前补提交的依据，也是端到端断言的证据）。
    pub committed: BTreeMap<(String, i32), i64>,
}

/// 组会话（全部状态；由 [`super::KafkaGroupSource`] 用 `tokio::sync::Mutex` 串行化）。
#[derive(Debug)]
pub(super) struct GroupSession {
    pub(super) bootstrap: Vec<String>,
    pub(super) security: KafkaSecurity,
    pub(super) client_id: String,
    pub(super) group: KafkaGroupConfig,
    pub(super) conns: BTreeMap<String, Wire>,
    pub(super) coordinator: Option<String>,
    pub(super) member_id: Option<String>,
    pub(super) generation_id: i32,
    pub(super) leader: bool,
    pub(super) member_count: usize,
    pub(super) assignment: Vec<(String, i32)>,
    /// `(topic, partition) → leader node id`。
    pub(super) leaders: BTreeMap<(String, i32), i32>,
    /// `node id → host:port`。
    pub(super) brokers: BTreeMap<i32, String>,
    /// 各 topic 的全部分区（Metadata 刷新）。
    pub(super) topic_partitions: BTreeMap<String, Vec<i32>>,
    /// 已提交进度（内存镜像；rebalance 前补提交与快照用）。
    pub(super) committed: BTreeMap<(String, i32), i64>,
    pub(super) joined: bool,
    pub(super) last_poll: Instant,
    pub(super) last_heartbeat: Instant,
    pub(super) rebalances: u64,
    pub(super) heartbeats: u64,
    pub(super) commits: u64,
    pub(super) committed_partitions: u64,
}

impl GroupSession {
    /// 新建（未入组；时长参数在此拦截，避免"建连后才发现配置非法"）。
    pub(super) fn new(
        bootstrap: Vec<String>,
        security: KafkaSecurity,
        client_id: String,
        group: KafkaGroupConfig,
    ) -> DomainResult<Self> {
        if group.group_id.trim().is_empty() {
            return Err(DomainError::Config("Kafka 消费者组需要非空的 group.id".to_string()));
        }
        validate_group_timing(group.session_timeout_ms, group.heartbeat_interval_ms, group.max_poll_interval_ms)?;
        let now = Instant::now();
        Ok(Self {
            bootstrap,
            security,
            client_id,
            group,
            conns: BTreeMap::new(),
            coordinator: None,
            member_id: None,
            generation_id: -1,
            leader: false,
            member_count: 0,
            assignment: Vec::new(),
            leaders: BTreeMap::new(),
            brokers: BTreeMap::new(),
            topic_partitions: BTreeMap::new(),
            committed: BTreeMap::new(),
            joined: false,
            last_poll: now,
            last_heartbeat: now,
            rebalances: 0,
            heartbeats: 0,
            commits: 0,
            committed_partitions: 0,
        })
    }

    /// 快照。
    pub(super) fn snapshot(&self) -> KafkaGroupSnapshot {
        KafkaGroupSnapshot {
            group_id: self.group.group_id.clone(),
            coordinator: self.coordinator.clone(),
            member_id: self.member_id.clone(),
            generation_id: self.generation_id,
            assignment: self.assignment.clone(),
            leader: self.leader,
            member_count: self.member_count,
            rebalances: self.rebalances,
            heartbeats: self.heartbeats,
            commits: self.commits,
            committed_partitions: self.committed_partitions,
            committed: self.committed.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // 连接与调用
    // -----------------------------------------------------------------------

    /// 按地址复用连接（不存在则建连：TCP/TLS → ApiVersions → 可选 SASL）。
    pub(super) async fn ensure_conn(&mut self, addr: &str) -> DomainResult<()> {
        if self.conns.contains_key(addr) {
            return Ok(());
        }
        let wire = Wire::connect(addr, &self.client_id, &self.security).await?;
        debug!(broker = wire.label(), "Kafka 组会话：新建 broker 连接并完成 ApiVersions 协商");
        self.conns.insert(addr.to_string(), wire);
        Ok(())
    }

    pub(super) fn version_for(&self, addr: &str, api_key: i16, preferred: i16, minimum: i16) -> DomainResult<i16> {
        self.conns
            .get(addr)
            .ok_or_else(|| DomainError::Internal(format!("Kafka 连接 {addr} 尚未建立")))
            .and_then(|wire| wire.version_for(api_key, preferred, minimum))
    }

    /// 向指定地址发一条请求（**先建连再协商版本**，两者都按需发生）。
    pub(super) async fn call<Req>(
        &mut self,
        addr: &str,
        preferred: i16,
        minimum: i16,
        request: &Req,
    ) -> DomainResult<Req::Response>
    where
        Req: kafka_protocol::protocol::Request,
        Req::Response: Send,
    {
        self.ensure_conn(addr).await?;
        let version = self.version_for(addr, Req::KEY, preferred, minimum)?;
        let wire =
            self.conns.get_mut(addr).ok_or_else(|| DomainError::Internal(format!("Kafka 连接 {addr} 尚未建立")))?;
        wire.send(version, request).await
    }

    /// 任取一个 bootstrap broker 完成"元数据类"请求（ApiVersions / FindCoordinator / Metadata）。
    pub(super) async fn bootstrap_call<Req>(
        &mut self,
        preferred: i16,
        minimum: i16,
        request: &Req,
    ) -> DomainResult<Req::Response>
    where
        Req: kafka_protocol::protocol::Request,
        Req::Response: Send,
    {
        let addrs = self.bootstrap.clone();
        let mut last_error = None;
        for addr in addrs {
            match self.call(&addr, preferred, minimum, request).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    warn!(broker = %addr, error = %error, "Kafka 组会话：bootstrap 请求失败，换下一个 broker");
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| DomainError::Config("Kafka bootstrap 列表为空".to_string())))
    }

    /// 向**组协调器**发一条请求；失败即清掉协调器缓存（下一轮重新 `FindCoordinator`）。
    pub(super) async fn coordinator_call<Req>(
        &mut self,
        preferred: i16,
        minimum: i16,
        request: &Req,
    ) -> DomainResult<Req::Response>
    where
        Req: kafka_protocol::protocol::Request,
        Req::Response: Send,
    {
        let addr = self.coordinator.clone().ok_or_else(|| {
            DomainError::Internal("Kafka 组会话：尚未找到组协调器（FindCoordinator 未执行）".to_string())
        })?;
        match self.call(&addr, preferred, minimum, request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                warn!(coordinator = %addr, error = %error, "Kafka 组会话：协调器请求失败（下一轮重新 FindCoordinator）");
                self.coordinator = None;
                Err(error)
            }
        }
    }

    /// 确保已知组协调器地址（`FindCoordinator(key=group.id, key_type=0)`）。
    ///
    /// `COORDINATOR_NOT_AVAILABLE(15)` 是**首次使用新组时的正常现象**（broker 正在建
    /// `__consumer_offsets` 分区），因此这里按 Java 客户端的口径重试几次，而不是直接失败。
    pub(super) async fn ensure_coordinator(&mut self) -> DomainResult<()> {
        if self.coordinator.is_some() {
            return Ok(());
        }
        let mut last_code = 0_i16;
        for attempt in 0..4_u32 {
            let mut request = FindCoordinatorRequest::default();
            request.key = StrBytes::from_string(self.group.group_id.clone());
            request.key_type = 0; // 0 = group（1 = transaction）
            let response: FindCoordinatorResponse =
                self.bootstrap_call(FIND_COORDINATOR_PREFERRED, 0, &request).await?;
            if response.error_code == 0 {
                let addr = format!("{}:{}", response.host, response.port);
                info!(
                    group = %self.group.group_id,
                    coordinator = %addr,
                    node_id = response.node_id.0,
                    "Kafka 消费者组：组协调器已定位（FindCoordinator）"
                );
                self.coordinator = Some(addr);
                return Ok(());
            }
            last_code = response.error_code;
            if response.error_code != COORDINATOR_NOT_AVAILABLE {
                break;
            }
            debug!(
                group = %self.group.group_id,
                attempt,
                "Kafka 消费者组：协调器尚未就绪（COORDINATOR_NOT_AVAILABLE，broker 正在建 __consumer_offsets），稍后重试"
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        Err(DomainError::DependencyUnavailable {
            dependency: "kafka".to_string(),
            cause: format!("FindCoordinator(group={}) 失败，错误码 {last_code}", self.group.group_id),
        })
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    /// 刷新 Metadata（broker 地址表 + 指定 topic 的分区与 leader）。
    pub(super) async fn refresh_metadata(&mut self, topics: &[String]) -> DomainResult<()> {
        let requested: Vec<MetadataRequestTopic> = topics
            .iter()
            .map(|topic| {
                let mut entry = MetadataRequestTopic::default();
                entry.name = Some(TopicName(StrBytes::from_string(topic.clone())));
                entry
            })
            .collect();
        let mut request = MetadataRequest::default();
        request.topics = Some(requested);
        let response: MetadataResponse = self.bootstrap_call(METADATA_PREFERRED, 1, &request).await?;
        for broker in &response.brokers {
            self.brokers.insert(broker.node_id.0, format!("{}:{}", broker.host, broker.port));
        }
        for topic in &response.topics {
            let Some(name) = topic.name.as_ref().map(|name| name.0.to_string()) else {
                continue;
            };
            if topic.error_code != 0 {
                return Err(DomainError::NotFound { entity: "kafka-topic", id: name });
            }
            let mut partitions: Vec<i32> = topic.partitions.iter().map(|partition| partition.partition_index).collect();
            partitions.sort_unstable();
            for partition in &topic.partitions {
                self.leaders.insert((name.clone(), partition.partition_index), partition.leader_id.0);
            }
            self.topic_partitions.insert(name, partitions);
        }
        Ok(())
    }

    /// 确保已加载某 topic 的分区与 leader。
    pub(super) async fn ensure_metadata(&mut self, topic: &str) -> DomainResult<()> {
        if self.topic_partitions.contains_key(topic) {
            return Ok(());
        }
        self.refresh_metadata(&[topic.to_string()]).await
    }

    /// 分区 leader 地址。
    pub(super) fn leader_addr(&self, topic: &str, partition: i32) -> DomainResult<String> {
        let node = self.leaders.get(&(topic.to_string(), partition)).ok_or_else(|| DomainError::NotFound {
            entity: "kafka-partition-leader",
            id: format!("{topic}/{partition}"),
        })?;
        self.brokers
            .get(node)
            .cloned()
            .ok_or_else(|| DomainError::NotFound { entity: "kafka-broker", id: node.to_string() })
    }
}

//! offset 语义与取数：`OffsetCommit` / `OffsetFetch` / `ListOffsets` / `Fetch`。
//!
//! ## 代际栅栏（组协议强于本地游标的地方）
//!
//! `OffsetCommit` 带上 `generation_id` + `member_id`：**只有当前代际的组成员**的提交会被
//! 协调器接受，过期成员（已被 rebalance 踢出）提交同一分区会拿到 `ILLEGAL_GENERATION`。
//! 因此"两个进程同时写一个分区"在协议层就被拒绝 —— 本地游标路径没有这层保护
//! （只能靠租约 + 内容去重兜住，见 `kafka.rs` 顶部的路径对比表）。
//!
//! ## 起始位置
//!
//! `OffsetFetch` 拿到的**已提交 offset 优先**（`>= 0` 即有效；`-1` = 协调器里没有记录）；
//! 没有记录时才按 `start_from` 用 `ListOffsets`（`-2` = earliest / `-1` = latest）定位。
//! 这正是"重启进程从已提交 offset 续消费，不重复不丢"的实现点。

use std::collections::BTreeMap;

use agf_core::error::{DomainError, DomainResult};
use kafka_protocol::messages::fetch_request::{FetchPartition, FetchTopic, ReplicaState};
use kafka_protocol::messages::list_offsets_request::{ListOffsetsPartition, ListOffsetsTopic};
use kafka_protocol::messages::offset_commit_request::{OffsetCommitRequestPartition, OffsetCommitRequestTopic};
use kafka_protocol::messages::offset_fetch_request::OffsetFetchRequestTopic;
use kafka_protocol::messages::{
    BrokerId, FetchRequest, FetchResponse, GroupId, ListOffsetsRequest, ListOffsetsResponse, OffsetCommitRequest,
    OffsetCommitResponse, OffsetFetchRequest, OffsetFetchResponse, TopicName,
};
use kafka_protocol::protocol::StrBytes;
use tracing::debug;

use super::assign::choose_start_offset;
use super::codec::decode_records;
use super::session::GroupSession;
use crate::kafka::{KafkaBatch, KafkaStartFrom};

/// `OffsetFetch` 版本偏好（v6+ 改走 `groups[]` 且是 flexible 版本）。
pub(super) const OFFSET_FETCH_PREFERRED: i16 = 5;
/// `OffsetCommit` 版本偏好（v8+ flexible）。
pub(super) const OFFSET_COMMIT_PREFERRED: i16 = 7;
/// `ListOffsets` 版本偏好（v8+ flexible）。
pub(super) const LIST_OFFSETS_PREFERRED: i16 = 7;
/// `Fetch` 版本偏好（v12+ flexible；v11 已含 `rack_id` / `forgotten_topics_data`）。
pub(super) const FETCH_PREFERRED: i16 = 11;

impl GroupSession {
    /// 把内存镜像里的进度全部补提交（rebalance 前、停机前调用）。
    pub(super) async fn commit_pending(&mut self) -> DomainResult<()> {
        let entries: Vec<(String, i32, i64)> =
            self.committed.iter().map(|((topic, partition), offset)| (topic.clone(), *partition, *offset)).collect();
        if entries.is_empty() {
            return Ok(());
        }
        self.commit(&entries).await
    }

    /// 提交 offset 到 broker（**代际栅栏在这里生效**）。
    pub(super) async fn commit(&mut self, offsets: &[(String, i32, i64)]) -> DomainResult<()> {
        if offsets.is_empty() {
            return Ok(());
        }
        let mut grouped: BTreeMap<String, Vec<OffsetCommitRequestPartition>> = BTreeMap::new();
        for (topic, partition, offset) in offsets {
            let mut entry = OffsetCommitRequestPartition::default();
            entry.partition_index = *partition;
            entry.committed_offset = *offset;
            entry.committed_leader_epoch = -1;
            grouped.entry(topic.clone()).or_default().push(entry);
        }
        let topics: Vec<OffsetCommitRequestTopic> = grouped
            .into_iter()
            .map(|(topic, partitions)| {
                let mut entry = OffsetCommitRequestTopic::default();
                entry.name = TopicName(StrBytes::from_string(topic));
                entry.partitions = partitions;
                entry
            })
            .collect();
        let mut request = OffsetCommitRequest::default();
        request.group_id = GroupId(StrBytes::from_string(self.group.group_id.clone()));
        request.generation_id_or_member_epoch = self.generation_id;
        request.member_id = StrBytes::from_string(self.member_id.clone().unwrap_or_default());
        request.retention_time_ms = -1;
        request.topics = topics;
        let response: OffsetCommitResponse = self.coordinator_call(OFFSET_COMMIT_PREFERRED, 2, &request).await?;
        let mut failures = Vec::new();
        for topic in &response.topics {
            for partition in &topic.partitions {
                if partition.error_code != 0 {
                    failures.push(format!(
                        "{}/{} 错误码 {}",
                        topic.name.0, partition.partition_index, partition.error_code
                    ));
                }
            }
        }
        if !failures.is_empty() {
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!("OffsetCommit 部分分区失败: {}", failures.join(", ")),
            });
        }
        self.commits = self.commits.saturating_add(1);
        self.committed_partitions =
            self.committed_partitions.saturating_add(u64::try_from(offsets.len()).unwrap_or(u64::MAX));
        for (topic, partition, offset) in offsets {
            self.committed.insert((topic.clone(), *partition), *offset);
        }
        debug!(group = %self.group.group_id, partitions = offsets.len(), "Kafka 消费者组：OffsetCommit 成功");
        Ok(())
    }

    /// 解析某分区的起始 offset：**已提交 offset 优先**，没有才按 `start_from` 定位。
    pub(super) async fn resolve_offset(
        &mut self,
        topic: &str,
        partition: i32,
        start_from: KafkaStartFrom,
    ) -> DomainResult<i64> {
        self.ensure_coordinator().await?;
        let mut wanted = OffsetFetchRequestTopic::default();
        wanted.name = TopicName(StrBytes::from_string(topic.to_string()));
        wanted.partition_indexes = vec![partition];
        let mut request = OffsetFetchRequest::default();
        request.group_id = GroupId(StrBytes::from_string(self.group.group_id.clone()));
        request.topics = Some(vec![wanted]);
        let response: OffsetFetchResponse = self.coordinator_call(OFFSET_FETCH_PREFERRED, 1, &request).await?;
        let committed = response
            .topics
            .iter()
            .flat_map(|entry| entry.partitions.iter())
            .find(|entry| entry.partition_index == partition)
            .map(|entry| entry.committed_offset);
        // 已提交 offset 优先（见 `choose_start_offset` 的口径说明）
        let resolved = match committed.filter(|offset| *offset >= 0) {
            Some(offset) => offset,
            None => self.list_offset(topic, partition, start_from).await?,
        };
        let (offset, source) = choose_start_offset(committed, resolved);
        debug!(group = %self.group.group_id, topic, partition, offset, source, "Kafka 消费者组：分区起始 offset 已确定");
        self.committed.insert((topic.to_string(), partition), offset);
        Ok(offset)
    }

    /// `ListOffsets`（earliest = -2 / latest = -1）——仅在组内没有已提交 offset 时使用。
    async fn list_offset(&mut self, topic: &str, partition: i32, start_from: KafkaStartFrom) -> DomainResult<i64> {
        self.ensure_metadata(topic).await?;
        let addr = self.leader_addr(topic, partition)?;
        let timestamp = match start_from {
            KafkaStartFrom::Earliest => -2,
            KafkaStartFrom::Latest => -1,
        };
        let mut wanted = ListOffsetsPartition::default();
        wanted.partition_index = partition;
        wanted.current_leader_epoch = -1;
        wanted.timestamp = timestamp;
        let mut topic_entry = ListOffsetsTopic::default();
        topic_entry.name = TopicName(StrBytes::from_string(topic.to_string()));
        topic_entry.partitions = vec![wanted];
        let mut request = ListOffsetsRequest::default();
        request.replica_id = BrokerId(-1);
        request.topics = vec![topic_entry];
        request.timeout_ms = 10_000;
        let response: ListOffsetsResponse = self.call(&addr, LIST_OFFSETS_PREFERRED, 1, &request).await?;
        let found = response
            .topics
            .iter()
            .flat_map(|entry| entry.partitions.iter())
            .find(|entry| entry.partition_index == partition);
        match found {
            Some(entry) if entry.error_code == 0 => {
                debug!(
                    topic,
                    partition,
                    offset = entry.offset,
                    start_from = start_from.as_str(),
                    "Kafka 消费者组：按 start_from 定位起始 offset（组内无已提交 offset）"
                );
                Ok(entry.offset)
            }
            Some(entry) => Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!("ListOffsets({topic}/{partition}) 错误码 {}", entry.error_code),
            }),
            None => Err(DomainError::NotFound { entity: "kafka-partition", id: format!("{topic}/{partition}") }),
        }
    }

    /// 向分区 leader 拉取一批记录（`session_id = 0` = 不用增量会话，每次都是完整请求）。
    pub(super) async fn fetch(
        &mut self,
        topic: &str,
        partition: i32,
        offset: i64,
        max_bytes: i32,
        max_wait_ms: i32,
    ) -> DomainResult<KafkaBatch> {
        self.ensure_metadata(topic).await?;
        let addr = self.leader_addr(topic, partition)?;
        let mut replica_state = ReplicaState::default();
        replica_state.replica_id = BrokerId(-1);
        replica_state.replica_epoch = -1;
        let mut partition_entry = FetchPartition::default();
        partition_entry.partition = partition;
        partition_entry.current_leader_epoch = -1;
        partition_entry.fetch_offset = offset;
        partition_entry.last_fetched_epoch = -1;
        partition_entry.log_start_offset = -1;
        partition_entry.partition_max_bytes = max_bytes.max(1);
        let mut topic_entry = FetchTopic::default();
        topic_entry.topic = TopicName(StrBytes::from_string(topic.to_string()));
        topic_entry.partitions = vec![partition_entry];
        let mut request = FetchRequest::default();
        request.replica_id = BrokerId(-1);
        request.replica_state = replica_state;
        request.max_wait_ms = max_wait_ms.max(0);
        request.min_bytes = 1;
        request.max_bytes = max_bytes.max(1);
        request.session_id = 0;
        request.session_epoch = -1;
        request.topics = vec![topic_entry];
        let response: FetchResponse = self.call(&addr, FETCH_PREFERRED, 4, &request).await?;
        // 拉取即"poll"：max.poll.interval.ms 的计时基准在这里刷新
        self.last_poll = std::time::Instant::now();
        let data = response
            .responses
            .iter()
            .flat_map(|entry| entry.partitions.iter())
            .find(|entry| entry.partition_index == partition)
            .ok_or_else(|| DomainError::NotFound { entity: "kafka-partition", id: format!("{topic}/{partition}") })?;
        if data.error_code != 0 {
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!("Fetch({topic}/{partition}) 错误码 {}", data.error_code),
            });
        }
        let records = match data.records.clone() {
            Some(bytes) => decode_records(bytes)?,
            None => Vec::new(),
        };
        Ok(KafkaBatch { records, high_watermark: data.high_watermark })
    }
}

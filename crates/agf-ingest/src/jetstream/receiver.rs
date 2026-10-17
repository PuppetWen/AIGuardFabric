//! JetStream 订阅接收器：pull 批量拉取 / push 推送，共用同一接入内核。
//!
//! 投递语义：**至少一次**——落库成功才 ack；落库失败 nak 重投；毒消息（超 `max_deliver`）term。

use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{HttpPullReceiver, Receiver, ReceiverDescriptor, ReceiverStatus, effective_status};

use super::plan::{
    ConsumerPlan, DEFAULT_BATCH_SIZE, JetAckAction, JetMessage, JetMode, JetStreamState, StreamPlan, parse_nats_urls,
};
use super::source::JetStreamSource;

/// 单条消息的接入结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JetIngestReport {
    /// 拆出的记录数。
    pub records: usize,
    /// 落库事件数。
    pub persisted: usize,
    /// 落库失败（`pipeline.ingest_batch` 返回错误）：应答端必须 nak。
    pub persist_failed: bool,
}

/// JetStream 订阅接收器。
#[derive(Debug)]
pub struct JetStreamReceiver {
    pipeline: Arc<IngestPipeline>,
    source: LogSource,
    stream: StreamPlan,
    consumer: ConsumerPlan,
    source_impl: Arc<dyn JetStreamSource>,
    max_records: usize,
    counters: Arc<ReceiverCounters>,
}

impl JetStreamReceiver {
    /// 构造（显式给出 stream/consumer 计划 + 数据源实现）。
    #[must_use]
    pub fn new(
        pipeline: Arc<IngestPipeline>,
        source: LogSource,
        stream: StreamPlan,
        consumer: ConsumerPlan,
        source_impl: Arc<dyn JetStreamSource>,
    ) -> Self {
        Self {
            pipeline,
            source,
            stream,
            consumer,
            source_impl,
            max_records: 1_000,
            counters: Arc::new(ReceiverCounters::new()),
        }
    }

    /// 由日志源构造默认计划（`connection.endpoint` 地址列表、`connection.topic` 过滤 subject）。
    ///
    /// 订阅模式由 `connection.headers["jetstream.mode"]` 指定（`pull` / `push`，默认 `pull`）。
    ///
    /// # Errors
    /// 地址列表缺失/为空。
    pub fn plan_from_source(source: &LogSource) -> DomainResult<(StreamPlan, ConsumerPlan)> {
        let endpoint =
            source.connection.endpoint.clone().ok_or_else(|| {
                DomainError::Config("JetStream 需要 connection.endpoint（NATS 地址列表）".to_string())
            })?;
        parse_nats_urls(&endpoint)?;
        let mode = match source.connection.headers.get("jetstream.mode").map(String::as_str) {
            Some("push") => JetMode::Push,
            _ => JetMode::Pull,
        };
        let filter = source.connection.topic.clone().unwrap_or_default();
        let batch_size = source
            .connection
            .headers
            .get("jetstream.batch")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(DEFAULT_BATCH_SIZE);
        let subject_prefix = source
            .connection
            .headers
            .get("jetstream.subject-prefix")
            .cloned()
            .unwrap_or_else(|| "agf.ingest".to_string());
        Ok((
            StreamPlan::for_source(source, &subject_prefix),
            ConsumerPlan::for_source(source, mode, &filter, batch_size),
        ))
    }

    /// 注入共享计数器。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// stream 计划。
    #[must_use]
    pub const fn stream_plan(&self) -> &StreamPlan {
        &self.stream
    }

    /// consumer 计划。
    #[must_use]
    pub const fn consumer_plan(&self) -> &ConsumerPlan {
        &self.consumer
    }

    /// 幂等声明 stream + consumer（启动时调用一次；重复调用安全）。
    ///
    /// # Errors
    /// NATS 不可达或服务端拒绝配置。
    pub async fn provision(&self) -> DomainResult<JetStreamState> {
        let state = self.source_impl.ensure_stream(&self.stream).await?;
        self.source_impl.ensure_consumer(&self.consumer).await?;
        Ok(state)
    }
    /// 接入一条消息（拆分 → 归一化 → 落库），返回报告；**不**自行应答（由 `decide`/`ack` 完成）。
    ///
    /// # Errors
    /// 落库失败（拆分/解析失败按既有口径计数，不返回错误）。
    pub async fn ingest_message(&self, message: &JetMessage) -> DomainResult<JetIngestReport> {
        self.counters.add_received(1);
        let records = HttpPullReceiver::split_records(&message.payload, self.max_records);
        if records.is_empty() {
            debug!(subject = %message.subject, "JetStream 载荷为空，跳过");
            return Ok(JetIngestReport::default());
        }
        let origin = format!("nats-jetstream://{}/{}", self.source_impl.describe(), message.subject);
        let items: Vec<(Vec<u8>, String)> = records.into_iter().map(|r| (r, origin.clone())).collect();
        let outcomes = self.pipeline.ingest_batch(&self.source, IngestProtocol::Nats, &items).await?;
        let persisted = outcomes.iter().filter(|o| o.persisted).count();
        self.counters.record_outcomes(&outcomes);
        Ok(JetIngestReport { records: items.len(), persisted, persist_failed: false })
    }

    /// 接入 + 显式应答（ack/nak/term 由 [`JetAckAction::decide`] 决定）。
    ///
    /// # Errors
    /// 应答投递失败（接入错误不会传播：已 nak 重投）。
    pub async fn ingest_and_ack(&self, message: &JetMessage) -> DomainResult<JetAckAction> {
        let report = match self.ingest_message(message).await {
            Ok(report) => report,
            Err(e) => {
                warn!(subject = %message.subject, error = %e, "JetStream 落库失败，nak 重投");
                JetIngestReport { records: 0, persisted: 0, persist_failed: true }
            }
        };
        let action = JetAckAction::decide(&report, message.delivered, self.consumer.max_deliver);
        if action == JetAckAction::Term {
            self.counters.add_dropped(1);
        }
        self.source_impl.ack(&self.consumer.durable_name, message, action).await?;
        Ok(action)
    }

    /// pull 一轮：批量拉取 + 逐条接入应答，返回处理条数。
    ///
    /// # Errors
    /// NATS 不可达或 consumer 未声明。
    pub async fn poll_batch(&self, max: usize) -> DomainResult<usize> {
        let wait = Duration::from_millis(500);
        let messages = self.source_impl.fetch_batch(&self.consumer.durable_name, max, wait).await?;
        let count = messages.len();
        for message in &messages {
            self.ingest_and_ack(message).await?;
        }
        Ok(count)
    }

    /// push 长跑：逐条消费推送直到通道关闭（pull 模式 = 循环批量拉取）。
    ///
    /// # Errors
    /// NATS 不可达。
    pub async fn run(&self) -> DomainResult<()> {
        match self.consumer.mode {
            JetMode::Push => {
                while let Some(message) = self.source_impl.next_push(&self.consumer.durable_name).await? {
                    if let Err(e) = self.ingest_and_ack(&message).await {
                        warn!(consumer = %self.consumer.durable_name, error = %e, "JetStream 应答失败（服务端按 ack_wait 重投）");
                    }
                }
                warn!(consumer = %self.consumer.durable_name, "JetStream 推送通道关闭，接收器退出");
                Ok(())
            }
            JetMode::Pull => loop {
                let pulled = self.poll_batch(self.consumer.batch_size).await?;
                if pulled == 0 {
                    // 空轮询退避，避免热循环。
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        }
    }
}

#[async_trait]
impl Receiver for JetStreamReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Nats
    }

    fn describe(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: format!("nats-jetstream-{}", self.consumer.mode.as_str()),
            protocol: IngestProtocol::Nats,
            // 与 `nats-jetstream` 能力矩阵行同一装配事实：订阅任务没起来 ⇒ `not-wired`
            status: effective_status(ReceiverStatus::Ready, "nats-jetstream"),
            note: format!(
                "NATS JetStream {} 订阅 {}，stream `{}`，durable consumer `{}`\
                 （服务端 `ack_with(AckKind)` 显式应答：ack/nak/term，至少一次）",
                self.consumer.mode.as_str(),
                self.source_impl.describe(),
                self.stream.name,
                self.consumer.durable_name
            ),
            todo: Some(
                "TODO ingest-jetstream-kv-object：JetStream KV/ObjectStore 未接线；\
                 横向扩展经 durable 名共享（queue group）可用，未单独暴露配置"
                    .to_string(),
            ),
            mock_replay: false,
        }
    }

    async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
        self.run().await
    }

    async fn poll_once(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource, max: usize) -> DomainResult<usize> {
        match self.consumer.mode {
            JetMode::Pull => self.poll_batch(max.max(1)).await,
            JetMode::Push => Err(DomainError::NotImplemented(
                "JetStream push 为推送型接收器，无轮询语义；请调用 run/ingest_and_ack".to_string(),
            )),
        }
    }
}

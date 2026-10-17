//! [`PulsarNativeReceiver`]：把原生 Pulsar 消费者接进接入流水线（**落库成功才 ack**）。
//!
//! ## 投递语义（与 JetStream 侧同一口径）
//!
//! * **至少一次**：`pipeline.ingest_batch` 成功 ⇒ 发 `CommandAck`；失败 ⇒ **不** ack，
//!   让 broker 在 `ackTimeout` 之后重投（Pulsar 协议没有 nak，本实现也不伪造）；
//! * **毒消息**（batch 结构损坏 / 压缩未实现）⇒ 用 `CommandAck.validation_error` 显式回执
//!   （`BatchDeSerializeError` / `DecompressionError`）并计入 `dropped`，
//!   否则 broker 会永远重投同一条；这是"不静默丢"与"不被毒消息卡死"的折中；
//! * **CRC32C 失败**：帧本身已损坏 ⇒ **取不出 message_id**，无法按条 ack。
//!   处理方式：计数（`checksum_failures`）+ `warn` + 按**连接级可重试错误**断开重连，
//!   让 broker 重投（既不静默丢，也不假装收到）。官方 Java 客户端同样不会 ack 解析失败的帧。
//!
//! ## 断线恢复
//!
//! * 指数退避：`reconnect_initial * 2^attempt`，上限 `reconnect_max`；`max_attempts=0` 永不放弃；
//! * 收到 `CommandCloseConsumer`（broker 迁移 topic）⇒ **重新订阅**（计入 `resubscribes`）；
//! * ack 可攒批（`AGF_INGEST_PULSAR_ACK_EVERY`）：重连时未发出的 ack 会丢 ⇒ 那几条被重投，
//!   由流水线的**内容去重**兜住（at-least-once + 去重，与 Kafka/KoP 路径同口径）。

use std::sync::Arc;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use tokio::sync::watch;

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{Receiver, ReceiverDescriptor, ReceiverStatus};

use super::PULSAR_NATIVE_REMAINING_TODO;
use super::batch;
use super::client::{
    ClientEvent, LookupOutcome, PulsarClient, PulsarError, PulsarNativeStats, attempts_exhausted, backoff_delay,
};
use super::config::{PulsarAckMode, PulsarNativeConfig, parse_lookup_url};
use super::frame::{self, compression_name};
use super::proto::{MessageIdData, MessageMetadata, ack_type, validation_error};

/// 原生 Pulsar 消费者（`AGF_INGEST_PULSAR_URL`）。
#[derive(Debug)]
pub struct PulsarNativeReceiver {
    config: PulsarNativeConfig,
    counters: Arc<ReceiverCounters>,
    stats: Arc<PulsarNativeStats>,
    shutdown: Option<watch::Receiver<bool>>,
}

impl PulsarNativeReceiver {
    /// 新建。
    #[must_use]
    pub fn new(config: PulsarNativeConfig) -> Self {
        Self {
            config,
            counters: Arc::new(ReceiverCounters::new()),
            stats: Arc::new(PulsarNativeStats::new()),
            shutdown: None,
        }
    }

    /// 注入共享计数器（`/metrics` 的 `pulsar-native` 标签）。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 注入连接级指标。
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<PulsarNativeStats>) -> Self {
        self.stats = stats;
        self
    }

    /// 注入停机信号（SIGINT/SIGTERM 时优雅退出消费循环）。
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &PulsarNativeConfig {
        &self.config
    }

    /// 连接级指标。
    #[must_use]
    pub const fn stats(&self) -> &Arc<PulsarNativeStats> {
        &self.stats
    }

    /// 建连（一次尝试；**不**退避）。
    ///
    /// # Errors
    /// 见 [`PulsarError`]。
    pub async fn connect(&self) -> Result<PulsarClient, PulsarError> {
        if self.config.tls_insecure_skip_verify {
            tracing::warn!("Pulsar 原生 TLS：证书链校验被关闭（仅可用于排障）");
        }
        PulsarClient::connect(&self.config, Arc::clone(&self.stats)).await
    }

    /// 建连 + **LOOKUP** + 订阅 + 开 FLOW（一次会话的入口）。
    ///
    /// ## 为什么必须先 LOOKUP（**实测踩过，务必保留**）
    ///
    /// 直接对 `pulsar://host:6650` 发 `CommandSubscribe`，broker 会回
    /// `CommandError{error=ServiceNotReady(6)}`：
    /// `Namespace bundle for topic (...) not served by this instance:... Please redo the lookup.`
    /// ——`public/default` 的 bundle 要在**一次 LOOKUP**（或产者路径）之后才被本 broker 认领。
    /// 因此本方法先发 `CommandLookupTopic`，按应答决定"当前连接上订阅"还是"连到重定向的 broker"。
    ///
    /// # Errors
    /// 见 [`PulsarError`]；LOOKUP 重定向跳数上限 3（防环）。
    pub async fn open_session(&self) -> Result<PulsarClient, PulsarError> {
        let mut client = self.connect().await?;
        // ---- LOOKUP：最多 3 跳（Redirect 之后重连新 broker，authoritative 再问一次） ----
        let mut authoritative = false;
        let mut hops = 0_u8;
        loop {
            let outcome = client.lookup(&self.config.topic, authoritative).await?;
            match outcome {
                LookupOutcome::ConnectHere => break,
                LookupOutcome::Redirect { url, authoritative: was_authoritative } => {
                    hops = hops.saturating_add(1);
                    if hops > 3 {
                        return Err(PulsarError::Unsupported(format!(
                            "LOOKUP 重定向超过 3 跳（{url}）——疑似配置了错误的 serviceUrl 或 broker 环"
                        )));
                    }
                    let Some((endpoint, tls)) = parse_lookup_url(&url) else {
                        return Err(PulsarError::Unsupported(format!("LOOKUP 重定向地址无法解析：{url:?}")));
                    };
                    tracing::info!(target = %endpoint.authority(), tls, "Pulsar 原生：LOOKUP 重定向到其它 broker");
                    client =
                        PulsarClient::connect_endpoint(&self.config, Arc::clone(&self.stats), &endpoint, tls).await?;
                    // 若对端回的是"非权威"应答，下一轮把 authoritative 置 true 再问
                    authoritative = !was_authoritative;
                }
            }
        }
        let consumer_id = client.subscribe(&self.config).await?;
        tracing::info!(
            topic = %self.config.topic,
            subscription = %self.config.subscription,
            sub_type = self.config.subscription_type.as_str(),
            initial_position = self.config.initial_position.as_str(),
            consumer_id,
            broker = %client.broker_url,
            server_version = %client.server_version,
            protocol_version = client.protocol_version,
            "Pulsar 原生消费者已订阅（binary protocol，**非 KoP**）"
        );
        client.send_flow(self.config.receiver_queue_size).await?;
        Ok(client)
    }

    /// 长跑：建连 → 订阅 → 消费；失败按退避重连。
    ///
    /// # Errors
    /// 只有**不可重试**的错误（配置/鉴权/topic 不存在…）或重连次数用尽才返回 `Err`。
    pub async fn run(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        let mut attempt: u32 = 0;
        let mut shutdown = self.shutdown.clone();
        loop {
            if is_stopped(shutdown.as_ref()) {
                return Ok(());
            }
            match self.open_session().await {
                Ok(mut client) => {
                    attempt = 0;
                    match self.session(&mut client, &pipeline, &source, shutdown.as_mut()).await {
                        Ok(()) => return Ok(()),
                        Err(error) => {
                            if !error.retryable() {
                                return Err(DomainError::Config(format!(
                                    "Pulsar 原生消费失败（不可重试，通常是配置/鉴权/topic 问题）：{error}"
                                )));
                            }
                            tracing::warn!(error = %error, kind = error.kind(), "Pulsar 原生消费中断，准备退避重连");
                        }
                    }
                }
                Err(error) => {
                    if !error.retryable() {
                        return Err(DomainError::Config(format!(
                            "Pulsar 原生建连失败（不可重试，通常是配置/鉴权/topic 问题）：{error}"
                        )));
                    }
                    tracing::warn!(error = %error, kind = error.kind(), "Pulsar 原生建连失败，准备退避重连");
                }
            }
            attempt = attempt.saturating_add(1);
            if attempts_exhausted(attempt, self.config.reconnect_max_attempts) {
                return Err(DomainError::Internal(format!(
                    "Pulsar 原生重连达到上限（{} 次）：{}",
                    self.config.reconnect_max_attempts,
                    self.config.describe()
                )));
            }
            PulsarNativeStats::bump(&self.stats.reconnects, 1);
            let delay = backoff_delay(attempt, self.config.reconnect_initial, self.config.reconnect_max);
            tracing::warn!(attempt, delay_ms = delay.as_millis() as u64, "Pulsar 原生退避重连");
            if sleep_or_stop(delay, shutdown.as_mut()).await {
                return Ok(());
            }
        }
    }

    /// 一次订阅会话（订阅成功之后直到连接断开/停机）。
    async fn session(
        &self,
        client: &mut PulsarClient,
        pipeline: &Arc<IngestPipeline>,
        source: &LogSource,
        shutdown: Option<&mut watch::Receiver<bool>>,
    ) -> Result<(), PulsarError> {
        let mut remaining = self.config.receiver_queue_size;
        let mut pending: Vec<MessageIdData> = Vec::new();
        let mut shutdown = shutdown;
        loop {
            if let Some(rx) = shutdown.as_deref() {
                if *rx.borrow() {
                    return Ok(());
                }
            }
            let event = match shutdown.as_mut() {
                Some(rx) => tokio::select! {
                    biased;
                    changed = rx.changed() => { let _ = changed; return Ok(()); }
                    event = client.read_message() => event?,
                },
                None => client.read_message().await?,
            };
            match event {
                ClientEvent::Message { command, metadata, payload, .. } => {
                    let message_id = command.message_id.clone().unwrap_or_default();
                    let permits = u32::try_from(metadata.batch_len()).unwrap_or(1);
                    let plan = self.handle_message(&message_id, &metadata, &payload, pipeline, source).await;
                    self.counters.add_received(plan.received as u64);
                    if plan.dropped > 0 {
                        self.counters.add_dropped(plan.dropped);
                    }
                    if !plan.should_ack {
                        tracing::warn!(
                            message_id = %message_id.describe(),
                            "Pulsar 原生：落库失败，本条不 ack（等 broker 重投）"
                        );
                    } else if plan.validation_error.is_some() {
                        client.send_ack(plan.ack_type, &plan.message_ids, plan.validation_error).await?;
                    } else {
                        match self.config.ack_mode {
                            PulsarAckMode::Individual => pending.extend(plan.message_ids.iter().cloned()),
                            PulsarAckMode::Cumulative => {
                                pending.clear();
                                if let Some(last) = plan.message_ids.last() {
                                    pending.push(last.clone());
                                }
                            }
                        }
                        if pending.len() >= self.config.ack_every {
                            let ids = std::mem::take(&mut pending);
                            client.send_ack(plan.ack_type, &ids, None).await?;
                        }
                    }
                    remaining = remaining.saturating_sub(permits);
                    if PulsarClient::should_replenish(remaining, self.config.receiver_queue_size) {
                        let replenish = self.config.receiver_queue_size.saturating_sub(remaining);
                        client.send_flow(replenish).await?;
                        remaining = self.config.receiver_queue_size;
                    }
                }
                ClientEvent::CloseConsumer { assigned_broker } => {
                    PulsarNativeStats::bump(&self.stats.resubscribes, 1);
                    return Err(PulsarError::ConsumerClosed { assigned_broker });
                }
                ClientEvent::Error { error, message, request_id } => {
                    return Err(PulsarError::Server { error, message, request_id });
                }
                ClientEvent::ReachedEndOfTopic => {
                    tracing::info!(topic = %self.config.topic, "Pulsar 原生：topic 已终止且消费到底，退出消费循环");
                    return Ok(());
                }
                ClientEvent::ActiveConsumerChange { is_active } => {
                    tracing::info!(
                        is_active,
                        subscription = %self.config.subscription,
                        "Pulsar 原生：活跃消费者变更（Failover）"
                    );
                }
                ClientEvent::Subscribed { .. } => {}
            }
        }
    }

    /// 处理一条消息：解压 → 拆 batch → 落库 → 决定 ack。
    async fn handle_message(
        &self,
        message_id: &MessageIdData,
        metadata: &MessageMetadata,
        payload: &[u8],
        pipeline: &Arc<IngestPipeline>,
        source: &LogSource,
    ) -> AckPlan {
        let compression = metadata.compression_kind();
        if !frame::compression_supported(compression) {
            PulsarNativeStats::bump(&self.stats.unsupported_compression, 1);
            tracing::warn!(
                compression = compression_name(compression),
                "Pulsar 原生：压缩类型未实现，按 ValidationError=DecompressionError 回执（不静默丢）"
            );
            return AckPlan::poison(message_id.clone(), validation_error::DECOMPRESSION_ERROR);
        }
        let decompressed = batch::decompress(compression, metadata.uncompressed_size.unwrap_or(0), payload);
        let Ok(bytes) = decompressed else {
            PulsarNativeStats::bump(&self.stats.unsupported_compression, 1);
            tracing::warn!("Pulsar 原生：解压失败，按 ValidationError=DecompressionError 回执");
            return AckPlan::poison(message_id.clone(), validation_error::DECOMPRESSION_ERROR);
        };
        let batch_count = metadata.batch_len();
        let entries = if batch_count > 1 && self.config.batch_split {
            match batch::split_batch(&bytes) {
                Ok(entries) => {
                    PulsarNativeStats::bump(&self.stats.batch_entries, entries.len() as u64);
                    entries
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        batch = batch_count,
                        "Pulsar 原生：batch 拆条失败，按 ValidationError=BatchDeSerializeError 回执"
                    );
                    return AckPlan::poison(message_id.clone(), validation_error::BATCH_DESERIALIZE_ERROR);
                }
            }
        } else {
            if batch_count > 1 {
                PulsarNativeStats::bump(&self.stats.batch_split_disabled, 1);
                tracing::warn!(
                    batch = batch_count,
                    "Pulsar 原生：AGF_INGEST_PULSAR_BATCH=0 ⇒ 整段 batch 作为一条原始报文选进流水线（条数计为 1）"
                );
            }
            vec![batch::single_entry(&bytes, metadata.properties_map(), metadata.partition_key.clone())]
        };
        let live: Vec<_> = entries.iter().filter(|entry| !entry.compacted_out).collect();
        if live.is_empty() {
            // 全部被 compacted_out 淘汰：没有要落库的东西，但**必须 ack**，否则会无限重投
            return AckPlan {
                ack_type: ack_type::INDIVIDUAL,
                message_ids: vec![message_id.clone()],
                validation_error: None,
                should_ack: true,
                received: 0,
                dropped: 0,
            };
        }
        let base = format!("{}#{}", self.config.topic, self.config.subscription);
        let items: Vec<(Vec<u8>, String)> = live
            .iter()
            .map(|entry| {
                let origin = if live.len() > 1 { format!("{base}#batch={}", entry.index) } else { base.clone() };
                (entry.payload.clone(), origin)
            })
            .collect();
        let received = items.len();
        match pipeline.ingest_batch(source, IngestProtocol::Pulsar, &items).await {
            Ok(outcomes) => {
                self.counters.record_outcomes(&outcomes);
                let persisted = outcomes.iter().filter(|outcome| outcome.persisted).count();
                if persisted < received {
                    tracing::warn!(received, persisted, "Pulsar 原生：部分条目未落库");
                }
                AckPlan {
                    ack_type: ack_type::INDIVIDUAL,
                    message_ids: vec![message_id.clone()],
                    validation_error: None,
                    should_ack: true,
                    received,
                    dropped: 0,
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "Pulsar 原生：落库失败，本条不 ack");
                AckPlan::defer(received)
            }
        }
    }

    /// 单轮取数（`poll_once`）：建连 → 订阅 → 收至多 `max` 条 → ack → 返回条数。
    ///
    /// # Errors
    /// 建连/订阅/协议错误。
    pub async fn poll_batch(
        &self,
        pipeline: &Arc<IngestPipeline>,
        source: &LogSource,
        max: usize,
    ) -> DomainResult<usize> {
        let mut client =
            self.open_session().await.map_err(|e| DomainError::Internal(format!("Pulsar 原生订阅失败：{e}")))?;
        let mut total = 0_usize;
        while total < max {
            match client.read_message().await {
                Ok(ClientEvent::Message { command, metadata, payload, .. }) => {
                    let message_id = command.message_id.clone().unwrap_or_default();
                    let plan = self.handle_message(&message_id, &metadata, &payload, pipeline, source).await;
                    self.counters.add_received(plan.received as u64);
                    if plan.dropped > 0 {
                        self.counters.add_dropped(plan.dropped);
                    }
                    if plan.should_ack {
                        client
                            .send_ack(plan.ack_type, &plan.message_ids, plan.validation_error)
                            .await
                            .map_err(|e| DomainError::Internal(format!("Pulsar ack 失败：{e}")))?;
                    }
                    total = total.saturating_add(plan.received.max(1));
                }
                Ok(ClientEvent::ReachedEndOfTopic) => break,
                Ok(ClientEvent::CloseConsumer { .. }) => {
                    tracing::warn!("Pulsar 原生：poll_once 期间被服务端关消费者");
                    break;
                }
                Ok(ClientEvent::Error { error, message, request_id }) => {
                    let error = PulsarError::Server { error, message, request_id };
                    return Err(DomainError::Internal(format!("Pulsar 原生：{error}")));
                }
                Ok(_) => {}
                Err(error) => return Err(DomainError::Internal(format!("Pulsar 原生读失败：{error}"))),
            }
        }
        Ok(total)
    }

    /// `/readyz` 与能力矩阵共用的一行状态说明。
    #[must_use]
    pub fn describe_native(&self) -> ReceiverDescriptor {
        let details = self.config.describe();
        ReceiverDescriptor {
            name: "pulsar-native".to_string(),
            protocol: IngestProtocol::Pulsar,
            status: ReceiverStatus::Ready,
            note: format!(
                "**Pulsar 原生二进制协议**（`pulsar://`，非 KoP）：{details}；\
                 握手 CONNECT/CONNECTED + SUBSCRIBE/SUCCESS + FLOW + MESSAGE + `CommandAck`（真发）+ \
                 batch 拆条 + **CRC32C 校验** + `CommandError` 分类 + 指数退避重连 + `CommandCloseConsumer` 重订阅；\
                 {PULSAR_NATIVE_REMAINING_TODO}"
            ),
            todo: Some(PULSAR_NATIVE_REMAINING_TODO.to_string()),
            mock_replay: false,
        }
    }
}

#[async_trait]
impl Receiver for PulsarNativeReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Pulsar
    }

    fn describe(&self) -> ReceiverDescriptor {
        self.describe_native()
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        self.run(pipeline, source).await
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        self.poll_batch(&pipeline, &source, max).await
    }
}

mod support;

pub use support::{AckPlan, ack_for_batch_error, cumulative_ack, individual_ack, stats_snapshot};

use support::{is_stopped, sleep_or_stop};

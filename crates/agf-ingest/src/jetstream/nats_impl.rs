//! `async-nats` 真实实现（默认特性 `nats`；`--no-default-features` 整体关闭）。
//!
//! ## 应答语义（**真应答**，不是快照）
//!
//! `JetStreamSource` 的协议无关入参是 [`JetMessage`]（可序列化快照，便于离线注入），
//! 但**真应答必须落在服务端**，而 `async-nats` 的应答 API（`ack_with(AckKind)`）挂在
//! 原始 [`async_nats::jetstream::Message`] 上。因此本实现：
//!
//! * `fetch_batch` / `next_push` 取出消息时，把**原始消息句柄**登记到
//!   `handles: (durable, stream_sequence) → Message`；
//! * [`JetStreamSource::ack`] 按 `(consumer, message.stream_sequence)` 取回句柄，
//!   调 `ack_with(AckKind::{Ack,Nak,Term})`，然后**摘除**句柄；
//! * 句柄缺失（消息不是本进程取的、或已应答过）⇒ **返回错误**，不静默成功——
//!   "假装应答成功"正是修复前的缺陷（`ack()` 只 `debug!` + `Ok(())`，从不 `ack_with`），
//!   真机上表现为"只会按 `ack_wait` 无限重投"，至少一次语义不成立。
//!
//! 命名约定（stream ← durable）见 [`super::plan::stream_name_for_durable`]。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use async_trait::async_trait;
use tracing::{debug, warn};

use super::plan::{
    ConsumerPlan, JetAckAction, JetConsumerStats, JetMessage, JetMode, JetStreamState, StreamPlan,
    stream_name_for_durable,
};
use super::source::JetStreamSource;

/// `async-nats` 真实实现。
pub struct AsyncNatsJetStream {
    context: async_nats::jetstream::Context,
    label: String,
    /// 已取回但尚未应答的原始消息句柄（`(durable, stream_sequence)` → `Message`）。
    ///
    /// 只在 [`JetStreamSource::ack`] 里被摘除：正常路径下每个取回的消息都会被
    /// ack / nak / term 一次，因此不会无限增长；`nak` 后服务端重投会覆盖同名键。
    handles: Mutex<HashMap<(String, u64), async_nats::jetstream::Message>>,
}

impl std::fmt::Debug for AsyncNatsJetStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pending = self.handles.lock().map(|h| h.len()).unwrap_or(0);
        f.debug_struct("AsyncNatsJetStream")
            .field("label", &self.label)
            .field("unacked_handles", &pending)
            .finish_non_exhaustive()
    }
}

impl AsyncNatsJetStream {
    /// 连接 NATS 并进入 JetStream 上下文。
    ///
    /// # Errors
    /// 连接失败。
    pub async fn connect(urls: Vec<String>) -> DomainResult<Self> {
        let urls = if urls.is_empty() { vec!["nats://127.0.0.1:4222".to_string()] } else { urls };
        let label = urls.iter().map(|url| crate::bus::nats_endpoint_label(url)).collect::<Vec<_>>().join(",");
        let client = crate::bus::connect_nats(&urls, Duration::from_secs(5)).await?;
        Ok(Self { context: async_nats::jetstream::new(client), label, handles: Mutex::new(HashMap::new()) })
    }

    /// 登记一条取回的原始消息（供后续 `ack_with` 使用）。
    fn remember(&self, consumer: &str, msg: &async_nats::jetstream::Message) {
        let key = (consumer.to_string(), msg.info().map(|i| i.stream_sequence).unwrap_or(0));
        if let Ok(mut handles) = self.handles.lock() {
            handles.insert(key, msg.clone());
        }
    }

    /// 取回并**摘除**句柄（摘除是必须的：同一条消息不能应答两次）。
    fn take_handle(&self, consumer: &str, sequence: u64) -> Option<async_nats::jetstream::Message> {
        self.handles.lock().ok().and_then(|mut handles| handles.remove(&(consumer.to_string(), sequence)))
    }

    /// 当前未应答句柄数（`/readyz` 与排障用：长期不归零 = 有消息没被应答）。
    #[must_use]
    pub fn unacked_handles(&self) -> usize {
        self.handles.lock().map(|h| h.len()).unwrap_or(0)
    }

    /// 删除 stream（**仅测试与排障**：生产不要用——删掉就丢了未消费的消息）。
    ///
    /// # Errors
    /// NATS 不可达或 stream 不存在。
    pub async fn delete_stream(&self, name: &str) -> DomainResult<()> {
        self.context.delete_stream(name).await.map_err(|e| map_nats_err(&self.label, "delete_stream", &e))?;
        Ok(())
    }

    /// JetStream `Context` 只读访问（**测试/模拟器发布用**：真机用例要往被测 subject 投递消息）。
    ///
    /// 生产接收路径**不**用它发布——接收器只做订阅，发布走调用方自己的客户端。
    #[must_use]
    pub const fn context(&self) -> &async_nats::jetstream::Context {
        &self.context
    }

    /// 读取 durable consumer 的**服务端**投递统计（真机验证"至少一次"的判据）。
    ///
    /// 这是"`ack()` 到底有没有把应答发给服务端"的唯一可观测出口：
    /// `ack()` 为空实现时，`num_ack_pending` 永不归零、`num_redelivered` 随 `ack_wait` 单调增长。
    ///
    /// # Errors
    /// NATS 不可达、stream/consumer 不存在。
    pub async fn consumer_stats(&self, durable: &str) -> DomainResult<JetConsumerStats> {
        let stream = self
            .context
            .get_stream(stream_name_for_durable(durable))
            .await
            .map_err(|e| map_nats_err(&self.label, "get_stream", &e))?;
        // `async-nats 0.46` 的 `Consumer::info()` 需要 `&mut self`（内部会刷新自身状态），
        // 因此这里必须声明为 `mut`；删掉会报 E0596。
        let mut consumer: async_nats::jetstream::consumer::Consumer<async_nats::jetstream::consumer::pull::Config> =
            stream.get_consumer(durable).await.map_err(|e| map_nats_err(&self.label, "get_consumer", &e))?;
        let info = consumer.info().await.map_err(|e| map_nats_err(&self.label, "consumer.info", &e))?;
        Ok(JetConsumerStats {
            num_pending: info.num_pending,
            // `async-nats 0.46` 把 `num_ack_pending`/`num_redelivered` 暴露为 `usize`，
            // 而本结构体统一用 `u64`（跨平台稳定）。这里显式转换，别改成 usize —— 否则
            // 32 位目标上字段宽度会变，且与 `num_pending` 的类型不一致。
            num_ack_pending: info.num_ack_pending as u64,
            num_redelivered: info.num_redelivered as u64,
            delivered_stream_seq: info.delivered.stream_sequence,
            ack_floor_stream_seq: info.ack_floor.stream_sequence,
            num_waiting: info.num_waiting,
        })
    }
}

/// 把 `async-nats` 错误映射为域错误（脱敏：不含凭据）。
fn map_nats_err(label: &str, op: &str, error: &dyn std::fmt::Display) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "nats".to_string(), cause: format!("{op} @ {label}: {error}") }
}

/// 域内应答动作 → `async-nats` 的 `AckKind`（**协议级映射，唯一一处**）。
#[must_use]
pub fn ack_kind(action: JetAckAction) -> async_nats::jetstream::AckKind {
    match action {
        JetAckAction::Ack => async_nats::jetstream::AckKind::Ack,
        // 不指定 `Duration` ⇒ 服务端按 consumer 的 `ack_wait` 重投（不额外延后）
        JetAckAction::Nak => async_nats::jetstream::AckKind::Nak(None),
        JetAckAction::Term => async_nats::jetstream::AckKind::Term,
    }
}

fn stream_config(plan: &StreamPlan) -> async_nats::jetstream::stream::Config {
    use async_nats::jetstream::stream::{Config, DiscardPolicy, RetentionPolicy, StorageType};
    let retention = match plan.retention.as_str() {
        "interest" => RetentionPolicy::Interest,
        "workqueue" => RetentionPolicy::WorkQueue,
        _ => RetentionPolicy::Limits,
    };
    let storage = if plan.storage == "memory" { StorageType::Memory } else { StorageType::File };
    Config {
        name: plan.name.clone(),
        subjects: plan.subjects.clone(),
        retention,
        storage,
        max_messages: plan.max_messages,
        discard: DiscardPolicy::Old,
        duplicate_window: Duration::from_nanos(plan.duplicate_window_nanos),
        ..Default::default()
    }
}

fn consumer_config(plan: &ConsumerPlan) -> async_nats::jetstream::consumer::Config {
    use async_nats::jetstream::consumer::{AckPolicy, Config, DeliverPolicy, ReplayPolicy};
    Config {
        durable_name: Some(plan.durable_name.clone()),
        name: Some(plan.durable_name.clone()),
        deliver_policy: DeliverPolicy::All,
        ack_policy: AckPolicy::Explicit,
        ack_wait: Duration::from_secs(plan.ack_wait_secs.max(1)),
        max_deliver: plan.max_deliver,
        filter_subject: plan.filter_subject.clone(),
        replay_policy: ReplayPolicy::Instant,
        deliver_subject: if plan.deliver_subject.is_empty() { None } else { Some(plan.deliver_subject.clone()) },
        ..Default::default()
    }
}

fn message_snapshot(msg: &async_nats::jetstream::Message) -> JetMessage {
    let (delivered, stream_sequence) = match msg.info() {
        Ok(info) => (info.delivered, info.stream_sequence),
        Err(_) => (1, 0),
    };
    JetMessage { subject: msg.subject.to_string(), payload: msg.payload.to_vec(), delivered, stream_sequence }
}

#[async_trait]
impl JetStreamSource for AsyncNatsJetStream {
    async fn ensure_stream(&self, plan: &StreamPlan) -> DomainResult<JetStreamState> {
        let stream = self
            .context
            .get_or_create_stream(stream_config(plan))
            .await
            .map_err(|e| map_nats_err(&self.label, "get_or_create_stream", &e))?;
        let info = stream.cached_info();
        Ok(JetStreamState {
            messages: info.state.messages,
            bytes: info.state.bytes,
            last_sequence: info.state.last_sequence,
            consumer_count: info.state.consumer_count,
        })
    }

    async fn ensure_consumer(&self, plan: &ConsumerPlan) -> DomainResult<()> {
        // 幂等：`get_or_create_consumer` 对待已存在的同名 durable 与新建走同一路径，
        // 因此第二次 `provision()` 只返回既有 consumer（实测：`/jsz` 的 consumers 不增）。
        let stream = self
            .context
            .get_stream(stream_name_for_durable(&plan.durable_name))
            .await
            .map_err(|e| map_nats_err(&self.label, "get_stream", &e))?;
        match plan.mode {
            // `async-nats` 0.46 的 `consumer::Config` 自身实现 `IntoConsumerConfig`/`FromConsumer`：
            // pull/push 由 `deliver_subject` 是否存在决定，无需（也不再提供）向 `pull::Config`/`push::Config` 的转换。
            JetMode::Pull => {
                stream
                    .get_or_create_consumer(&plan.durable_name, consumer_config(plan))
                    .await
                    .map_err(|e| map_nats_err(&self.label, "get_or_create_consumer(pull)", &e))?;
            }
            JetMode::Push => {
                stream
                    .get_or_create_consumer(&plan.durable_name, consumer_config(plan))
                    .await
                    .map_err(|e| map_nats_err(&self.label, "get_or_create_consumer(push)", &e))?;
            }
        }
        Ok(())
    }

    async fn fetch_batch(&self, consumer: &str, max: usize, wait: Duration) -> DomainResult<Vec<JetMessage>> {
        use futures::StreamExt;
        let stream = self
            .context
            .get_stream(stream_name_for_durable(consumer))
            .await
            .map_err(|e| map_nats_err(&self.label, "get_stream", &e))?;
        let consumer_handle: async_nats::jetstream::consumer::Consumer<async_nats::jetstream::consumer::pull::Config> =
            stream.get_consumer(consumer).await.map_err(|e| map_nats_err(&self.label, "get_consumer", &e))?;
        let mut batch = consumer_handle
            .batch()
            .max_messages(max.max(1))
            .expires(wait)
            .messages()
            .await
            .map_err(|e| map_nats_err(&self.label, "batch", &e))?;
        let mut out = Vec::new();
        while let Some(item) = batch.next().await {
            match item {
                Ok(msg) => {
                    // **先登记句柄再返回快照**：否则后续 `ack` 无从应答（这正是修复前的缺陷）
                    self.remember(consumer, &msg);
                    out.push(message_snapshot(&msg));
                }
                Err(e) => return Err(map_nats_err(&self.label, "batch.next", &e)),
            }
        }
        Ok(out)
    }

    async fn next_push(&self, consumer: &str) -> DomainResult<Option<JetMessage>> {
        use futures::StreamExt;
        let stream = self
            .context
            .get_stream(stream_name_for_durable(consumer))
            .await
            .map_err(|e| map_nats_err(&self.label, "get_stream", &e))?;
        let consumer_handle: async_nats::jetstream::consumer::Consumer<async_nats::jetstream::consumer::push::Config> =
            stream.get_consumer(consumer).await.map_err(|e| map_nats_err(&self.label, "get_consumer", &e))?;
        let mut messages =
            consumer_handle.messages().await.map_err(|e| map_nats_err(&self.label, "push.messages", &e))?;
        match messages.next().await {
            Some(Ok(msg)) => {
                self.remember(consumer, &msg);
                Ok(Some(message_snapshot(&msg)))
            }
            Some(Err(e)) => Err(map_nats_err(&self.label, "push.next", &e)),
            None => Ok(None),
        }
    }

    async fn ack(&self, consumer: &str, message: &JetMessage, action: JetAckAction) -> DomainResult<()> {
        let Some(handle) = self.take_handle(consumer, message.stream_sequence) else {
            // 不静默成功：句柄缺失意味着"这条消息的应答根本没有发给服务端"
            return Err(DomainError::Internal(format!(
                "JetStream 应答失败：未持有 consumer={consumer} seq={} 的原始消息句柄（服务端不会收到 {}），\
                 该消息将按 ack_wait 重投",
                message.stream_sequence,
                action.as_str()
            )));
        };
        let kind = ack_kind(action);
        match handle.ack_with(kind).await {
            Ok(()) => {
                debug!(
                    consumer,
                    subject = %message.subject,
                    seq = message.stream_sequence,
                    action = action.as_str(),
                    "JetStream 已向服务端发送应答"
                );
                Ok(())
            }
            Err(e) => {
                warn!(consumer, seq = message.stream_sequence, action = action.as_str(), error = %e, "JetStream 应答投递失败");
                Err(map_nats_err(&self.label, &format!("ack_with({})", action.as_str()), &e))
            }
        }
    }

    fn describe(&self) -> String {
        format!("nats://{}（jetstream）", self.label)
    }
}

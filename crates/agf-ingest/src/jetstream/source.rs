//! JetStream 数据源抽象（可注入）：真实实现走 `async-nats`（见 `nats_impl`，默认特性 `nats`），
//! 测试注入 [`FakeJetStream`] 内存实现（**测试不依赖 docker**）。
//!
//! 对应 Kafka 的 [`crate::kafka::KafkaSource`] 与 MQTT 的 [`crate::mqtt::MqttSubscription`]。

use std::sync::Mutex;
use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use async_trait::async_trait;

use super::plan::{ConsumerPlan, JetAckAction, JetMessage, JetStreamState, StreamPlan};

/// JetStream 数据源抽象。
#[async_trait]
pub trait JetStreamSource: Send + Sync + std::fmt::Debug {
    /// 幂等声明 durable stream（重复调用返回既有 stream 的状态）。
    ///
    /// # Errors
    /// NATS 不可达或配置被服务端拒绝。
    async fn ensure_stream(&self, plan: &StreamPlan) -> DomainResult<JetStreamState>;

    /// 幂等声明 durable consumer（重复调用返回既有 consumer）。
    ///
    /// # Errors
    /// NATS 不可达、stream 不存在或配置被服务端拒绝。
    async fn ensure_consumer(&self, plan: &ConsumerPlan) -> DomainResult<()>;

    /// pull 模式：批量拉取一批消息（最多 `max`，`wait` 内聚合）。
    ///
    /// # Errors
    /// NATS 不可达或 consumer 未声明。
    async fn fetch_batch(&self, consumer: &str, max: usize, wait: Duration) -> DomainResult<Vec<JetMessage>>;

    /// push 模式：取下一条推送消息（`None` = 推送通道关闭）。
    ///
    /// # Errors
    /// NATS 不可达或 consumer 未声明。
    async fn next_push(&self, consumer: &str) -> DomainResult<Option<JetMessage>>;

    /// 显式应答（ack/nak/term）。
    ///
    /// # Errors
    /// NATS 不可达或应答投递失败。
    async fn ack(&self, consumer: &str, message: &JetMessage, action: JetAckAction) -> DomainResult<()>;

    /// 描述（`/readyz` 与日志用）。
    fn describe(&self) -> String;
}

/// 内存 JetStream 实现：复刻 durable 幂等 + ack/nak/term 语义（nak 重投队首、term 丢弃）。
#[derive(Debug)]
pub struct FakeJetStream {
    state: Mutex<FakeState>,
}

#[derive(Debug, Default)]
struct FakeState {
    stream: Option<StreamPlan>,
    consumers: Vec<ConsumerPlan>,
    /// 待投递队列。
    pending: std::collections::VecDeque<JetMessage>,
    /// 应答审计日志（(durable, seq, action)）。
    acked: Vec<(String, u64, JetAckAction)>,
    /// 下一次分配的流内序号。
    next_seq: u64,
}

impl Default for FakeJetStream {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeJetStream {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self { state: Mutex::new(FakeState { next_seq: 1, ..FakeState::default() }) }
    }

    /// 测试注入消息（delivered=1），返回流内序号。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn push(&self, subject: &str, payload: Vec<u8>) -> DomainResult<u64> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        let seq = state.next_seq;
        state.next_seq += 1;
        state.pending.push_back(JetMessage {
            subject: subject.to_string(),
            payload,
            delivered: 1,
            stream_sequence: seq,
        });
        Ok(seq)
    }

    /// 已声明的 consumer 数（幂等性断言用）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn consumer_count(&self) -> DomainResult<usize> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        Ok(state.consumers.len())
    }

    /// 应答审计（(durable, seq, action)）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn acked(&self) -> DomainResult<Vec<(String, u64, JetAckAction)>> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        Ok(state.acked.clone())
    }

    /// 待投递条数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn pending(&self) -> DomainResult<usize> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        Ok(state.pending.len())
    }
}

#[async_trait]
impl JetStreamSource for FakeJetStream {
    async fn ensure_stream(&self, plan: &StreamPlan) -> DomainResult<JetStreamState> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        state.stream = Some(plan.clone());
        Ok(JetStreamState {
            messages: state.pending.len() as u64,
            bytes: state.pending.iter().map(|m| m.payload.len() as u64).sum(),
            last_sequence: state.next_seq.saturating_sub(1),
            consumer_count: state.consumers.len(),
        })
    }

    async fn ensure_consumer(&self, plan: &ConsumerPlan) -> DomainResult<()> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        if !state.consumers.iter().any(|c| c.durable_name == plan.durable_name) {
            state.consumers.push(plan.clone());
        }
        Ok(())
    }

    async fn fetch_batch(&self, _consumer: &str, max: usize, _wait: Duration) -> DomainResult<Vec<JetMessage>> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        let take = max.min(state.pending.len());
        Ok(state.pending.drain(..take).collect())
    }

    async fn next_push(&self, _consumer: &str) -> DomainResult<Option<JetMessage>> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        Ok(state.pending.pop_front())
    }

    async fn ack(&self, consumer: &str, message: &JetMessage, action: JetAckAction) -> DomainResult<()> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("fake 锁中毒: {e}")))?;
        state.acked.push((consumer.to_string(), message.stream_sequence, action));
        if action == JetAckAction::Nak {
            let mut redelivered = message.clone();
            redelivered.delivered += 1;
            state.pending.push_front(redelivered);
        }
        Ok(())
    }

    fn describe(&self) -> String {
        "memory://nats-jetstream".to_string()
    }
}

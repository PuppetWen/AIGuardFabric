//! 事件总线：把归一化事件投递给下游消费者（关联分析、告警、AI 研判）。
//!
//! | 实现 | 状态 | 说明 |
//! |---|---|---|
//! | [`InMemoryEventBus`] | 已实现 | 进程内有界队列，用于单机部署与测试（可 `drain` 取出） |
//! | [`NoopEventBus`] | 已实现 | 显式丢弃（关闭下游投递；事件仍已落库） |
//! | [`NatsEventBus`] | 已实现（默认特性 `nats`） | 真实发布到 NATS；未连接服务器时发布失败并返回 `DependencyUnavailable` |
//!
//! SQL 生产流水线将原文、事件和投递队列原子提交，由 [`EventOutbox`] 向
//! `JetStreamEventBus` 投递并等待持久存储确认。失败保留队列，消费者仍需按事件 ID 幂等。
//! `NatsEventBus` 是保留的核心协议实现，不提供持久确认；内存/Noop 仅供显式演示与测试。

mod outbox;
pub use outbox::{DeliveryReport, EventOutbox};
#[cfg(feature = "nats")]
mod jetstream;
#[cfg(feature = "nats")]
pub use jetstream::JetStreamEventBus;
#[cfg(feature = "nats")]
mod connection;
#[cfg(feature = "nats")]
pub use connection::{connect_nats, nats_endpoint_label};

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use agf_core::error::{DomainError, DomainResult};
use agf_core::event::Event;
use async_trait::async_trait;
#[cfg(feature = "nats")]
use tracing::{debug, warn};

/// 事件总线接口。
#[async_trait]
pub trait EventBus: Send + Sync + std::fmt::Debug {
    /// 总线名称（`memory` / `nats` / `noop`）。
    fn name(&self) -> &'static str;

    /// 发布单条事件。
    ///
    /// # Errors
    /// 下游不可达或序列化失败。
    async fn publish(&self, event: &Event) -> DomainResult<()>;

    /// 批量发布（返回成功条数）。
    ///
    /// # Errors
    /// 下游不可达或序列化失败。
    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize>;

    /// 健康探测。
    ///
    /// # Errors
    /// 下游不可达。
    async fn health(&self) -> DomainResult<()>;

    /// 当前积压（内存实现有意义；其他实现返回 0）。
    fn pending(&self) -> usize {
        0
    }
}

/// 进程内事件总线（有界；溢出丢弃最旧并计数）。
#[derive(Debug)]
pub struct InMemoryEventBus {
    queue: Mutex<VecDeque<Event>>,
    capacity: usize,
    dropped: AtomicU64,
    published: AtomicU64,
}

impl InMemoryEventBus {
    /// 新建（`capacity` 为队列上限，至少 1）。
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            published: AtomicU64::new(0),
        }
    }

    /// 取出现有事件（消费语义，供单机消费者/测试使用）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn drain(&self, limit: usize) -> DomainResult<Vec<Event>> {
        let mut queue = self.queue.lock().map_err(|e| DomainError::Internal(format!("总线锁中毒: {e}")))?;
        let take = limit.min(queue.len());
        Ok(queue.drain(..take).collect())
    }

    /// 已发布条数。
    #[must_use]
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    /// 因容量溢出被丢弃的条数。
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl EventBus for InMemoryEventBus {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn publish(&self, event: &Event) -> DomainResult<()> {
        let mut queue = self.queue.lock().map_err(|e| DomainError::Internal(format!("总线锁中毒: {e}")))?;
        while queue.len() >= self.capacity {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(event.clone());
        self.published.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        let mut ok = 0;
        for event in events {
            if self.publish(event).await.is_ok() {
                ok += 1;
            }
        }
        Ok(ok)
    }

    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }

    fn pending(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }
}

/// 显式丢弃的总线（`emit_to_bus=false` 时使用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventBus;

#[async_trait]
impl EventBus for NoopEventBus {
    fn name(&self) -> &'static str {
        "noop"
    }

    async fn publish(&self, _event: &Event) -> DomainResult<()> {
        Ok(())
    }

    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        Ok(events.len())
    }

    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// NATS 主题命名（`agf.events.<tenant>.<severity>`，便于按租户/等级分流）。
#[must_use]
pub fn subject_for(tenant: &str, severity: &str) -> String {
    let tenant = if tenant.is_empty() { "unknown" } else { tenant };
    format!("agf.events.{}.{}", tenant.replace('.', "-"), severity)
}

/// NATS 事件总线（默认特性 `nats`）。
///
/// **降级说明**：`publish` 在无 NATS 服务器时返回 [`DomainError::DependencyUnavailable`]；
/// 接入流水线只记警告并计数（事件已落库），**不会丢数据**。
#[cfg(feature = "nats")]
#[derive(Debug)]
pub struct NatsEventBus {
    client: async_nats::Client,
    subject: String,
}

#[cfg(feature = "nats")]
impl NatsEventBus {
    /// 连接 NATS 并绑定主题。
    ///
    /// # Errors
    /// 连接失败（服务器不可达/URL 非法）。
    pub async fn connect(url: &str, subject: &str) -> DomainResult<Self> {
        let client = connect_nats(&[url.to_string()], std::time::Duration::from_secs(5)).await?;
        debug!(endpoint = %nats_endpoint_label(url), subject, "NATS 事件总线已连接");
        Ok(Self { client, subject: subject.to_string() })
    }

    /// 由已有客户端构造（便于复用连接）。
    #[must_use]
    pub fn from_client(client: async_nats::Client, subject: &str) -> Self {
        Self { client, subject: subject.to_string() }
    }

    /// 当前主题。
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

#[cfg(feature = "nats")]
#[async_trait]
impl EventBus for NatsEventBus {
    fn name(&self) -> &'static str {
        "nats"
    }

    async fn publish(&self, event: &Event) -> DomainResult<()> {
        let payload = serde_json::to_vec(event).map_err(|e| DomainError::Internal(format!("事件序列化失败: {e}")))?;
        let subject = subject_for(&event.tenant_id.to_string(), event.severity.as_str());
        self.client.publish(subject, payload.into()).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "nats".to_string(),
            cause: format!("发布失败: {e}"),
        })?;
        self.client.flush().await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "nats".to_string(),
            cause: format!("flush 失败: {e}"),
        })
    }

    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        let mut ok = 0;
        for event in events {
            match self.publish(event).await {
                Ok(()) => ok += 1,
                Err(e) => warn!(error = %e, "NATS 批量发布中单条失败，已跳过"),
            }
        }
        Ok(ok)
    }

    async fn health(&self) -> DomainResult<()> {
        match self.client.connection_state() {
            async_nats::connection::State::Connected => Ok(()),
            other => Err(DomainError::DependencyUnavailable {
                dependency: "nats".to_string(),
                cause: format!("连接状态异常: {other:?}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::enums::{IngestProtocol, Severity};
    use agf_core::ids::{Id, TenantId};

    fn event(severity: Severity) -> Event {
        let mut e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Syslog);
        e.severity = severity;
        e.message = "测试事件".to_string();
        e
    }

    #[tokio::test]
    async fn in_memory_bus_publishes_and_drains_in_order() {
        let bus = InMemoryEventBus::new(4);
        assert_eq!(bus.name(), "memory");
        assert!(bus.health().await.is_ok());
        for severity in [Severity::Info, Severity::High, Severity::Critical] {
            assert!(bus.publish(&event(severity)).await.is_ok());
        }
        assert_eq!(bus.published(), 3);
        assert_eq!(bus.pending(), 3);
        let drained = bus.drain(10);
        assert_eq!(drained.as_ref().ok().map(Vec::len), Some(3));
        assert_eq!(drained.ok().and_then(|v| v.first().map(|e| e.severity)), Some(Severity::Info));
        assert_eq!(bus.pending(), 0);
        assert_eq!(bus.drain(1).ok().map(|v| v.len()), Some(0));
    }

    #[tokio::test]
    async fn in_memory_bus_drops_oldest_on_overflow() {
        let bus = InMemoryEventBus::new(2);
        for severity in [Severity::Info, Severity::Low, Severity::High] {
            assert!(bus.publish(&event(severity)).await.is_ok());
        }
        assert_eq!(bus.published(), 3);
        assert_eq!(bus.dropped(), 1);
        let drained = bus.drain(10).unwrap_or_default();
        assert_eq!(drained.first().map(|e| e.severity), Some(Severity::Low));
    }

    #[tokio::test]
    async fn batch_publish_reports_count() {
        let bus = InMemoryEventBus::new(8);
        let events = vec![event(Severity::Info), event(Severity::Medium)];
        assert_eq!(bus.publish_batch(&events).await.ok(), Some(2));
        assert_eq!(bus.pending(), 2);
    }

    #[tokio::test]
    async fn noop_bus_swallows_everything() {
        let bus = NoopEventBus;
        assert_eq!(bus.name(), "noop");
        assert!(bus.publish(&event(Severity::Critical)).await.is_ok());
        assert_eq!(bus.publish_batch(&[event(Severity::Info)]).await.ok(), Some(1));
        assert_eq!(bus.pending(), 0);
        assert!(bus.health().await.is_ok());
    }

    #[test]
    fn subject_naming_is_stable_and_safe() {
        assert_eq!(
            subject_for("00000000-0000-0000-0000-000000000001", "high"),
            "agf.events.00000000-0000-0000-0000-000000000001.high"
        );
        assert_eq!(subject_for("", "info"), "agf.events.unknown.info");
        assert_eq!(subject_for("a.b", "low"), "agf.events.a-b.low");
    }

    #[cfg(feature = "nats")]
    #[test]
    fn nats_bus_describes_subject() {
        // 仅验证主题计算与类型可用性（无 NATS 服务器时不发起连接）
        let rendered = subject_for(&TenantId::default_tenant().to_string(), Severity::High.as_str());
        assert!(rendered.starts_with("agf.events."));
        assert!(rendered.ends_with(".high"));
    }
}

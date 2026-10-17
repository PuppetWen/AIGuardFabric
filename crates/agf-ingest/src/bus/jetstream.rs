//! Persistent JetStream publications with event IDs for broker-side duplicate suppression.
use super::{Event, EventBus};
use agf_core::error::{DomainError, DomainResult};
use async_nats::jetstream::{
    Context,
    stream::{Config, DiscardPolicy, RetentionPolicy, StorageType},
};
use std::time::Duration;

/// A file-backed JetStream publisher. Existing incompatible streams are never rewritten.
#[derive(Debug)]
pub struct JetStreamEventBus {
    context: Context,
    stream: String,
    prefix: String,
}

impl JetStreamEventBus {
    /// Persistent pull subscription. Reusing a durable never resets its acknowledgement cursor.
    pub async fn consumer(
        &self,
        name: &str,
    ) -> DomainResult<async_nats::jetstream::consumer::Consumer<async_nats::jetstream::consumer::pull::Config>> {
        use async_nats::jetstream::consumer::{AckPolicy, Config, DeliverPolicy};
        let stream =
            self.context.get_stream(&self.stream).await.map_err(|_| unavailable("Event stream unavailable"))?;
        let subject = format!("{}.>", self.prefix);
        let consumer = stream
            .get_or_create_consumer(
                name,
                Config {
                    durable_name: Some(name.into()),
                    name: Some(name.into()),
                    filter_subject: subject.clone(),
                    ack_policy: AckPolicy::Explicit,
                    deliver_policy: DeliverPolicy::All,
                    ack_wait: Duration::from_mins(2),
                    max_deliver: -1,
                    max_ack_pending: 128,
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| unavailable("Event consumer unavailable"))?;
        let config = &consumer.cached_info().config;
        if config.ack_policy != AckPolicy::Explicit
            || config.filter_subject != subject
            || config.deliver_subject.is_some()
            || config.max_deliver > 0
        {
            return Err(DomainError::Config(
                "Existing event consumer has incompatible acknowledgement or subject settings".into(),
            ));
        }
        stream.get_consumer(name).await.map_err(|_| unavailable("Event pull consumer unavailable"))
    }

    /// Connect to the configured stream and subject prefix (normally `agf.events`).
    pub async fn connect(url: &str, stream: &str, prefix: &str) -> DomainResult<Self> {
        if stream.is_empty()
            || !stream.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || prefix
                .split('.')
                .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)))
        {
            return Err(DomainError::Config("Invalid event stream or subject prefix".into()));
        }
        let client = super::connect_nats(&[url.to_string()], Duration::from_secs(5)).await?;
        let context = async_nats::jetstream::new(client);
        let subject = format!("{prefix}.>");
        let existing = context
            .get_or_create_stream(Config {
                name: stream.into(),
                subjects: vec![subject.clone()],
                storage: StorageType::File,
                retention: RetentionPolicy::Limits,
                discard: DiscardPolicy::New,
                max_bytes: 1_073_741_824,
                max_age: Duration::from_hours(168),
                duplicate_window: Duration::from_hours(24),
                ..Default::default()
            })
            .await
            .map_err(|_| unavailable("Unable to provision event stream"))?;
        let config = &existing.cached_info().config;
        if config.storage != StorageType::File
            || config.retention != RetentionPolicy::Limits
            || config.discard != DiscardPolicy::New
            || config.subjects != vec![subject]
        {
            return Err(DomainError::Config(
                "Existing event stream has incompatible subjects, storage or retention; review its configuration"
                    .into(),
            ));
        }
        Ok(Self { context, stream: stream.into(), prefix: prefix.into() })
    }
}

#[async_trait::async_trait]
impl EventBus for JetStreamEventBus {
    fn name(&self) -> &'static str {
        "nats-jetstream"
    }
    async fn publish(&self, event: &Event) -> DomainResult<()> {
        let subject = format!("{}.{}.{}", self.prefix, event.tenant_id, event.severity.as_str());
        let payload = serde_json::to_vec(event)?;
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", format!("{}:{}", event.tenant_id, event.id));
        let acknowledgement = self
            .context
            .publish_with_headers(subject, headers, payload.into())
            .await
            .map_err(|_| unavailable("Event publication failed"))?
            .await
            .map_err(|_| unavailable("Event storage acknowledgement missing"))?;
        if acknowledgement.stream != self.stream {
            return Err(unavailable("Unexpected event stream acknowledgement"));
        }
        Ok(())
    }
    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(events.len())
    }
    async fn health(&self) -> DomainResult<()> {
        self.context.get_stream(&self.stream).await.map_err(|_| unavailable("Event stream unavailable"))?;
        Ok(())
    }
}

fn unavailable(cause: &str) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "event-jetstream".into(), cause: cause.into() }
}

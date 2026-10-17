//! Shared durable source record used by the API and native collectors.
use super::LogSource;
use crate::{credential::SecretMaterial, ids::Id};
use serde::{Deserialize, Serialize};

/// Credentials stay sealed; public responses expose only source metadata and counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceRecord {
    /// None is a tombstone and must never be automatically registered again.
    pub source: Option<LogSource>,
    /// Encrypted HTTP pull headers.
    pub headers: Option<SecretMaterial>,
    /// Exclusive pull lease expiry.
    pub lease_until: i64,
    /// Owner of the pull lease.
    pub lease_id: Option<Id>,
    /// Next pull time, in Unix seconds.
    pub next_poll_at: i64,
    /// Upstream continuation cursor.
    pub cursor: Option<String>,
    /// Received records.
    pub received: u64,
    /// Matched parser records.
    pub matched: u64,
    /// Records that failed persistence.
    pub failed: u64,
    /// Native receiver binding; absent for API-managed HTTP push/pull sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_receiver: Option<String>,
}

/// Native deployment names have a fixed protocol, shared by console and collector validation.
#[must_use]
pub fn native_receiver_protocol(name: &str) -> Option<crate::enums::IngestProtocol> {
    use crate::enums::IngestProtocol as P;
    Some(match name {
        "syslog-udp" | "syslog-tcp" | "syslog-tls" => P::Syslog,
        "webhook" => P::Webhook,
        "kafka" => P::Kafka,
        "pulsar" | "pulsar-native" => P::Pulsar,
        "nats-jetstream" => P::Nats,
        "snmp-trap" => P::SnmpTrap,
        "mqtt" => P::Mqtt,
        "object-pull" => P::ObjectStorage,
        "sql-pull" => P::Jdbc,
        "otlp" | "otlp-traces" | "otlp-metrics" | "otlp-grpc" | "otlp-grpc-traces" | "otlp-grpc-metrics" => P::Otlp,
        _ => return None,
    })
}

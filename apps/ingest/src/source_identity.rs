//! A receiver deployment has a fixed tenant and stable source identities across restarts.
use agf_core::{
    enums::IngestProtocol,
    ids::{Id, TenantId, deterministic_id},
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub(crate) struct SourceIdentity {
    pub tenant: TenantId,
    pub instance: String,
    source_ids: BTreeMap<String, Id>,
}

const RECEIVERS: &[&str] = &[
    "syslog-udp",
    "syslog-tcp",
    "syslog-tls",
    "webhook",
    "kafka",
    "pulsar",
    "pulsar-native",
    "nats-jetstream",
    "snmp-trap",
    "mqtt",
    "object-pull",
    "sql-pull",
    "otlp",
    "otlp-traces",
    "otlp-metrics",
    "otlp-grpc",
    "otlp-grpc-traces",
    "otlp-grpc-metrics",
];

impl SourceIdentity {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        Self::parse(
            &std::env::var("AGF_INGEST_TENANT_ID").unwrap_or_default(),
            &std::env::var("AGF_INGEST_INSTANCE_ID").unwrap_or_else(|_| "local".into()),
            &std::env::var("AGF_INGEST_SOURCE_IDS").unwrap_or_else(|_| "{}".into()),
        )
    }

    fn parse(tenant: &str, instance: &str, ids: &str) -> anyhow::Result<Self> {
        let tenant = if tenant.trim().is_empty() { TenantId::default_tenant() } else { tenant.trim().parse()? };
        anyhow::ensure!(tenant.to_string() != "00000000-0000-0000-0000-000000000000", "Tenant must not be nil");
        let instance = instance.trim();
        anyhow::ensure!(
            !instance.is_empty()
                && instance.len() <= 64
                && instance.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "AGF_INGEST_INSTANCE_ID must contain 1-64 letters, digits, dots, underscores or hyphens"
        );
        anyhow::ensure!(ids.len() <= 8192, "AGF_INGEST_SOURCE_IDS exceeds 8192 bytes");
        let source_ids: BTreeMap<String, Id> = serde_json::from_str(if ids.trim().is_empty() { "{}" } else { ids })?;
        let mut unique = BTreeSet::new();
        for (name, id) in &source_ids {
            anyhow::ensure!(RECEIVERS.contains(&name.as_str()), "Unknown receiver name: {name}");
            anyhow::ensure!(*id != Id::nil() && unique.insert(*id), "Source IDs must be non-nil and unique");
        }
        Ok(Self { tenant, instance: instance.into(), source_ids })
    }

    pub(crate) fn source_id(&self, protocol: IngestProtocol, name: &str) -> Id {
        self.source_ids.get(name).copied().unwrap_or_else(|| {
            deterministic_id("agf-native-receiver", &format!("{}:{}:{protocol:?}:{name}", self.tenant, self.instance))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restarts_are_stable_and_tenant_instance_and_receiver_boundaries_are_distinct() {
        let a = SourceIdentity::parse("", "branch-a", "{}").unwrap();
        let b = SourceIdentity::parse("", "branch-a", "{}").unwrap();
        let c = SourceIdentity::parse("", "branch-b", "{}").unwrap();
        let d = SourceIdentity::parse("00000000-0000-0000-0000-000000000002", "branch-a", "{}").unwrap();
        let id = |value: &SourceIdentity| value.source_id(IngestProtocol::Syslog, "syslog-tcp");
        assert_eq!(id(&a), id(&b));
        assert_ne!(id(&a), id(&c));
        assert_ne!(id(&a), id(&d));
        assert_ne!(id(&a), a.source_id(IngestProtocol::Syslog, "syslog-udp"));
    }
    #[test]
    fn invalid_identity_fails_and_explicit_source_binding_is_preserved() {
        assert!(SourceIdentity::parse("typo", "local", "{}").is_err());
        assert!(SourceIdentity::parse("", "../other", "{}").is_err());
        assert!(SourceIdentity::parse("", "local", r#"{"unknown":"00000000-0000-0000-0000-000000000002"}"#).is_err());
        let value =
            SourceIdentity::parse("", "local", r#"{"syslog-tcp":"00000000-0000-0000-0000-000000000002"}"#).unwrap();
        assert_eq!(
            value.source_id(IngestProtocol::Syslog, "syslog-tcp").to_string(),
            "00000000-0000-0000-0000-000000000002"
        );
    }
}

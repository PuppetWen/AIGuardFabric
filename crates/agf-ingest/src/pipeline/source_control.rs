//! Native collectors share the console's source lifecycle and parser configuration.
use super::*;
use agf_core::{enums::HealthState, parser::Parser, source::SourceRecord};
use agf_storage::configuration::ConfigStore;

/// Persistent native-source registry. One deployment is assigned one tenant.
#[derive(Debug)]
pub struct NativeSourceControl {
    database: Option<Arc<agf_storage::Store>>,
    configurations: Arc<ConfigStore>,
    registry: ParserRegistry,
}

#[derive(Deserialize)]
struct ParserRevision {
    parser: Parser,
}
#[derive(Deserialize)]
struct ParserRecord {
    current: Option<ParserRevision>,
    deleted: bool,
}

impl NativeSourceControl {
    /// Use the same SQL configuration store as the API; None is only for offline tests.
    #[must_use]
    pub fn new(database: Option<Arc<agf_storage::Store>>, registry: ParserRegistry) -> Self {
        let configurations = Arc::new(ConfigStore::new(database.clone()));
        Self { database, configurations, registry }
    }

    pub(super) async fn resolve(&self, base: &LogSource) -> DomainResult<(LogSource, ParserRegistry)> {
        if let Some(database) = &self.database {
            // The tenant directory is platform metadata; the restricted business role
            // intentionally cannot enumerate it. Bind the deployment's exact tenant ID.
            let enabled: Option<bool> =
                sqlx::query_scalar("SELECT enabled FROM tenants WHERE id=$1 AND deleted_at IS NULL")
                    .bind(base.tenant_id.as_uuid())
                    .fetch_optional(database.db().pool())
                    .await
                    .map_err(|error| {
                        tracing::error!(%error, "Native receiver tenant lookup failed");
                        DomainError::DependencyUnavailable {
                            dependency: "postgres".into(),
                            cause: "Cannot verify native receiver tenant".into(),
                        }
                    })?;
            if enabled != Some(true) {
                return Err(DomainError::Forbidden("Native receiver tenant is disabled or missing".into()));
            }
        }
        // Option distinguishes an absent row from an explicit source=None tombstone.
        let existing: Option<SourceRecord> = self.configurations.get(base.tenant_id, "log-source", base.id).await?;
        let row = if let Some(row) = existing {
            row
        } else {
            self.configurations
                .mutate::<Option<SourceRecord>, _>(base.tenant_id, "log-source", base.id, |row| {
                    if row.is_none() {
                        let mut public_source = base.clone();
                        // Receiver constructors may carry MQTT/SNMP/Pulsar credentials in
                        // connection headers. Persist only the binding, never runtime secrets.
                        public_source.connection = agf_core::source::SourceConnection {
                            endpoint: Some(format!("receiver://{}", base.product)),
                            tls: base.connection.tls,
                            ..Default::default()
                        };
                        *row = Some(SourceRecord {
                            source: Some(public_source),
                            native_receiver: Some(base.product.clone()),
                            ..SourceRecord::default()
                        });
                    }
                    Ok(())
                })
                .await?
                .ok_or_else(|| DomainError::Internal("Native source registration missing".into()))?
        };
        let source = row.source.ok_or_else(|| {
            DomainError::Forbidden("Native source was deleted; register a new source ID to resume".into())
        })?;
        if source.tenant_id != base.tenant_id
            || source.id != base.id
            || source.protocol != base.protocol
            || row.native_receiver.as_deref() != Some(base.product.as_str())
        {
            return Err(DomainError::Forbidden("Native source binding does not match the configured receiver".into()));
        }
        if !source.enabled {
            return Err(DomainError::Forbidden("Native source is disabled in the console".into()));
        }
        let mut registry = self.registry.clone();
        let records: Vec<ParserRecord> = self.configurations.list(base.tenant_id, "parser-template").await?;
        for row in records {
            if !row.deleted {
                if let Some(current) = row.current {
                    registry.upsert(current.parser)?;
                }
            }
        }
        if source.parser_id.is_some_and(|id| registry.find_id(id).is_none_or(|parser| !parser.enabled)) {
            return Err(DomainError::PreconditionFailed(
                "Bound parser is missing or disabled; update the source in the console".into(),
            ));
        }
        Ok((source, registry))
    }

    pub(super) async fn record_rejection(&self, source: &LogSource, error: &DomainError) -> DomainResult<()> {
        self.configurations
            .mutate::<SourceRecord, _>(source.tenant_id, "log-source", source.id, |row| {
                if let Some(current) = row.source.as_mut() {
                    current.last_error = Some(error.to_string().chars().take(1024).collect());
                    current.health = HealthState::Degraded;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub(super) async fn record(&self, source: &LogSource, outcomes: &[IngestOutcome]) -> DomainResult<()> {
        self.configurations
            .mutate::<SourceRecord, _>(source.tenant_id, "log-source", source.id, |row| {
                let Some(current) = row.source.as_mut() else {
                    return Ok(());
                };
                for outcome in outcomes {
                    row.received = row.received.saturating_add(1);
                    row.matched = row.matched.saturating_add(u64::from(outcome.matched));
                    row.failed = row.failed.saturating_add(u64::from(!outcome.persisted));
                    current.total_events = current.total_events.saturating_add(u64::from(outcome.persisted));
                    if outcome.persisted {
                        current.last_event_at = Some(Timestamp::now());
                    }
                }
                current.last_error = outcomes.iter().find_map(|outcome| outcome.error.clone());
                current.health =
                    if current.last_error.is_some() { HealthState::Degraded } else { HealthState::Healthy };
                Ok(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use agf_core::source::{CollectionMode, SourceConnection};

    #[tokio::test]
    async fn native_source_respects_console_changes_and_never_revives_a_tombstone() {
        let control = NativeSourceControl::new(None, ParserRegistry::with_builtins());
        let mut source = LogSource {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "syslog-udp".into(),
            protocol: IngestProtocol::Syslog,
            vendor: String::new(),
            product: "syslog-udp".into(),
            enabled: true,
            parser_id: None,
            connection: SourceConnection::default(),
            mode: CollectionMode::Push,
            poll_interval_secs: None,
            require_mtls: false,
            allowed_cidrs: vec![],
            max_message_bytes: 4096,
            max_eps: 100,
            tags: vec![],
            health: HealthState::Unconfigured,
            last_event_at: None,
            total_events: 0,
            last_error: None,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };
        source.connection.headers.insert("password".into(), "fixture-runtime-secret".into());
        source.connection.endpoint = Some("mqtt://user:fixture-runtime-secret@localhost".into());
        assert_eq!(control.resolve(&source).await.unwrap().0.id, source.id);
        let stored: SourceRecord =
            control.configurations.get(source.tenant_id, "log-source", source.id).await.unwrap().unwrap();
        assert!(!serde_json::to_string(&stored).unwrap().contains("fixture-runtime-secret"));
        assert_eq!(stored.source.unwrap().connection.endpoint.as_deref(), Some("receiver://syslog-udp"));
        control
            .configurations
            .mutate::<SourceRecord, _>(source.tenant_id, "log-source", source.id, |row| {
                row.source.as_mut().unwrap().enabled = false;
                Ok(())
            })
            .await
            .unwrap();
        assert!(control.resolve(&source).await.unwrap_err().to_string().contains("disabled"));
        let mut parser = control.registry.all()[0].clone();
        parser.id = Id::new();
        parser.definition.key = "native-source-template".into();
        control
            .configurations
            .mutate::<SourceRecord, _>(source.tenant_id, "log-source", source.id, |row| {
                let current = row.source.as_mut().unwrap();
                current.enabled = true;
                current.parser_id = Some(parser.id);
                Ok(())
            })
            .await
            .unwrap();
        control
            .configurations
            .put(
                source.tenant_id,
                "parser-template",
                parser.id,
                &serde_json::json!({"current":{"parser":parser},"deleted":false}),
            )
            .await
            .unwrap();
        let (resolved, registry) = control.resolve(&source).await.unwrap();
        assert_eq!(resolved.parser_id, Some(parser.id));
        assert_eq!(registry.find_id(parser.id).unwrap().definition.key, "native-source-template");
        parser.enabled = false;
        control
            .configurations
            .put(
                source.tenant_id,
                "parser-template",
                parser.id,
                &serde_json::json!({"current":{"parser":parser},"deleted":false}),
            )
            .await
            .unwrap();
        assert!(control.resolve(&source).await.unwrap_err().to_string().contains("parser"));
        control.configurations.put(source.tenant_id, "log-source", source.id, &SourceRecord::default()).await.unwrap();
        assert!(control.resolve(&source).await.unwrap_err().to_string().contains("deleted"));
        let tombstone: SourceRecord =
            control.configurations.get(source.tenant_id, "log-source", source.id).await.unwrap().unwrap();
        assert!(tombstone.source.is_none());
    }
}

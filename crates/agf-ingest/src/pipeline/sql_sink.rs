//! PostgreSQL sink implementation, including verified AgentTeams audit transactions.
use super::*;

#[async_trait]
impl Sink for SqlSink {
    async fn agentteams_failure_snapshot(
        &self,
        query: &AgentTeamsFailureQuery,
    ) -> DomainResult<AgentTeamsFailureSnapshot> {
        super::agentteams_failure_sql::snapshot(&self.store, query).await
    }
    async fn agentteams_failure_record(&self, tenant: TenantId, id: Id) -> DomainResult<Option<AgentTeamsAuditRecord>> {
        super::agentteams_failure_sql::record(&self.store, tenant, id).await
    }

    async fn persist_agentteams(
        &self,
        guard: &AgentTeamsBindingGuard,
        items: &[AgentTeamsIngestItem],
    ) -> DomainResult<AgentTeamsIngestResult> {
        super::agentteams_sql::persist(&self.store, guard, items, self.event_outbox).await
    }

    async fn agentteams_audit_records(&self, query: &AgentTeamsAuditQuery) -> DomainResult<Vec<AgentTeamsAuditRecord>> {
        super::agentteams_queries::records(&self.store, query).await
    }

    async fn agentteams_trace_snapshot(&self, query: &AgentTeamsTraceQuery) -> DomainResult<AgentTeamsTraceSnapshot> {
        super::agentteams_trace_sql::snapshot(&self.store, query).await
    }

    async fn agentteams_audit_aggregate(
        &self,
        tenant: TenantId,
        scope: Id,
        from: Timestamp,
        until: Timestamp,
    ) -> DomainResult<AgentTeamsAuditAggregate> {
        super::agentteams_queries::aggregate(&self.store, tenant, scope, from, until).await
    }

    fn queues_events(&self) -> bool {
        self.event_outbox
    }
    async fn persist_ingest(&self, items: &[IngestWrite]) -> DomainResult<usize> {
        super::persistence::persist_sql(&self.store, items, self.event_outbox).await
    }

    fn database(&self) -> Option<Arc<agf_storage::Store>> {
        Some(self.store.clone())
    }
    fn backend(&self) -> &'static str {
        "sql"
    }

    async fn put_raw(&self, raw: &RawLog) -> DomainResult<()> {
        // 闭包按 `'static` 装箱，因此需要把入参克隆进闭包（RawLog 为小型结构，开销可接受）
        let owned = raw.clone();
        self.store
            .with_tenant(raw.tenant_id, move |tx| {
                Box::pin(async move { agf_storage::repository::EventRepo::insert_raw(tx, &owned).await })
            })
            .await
    }

    async fn mark_raw(
        &self,
        tenant: TenantId,
        raw_id: Id,
        parsed: bool,
        event_id: Option<Id>,
        error: Option<&str>,
    ) -> DomainResult<()> {
        let error_text = error.map(ToString::to_string);
        self.store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE raw_logs SET parsed = $1, event_id = $2, parse_error = $3 WHERE id = $4")
                        .bind(parsed)
                        .bind(event_id.map(|v| v.as_uuid()))
                        .bind(&error_text)
                        .bind(raw_id.as_uuid())
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("mark_raw_log", &e))?;
                    Ok(())
                })
            })
            .await
    }

    async fn put_event(&self, event: &Event) -> DomainResult<()> {
        let owned = event.clone();
        self.store
            .with_tenant(event.tenant_id, move |tx| {
                Box::pin(async move { agf_storage::repository::EventRepo::insert(tx, &owned).await })
            })
            .await
    }

    async fn put_events(&self, events: &[Event]) -> DomainResult<usize> {
        let Some(first) = events.first() else { return Ok(0) };
        let tenant = first.tenant_id;
        let owned: Vec<Event> = events.to_vec();
        self.store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move { agf_storage::repository::EventRepo::insert_batch(tx, &owned).await })
            })
            .await
    }

    async fn get_event(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Event>> {
        use sqlx::Row;
        self.store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"SELECT id::text AS id, tenant_id::text AS tenant_id, time, ingested_at, category, action,
                                  action_raw, severity, source_id::text AS source_id, source_name, protocol,
                                  parser_id::text AS parser_id, parser_name, vendor, product, host, "user", network, ai,
                                  message, raw, raw_ref, raw_hash, redacted, tags, extra
                           FROM events WHERE id = $1"#,
                    )
                    .bind(id.as_uuid())
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("get_event_raw", &e))?;
                    let Some(row) = row else { return Ok(None) };
                    let now = Timestamp::now().as_datetime();
                    let value = serde_json::json!({
                        "id": row.try_get::<String, _>("id").unwrap_or_default(),
                        "tenant_id": row.try_get::<String, _>("tenant_id").unwrap_or_default(),
                        "time": row.try_get::<chrono::DateTime<chrono::Utc>, _>("time").unwrap_or(now),
                        "ingested_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("ingested_at").unwrap_or(now),
                        "category": row.try_get::<String, _>("category").unwrap_or_default(),
                        "action": row.try_get::<String, _>("action").unwrap_or_default(),
                        "action_raw": row.try_get::<String, _>("action_raw").unwrap_or_default(),
                        "severity": row.try_get::<String, _>("severity").unwrap_or_default(),
                        "source_id": row.try_get::<String, _>("source_id").unwrap_or_default(),
                        "source_name": row.try_get::<String, _>("source_name").unwrap_or_default(),
                        "protocol": row.try_get::<String, _>("protocol").unwrap_or_default(),
                        "parser_id": row.try_get::<Option<String>, _>("parser_id").unwrap_or(None),
                        "parser_name": row.try_get::<Option<String>, _>("parser_name").unwrap_or(None),
                        "vendor": row.try_get::<String, _>("vendor").unwrap_or_default(),
                        "product": row.try_get::<String, _>("product").unwrap_or_default(),
                        "host": row.try_get::<Value, _>("host").unwrap_or(Value::Null),
                        "user": row.try_get::<Value, _>("user").unwrap_or(Value::Null),
                        "network": row.try_get::<Value, _>("network").unwrap_or(Value::Null),
                        "ai": row.try_get::<Value, _>("ai").unwrap_or(Value::Null),
                        "message": row.try_get::<String, _>("message").unwrap_or_default(),
                        "raw": row.try_get::<Value, _>("raw").unwrap_or(Value::Null),
                        "raw_ref": row.try_get::<Option<String>, _>("raw_ref").unwrap_or(None),
                        "raw_hash": row.try_get::<String, _>("raw_hash").unwrap_or_default(),
                        "redacted": row.try_get::<bool, _>("redacted").unwrap_or(false),
                        "tags": row.try_get::<Value, _>("tags").unwrap_or(Value::Null),
                        "extra": row.try_get::<Value, _>("extra").unwrap_or(Value::Null),
                    });
                    serde_json::from_value::<Event>(value)
                        .map(Some)
                        .map_err(|e| DomainError::Parse(format!("事件反序列化失败: {e}")))
                })
            })
            .await
    }

    async fn unparsed_raw(&self, tenant: TenantId, limit: i64) -> DomainResult<Vec<RawLog>> {
        self.store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move { agf_storage::repository::EventRepo::unparsed_raw(tx, limit).await })
            })
            .await
    }

    async fn event_count(&self, tenant: TenantId) -> DomainResult<u64> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE tenant_id=$1")
            .bind(tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| DomainError::Internal(format!("读取事件计数失败: {error}")))?;
        tx.commit().await?;
        Ok(u64::try_from(n.max(0)).unwrap_or(0))
    }

    async fn raw_count(&self, tenant: TenantId) -> DomainResult<u64> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM raw_logs WHERE tenant_id=$1")
            .bind(tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| DomainError::Internal(format!("读取原始日志计数失败: {error}")))?;
        tx.commit().await?;
        Ok(u64::try_from(n.max(0)).unwrap_or(0))
    }
}

//! 流水线主体：`IngestPipeline`（去重 → 解析 → 归一化 → 脱敏 → 落库 → 投递）与脱敏/解码工具。

use super::dedup::DedupBatch;
use super::*;

// ---------------------------------------------------------------------------
// 流水线
// ---------------------------------------------------------------------------

/// 一体化接入流水线。
#[derive(Debug)]
pub struct IngestPipeline {
    registry: Mutex<ParserRegistry>,
    source_control: Option<Arc<NativeSourceControl>>,
    sink: Arc<dyn Sink>,
    bus: Arc<dyn EventBus>,
    config: IngestConfig,
    dedup: super::dedup::Window,
    source_gates: [tokio::sync::Mutex<()>; 64],
    buckets: Mutex<HashMap<Id, TokenBucket>>,
    counters: Counters,
}

impl IngestPipeline {
    /// 构造。
    #[must_use]
    pub fn new(registry: ParserRegistry, sink: Arc<dyn Sink>, bus: Arc<dyn EventBus>, config: IngestConfig) -> Self {
        Self {
            registry: Mutex::new(registry),
            source_control: None,
            sink,
            bus,
            config,
            dedup: Mutex::new(HashMap::new()),
            source_gates: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
            buckets: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }
    }

    /// Attach console source lifecycle and tenant parser resolution to a native receiver.
    #[must_use]
    pub fn with_source_control(mut self, control: Arc<NativeSourceControl>) -> Self {
        self.source_control = Some(control);
        self
    }

    /// 用内置模板 + 内存落地 + 无总线构造（测试/演示）。
    #[must_use]
    pub fn in_memory(sink: Arc<dyn Sink>) -> Self {
        Self::new(
            ParserRegistry::with_builtins(),
            sink,
            Arc::new(NoopEventBus),
            IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
        )
    }

    /// 统计快照。
    #[must_use]
    pub fn stats(&self) -> PipelineStats {
        self.counters.snapshot()
    }

    /// 解析器注册表统计。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn registry_stats(&self) -> DomainResult<RegistryStats> {
        self.registry.lock().map(|r| r.stats()).map_err(|e| DomainError::Internal(format!("注册表锁中毒: {e}")))
    }

    /// 注册表只读访问（加载 YAML 模板等）。
    ///
    /// # Errors
    /// 锁中毒或注册失败。
    pub fn with_registry<T>(&self, f: impl FnOnce(&mut ParserRegistry) -> T) -> DomainResult<T> {
        let mut guard = self.registry.lock().map_err(|e| DomainError::Internal(format!("注册表锁中毒: {e}")))?;
        Ok(f(&mut guard))
    }

    /// 接入一条原始报文。
    ///
    /// # Errors
    /// 报文超限（[`DomainError::Validation`]）、限流（[`DomainError::RateLimited`]）或落库失败。
    pub async fn ingest_raw(
        &self,
        source: &LogSource,
        protocol: IngestProtocol,
        payload: &[u8],
        origin: &str,
    ) -> DomainResult<IngestOutcome> {
        self.ingest_raw_from(source, protocol, payload, origin, TransportPeer::default()).await
    }

    /// Ingest using attributes verified by the receiving transport.
    ///
    /// # Errors
    /// Source access is denied, limits are exceeded or persistence fails.
    pub async fn ingest_raw_from(
        &self,
        source: &LogSource,
        protocol: IngestProtocol,
        payload: &[u8],
        origin: &str,
        peer: TransportPeer,
    ) -> DomainResult<IngestOutcome> {
        let mut resolved = match &self.source_control {
            Some(control) => Some(control.resolve(source).await?),
            None => None,
        };
        let (source, registry) = match &mut resolved {
            Some((source, registry)) => (&*source, Some(registry)),
            None => (source, None),
        };
        self.authorize_transport(source, peer).await?;
        let gate = self.source_gates[source.id.as_uuid().as_u128() as usize % self.source_gates.len()].lock().await;
        let mut dedup = DedupBatch::new(&self.dedup, self.config.dedup_window_secs);
        let prepared = self.prepare(source, protocol, payload, origin, registry, &mut dedup)?;
        self.persist(std::slice::from_ref(&prepared)).await?;
        dedup.commit();
        drop(gate);
        // 去重命中的报文只保留原始日志，不再向总线投递（否则下游会二次处理）
        if !prepared.outcome.deduped {
            self.emit(std::slice::from_ref(&prepared.event)).await;
        }
        if let Some(control) = &self.source_control {
            control.record(source, std::slice::from_ref(&prepared.outcome)).await?;
        }
        Ok(prepared.outcome)
    }

    /// 批量接入（背压：超过 `batch_limit` 的条目直接拒绝并计数）。
    ///
    /// # Errors
    /// 落库整体失败时返回错误；单条失败记入 `IngestOutcome::error` 而不中断整批。
    pub async fn ingest_batch(
        &self,
        source: &LogSource,
        protocol: IngestProtocol,
        items: &[(Vec<u8>, String)],
    ) -> DomainResult<Vec<IngestOutcome>> {
        self.ingest_batch_from(source, protocol, items, TransportPeer::default()).await
    }

    /// Ingest using attributes verified by the receiving transport.
    ///
    /// # Errors
    /// Source access is denied, limits are exceeded or persistence fails.
    pub async fn ingest_batch_from(
        &self,
        source: &LogSource,
        protocol: IngestProtocol,
        items: &[(Vec<u8>, String)],
        peer: TransportPeer,
    ) -> DomainResult<Vec<IngestOutcome>> {
        let mut resolved = match &self.source_control {
            Some(control) => Some(control.resolve(source).await?),
            None => None,
        };
        let (source, mut registry) = match &mut resolved {
            Some((source, registry)) => (&*source, Some(registry)),
            None => (source, None),
        };
        self.authorize_transport(source, peer).await?;
        let gate = self.source_gates[source.id.as_uuid().as_u128() as usize % self.source_gates.len()].lock().await;
        let mut dedup = DedupBatch::new(&self.dedup, self.config.dedup_window_secs);
        let mut prepared = Vec::new();
        let mut outcomes: Vec<IngestOutcome> = Vec::new();
        for (payload, origin) in items.iter().take(self.config.batch_limit) {
            match self.prepare(source, protocol, payload, origin, registry.as_deref_mut(), &mut dedup) {
                Ok(item) => {
                    outcomes.push(item.outcome.clone());
                    prepared.push(item);
                }
                Err(e) => {
                    outcomes.push(IngestOutcome {
                        raw_id: Id::nil(),
                        event_id: None,
                        parser_key: None,
                        matched_by: None,
                        matched: false,
                        persisted: false,
                        deduped: false,
                        redacted: false,
                        bytes: payload.len(),
                        elapsed_micros: 0,
                        origin: origin.clone(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }
        let over = items.len().saturating_sub(self.config.batch_limit);
        for (payload, origin) in items.iter().skip(self.config.batch_limit) {
            self.counters.oversized.fetch_add(1, Ordering::Relaxed);
            outcomes.push(IngestOutcome {
                raw_id: Id::nil(),
                event_id: None,
                parser_key: None,
                matched_by: None,
                matched: false,
                persisted: false,
                deduped: false,
                redacted: false,
                bytes: payload.len(),
                elapsed_micros: 0,
                origin: origin.clone(),
                error: Some(format!("超过单批上限 {}，已拒绝（本批超出 {over} 条）", self.config.batch_limit)),
            });
        }
        self.persist(&prepared).await?;
        dedup.commit();
        drop(gate);
        // 同 ingest_raw：去重命中的事件不投递总线
        let events: Vec<Event> = prepared.iter().filter(|p| !p.outcome.deduped).map(|p| p.event.clone()).collect();
        self.emit(&events).await;
        if let Some(control) = &self.source_control {
            control.record(source, &outcomes).await?;
        }
        Ok(outcomes)
    }

    async fn authorize_transport(&self, source: &LogSource, peer: TransportPeer) -> DomainResult<()> {
        if let Err(error) = peer.authorize(source) {
            if let Some(control) = &self.source_control {
                if let Err(record_error) = control.record_rejection(source, &error).await {
                    warn!(%record_error, "Failed to update source rejection status");
                }
            }
            return Err(error);
        }
        Ok(())
    }

    /// 前置阶段：闸门 → 落原始日志 → 解析 → 归一化 → 脱敏。不写事件、不投递。
    fn prepare(
        &self,
        source: &LogSource,
        protocol: IngestProtocol,
        payload: &[u8],
        origin: &str,
        resolved_registry: Option<&mut ParserRegistry>,
        dedup: &mut DedupBatch<'_>,
    ) -> DomainResult<Prepared> {
        if !source.enabled {
            return Err(DomainError::Forbidden("Log source is disabled".into()));
        }
        let start = Instant::now();
        self.counters.received.fetch_add(1, Ordering::Relaxed);

        if payload.len() > source.max_message_bytes {
            self.counters.oversized.fetch_add(1, Ordering::Relaxed);
            return Err(DomainError::Validation(format!(
                "报文 {} 字节超过日志源上限 {} 字节",
                payload.len(),
                source.max_message_bytes
            )));
        }
        if !self.acquire_token(source.id, source.max_eps) {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(DomainError::RateLimited(format!(
                "日志源 {} 超过 {} EPS 上限，已拒绝",
                source.name, source.max_eps
            )));
        }

        let received_at = Timestamp::now();
        let payload_hash = content_hash(&String::from_utf8_lossy(payload));
        let raw_id = Id::new();
        let raw = RawLog {
            id: raw_id,
            tenant_id: source.tenant_id,
            source_id: source.id,
            received_at,
            protocol,
            payload_b64: B64.encode(payload),
            payload_hash: payload_hash.clone(),
            bytes: payload.len(),
            origin: origin.to_string(),
            parsed: false,
            parse_error: None,
            event_id: None,
        };

        // 解析（锁内完成，避免跨 await 持有）
        let text = String::from_utf8_lossy(payload).to_string();
        let (outcome, match_mode) = {
            let mut registry = self.registry.lock().map_err(|e| DomainError::Internal(format!("注册表锁中毒: {e}")))?;
            let registry = resolved_registry.unwrap_or(&mut registry);
            let parser_key = source.parser_id.and_then(|id| registry.find_id(id).map(|p| p.definition.key.clone()));
            let vendor = if source.vendor.is_empty() { None } else { Some(source.vendor.as_str()) };
            registry.match_raw_with_mode(&text, protocol, vendor, parser_key.as_deref())
        };
        if outcome.matched {
            self.counters.matched.fetch_add(1, Ordering::Relaxed);
            if let Some(mode) = match_mode {
                // 逐趟如实计数：`matched` 是总量、`matched_relaxed` 是其中一格，这里是全量分项。
                // 两处都要写：① 实例级（`/stats` 的 `pipeline.matched_by`）；
                // ② 进程级（`/metrics` 的 `agf_ingest_matched_by_total`，见 [`crate::metrics`]）。
                self.counters.record_mode(mode);
                crate::metrics::record_matched_by(mode);
            }
            if match_mode.is_some_and(|mode| mode.is_relaxed()) {
                // 放宽趟命中（协议白名单被忽略）——如实计数，便于解释命中率变化
                self.counters.matched_relaxed.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.counters.unmatched.fetch_add(1, Ordering::Relaxed);
        }

        let mut meta = SourceMeta::from_source(source);
        meta.ingested_at = received_at;
        meta.protocol = protocol;
        let mut event = normalize::normalize(&outcome, &meta, &text, origin);
        let redactions = redact_event(&mut event, self.config.redaction);
        if redactions > 0 {
            self.counters.redacted.fetch_add(1, Ordering::Relaxed);
        }

        // 去重（键 = 源 + 事件时间 + 原始哈希）
        let deduped = dedup.check(&event, received_at);
        if deduped {
            self.counters.deduped.fetch_add(1, Ordering::Relaxed);
        }
        let event_id = if deduped { None } else { Some(event.id) };

        Ok(Prepared {
            raw: RawLog { parsed: outcome.matched && !deduped, event_id, parse_error: outcome.error.clone(), ..raw },
            event,
            outcome: IngestOutcome {
                raw_id,
                event_id,
                parser_key: outcome.parser_key.clone(),
                // 逐条趟次：注册表在命中时回填 `ParseOutcome::matched_by`，这里原样透出
                matched_by: outcome.matched_by.clone(),
                matched: outcome.matched,
                persisted: true,
                deduped,
                redacted: redactions > 0,
                bytes: payload.len(),
                elapsed_micros: u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
                origin: origin.to_string(),
                // 未命中模板时**如实回填原因**（此前恒为 None，导致"全量未命中"看起来
                // 和"全部命中"一样成功）。原始日志仍保真落库、事件仍按缺省字段生成，
                // 因此这不改变"保真优先"的行为，只让 `matched=false` 在结果里可见。
                // 不变量：`error.is_some()` ⟺ 未命中模板或被批量上限拒绝。
                error: if outcome.matched {
                    None
                } else {
                    Some(outcome.error.clone().unwrap_or_else(|| "无模板命中（可上送 AI 推断生成解析器）".to_string()))
                },
            },
        })
    }

    /// 落原始日志 + 事件 + 回填解析状态。
    async fn persist(&self, prepared: &[Prepared]) -> DomainResult<()> {
        let items: Vec<IngestWrite> = prepared
            .iter()
            .map(|item| {
                let mut raw = item.raw.clone();
                if item.outcome.deduped {
                    raw.parsed = true;
                    raw.event_id = None;
                    raw.parse_error = Some("重复报文，事件已去重丢弃".into());
                }
                IngestWrite { raw, event: (!item.outcome.deduped).then(|| item.event.clone()) }
            })
            .collect();
        let written = self.sink.persist_ingest(&items).await?;
        self.counters.persisted.fetch_add(u64::try_from(written).unwrap_or(0), Ordering::Relaxed);
        Ok(())
    }

    /// 投递总线（失败只告警，不回滚）。
    async fn emit(&self, events: &[Event]) {
        if self.sink.queues_events() || !self.config.emit_to_bus || events.is_empty() {
            return;
        }
        match self.bus.publish_batch(events).await {
            Ok(n) => debug!(published = n, "事件已投递总线"),
            Err(e) => {
                warn!(error = %e, count = events.len(), "事件总线投递失败（事件已落库，可由回放重建）");
                self.counters.bus_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 令牌桶取令牌（`max_eps = 0` 表示不限速）。
    /// Reserve a whole typed batch against the same process-local source bucket as generic ingestion.
    ///
    /// # Errors
    /// Invalid batch size, poisoned bucket state, or insufficient source EPS capacity.
    pub fn admit_batch(&self, source: &LogSource, count: usize) -> DomainResult<()> {
        let count = u32::try_from(count).map_err(|_| DomainError::Validation("Batch too large".into()))?;
        if source.max_eps == 0 || count == 0 {
            return Ok(());
        }
        let mut buckets =
            self.buckets.lock().map_err(|_| DomainError::Internal("Source limiter unavailable".into()))?;
        let bucket = buckets.entry(source.id).or_insert_with(|| TokenBucket::new(source.max_eps));
        bucket.set_rate(source.max_eps);
        if !bucket.try_acquire_many(count) {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(DomainError::RateLimited("日志源 EPS 容量不足，请减小批次并稍后重试".into()));
        }
        Ok(())
    }

    /// 令牌桶取令牌（`max_eps = 0` 表示不限速）。
    fn acquire_token(&self, source_id: Id, max_eps: u32) -> bool {
        if max_eps == 0 {
            return true;
        }
        let Ok(mut buckets) = self.buckets.lock() else {
            warn!("令牌桶锁中毒，跳过限流（可用性优先）");
            return true;
        };
        let bucket = buckets.entry(source_id).or_insert_with(|| TokenBucket::new(max_eps));
        bucket.set_rate(max_eps);
        bucket.try_acquire()
    }
}

/// 预处理结果（内部使用）。
#[derive(Debug, Clone)]
struct Prepared {
    raw: RawLog,
    event: Event,
    outcome: IngestOutcome,
}

/// 落库前脱敏：对事件的 `raw` / `message` 副本打码，原始载荷仍在 `raw_logs` 中保真。
///
/// 返回脱敏条目数（0 表示未命中任何凭据）。
#[must_use]
pub fn redact_event(event: &mut Event, mode: RedactionMode) -> usize {
    if !mode.is_active() {
        return 0;
    }
    let mut hits = scan_credentials(&event.message, &[]);
    if hits.is_empty() {
        hits = scan_credentials(&event.raw.to_string(), &[]);
    }
    if hits.is_empty() {
        return 0;
    }
    let mut map = RedactionMap::new();
    event.raw = redact_json(&event.raw, mode, &mut map);
    event.message = redact_text(&event.message, mode, &mut map).text;
    let count = map.entries().len();
    if count == 0 {
        return 0;
    }
    event.redacted = true;
    event.extra.insert("agf.redaction.count".to_string(), Value::from(u64::try_from(count).unwrap_or(0)));
    let categories: Vec<String> = map.entries().iter().map(|r| r.category.clone()).collect();
    event.extra.insert("agf.redaction.categories".to_string(), Value::from(categories));
    count
}

/// 从原始日志还原文本载荷（回放/排障用）。
///
/// # Errors
/// base64 非法或非 UTF-8。
pub fn decode_payload(raw: &RawLog) -> DomainResult<String> {
    let bytes = B64.decode(&raw.payload_b64).map_err(|e| DomainError::Parse(format!("原始载荷 base64 非法: {e}")))?;
    String::from_utf8(bytes).map_err(|e| DomainError::Parse(format!("原始载荷非 UTF-8: {e}")))
}

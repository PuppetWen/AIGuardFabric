//! 回放计划与报告模型：`ReplayConfig`、`ReplayReport` / `ReplayFailure` / `ReplayDiff` 与 `Replayer`。

use super::*;

/// 回放配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// 默认回放条数上限。
    pub limit: i64,
    /// 是否把成功回放的原始日志标记为已解析。
    pub mark_parsed: bool,
    /// 是否把新事件投递总线。
    pub emit_to_bus: bool,
    /// 租户（多租户隔离；默认租户用于单机部署）。
    pub tenant: TenantId,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self { limit: 1_000, mark_parsed: true, emit_to_bus: false, tenant: TenantId::default_tenant() }
    }
}

/// 单字段差分。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldDiff {
    /// 字段路径（AGF-ECS）。
    pub path: String,
    /// 回放前（`None` = 原事件无该字段）。
    pub before: Option<Value>,
    /// 回放后（`None` = 新事件无该字段）。
    pub after: Option<Value>,
}

/// 单条原始日志的回放差分。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDiff {
    /// 原始日志 id。
    pub raw_id: Id,
    /// 本次使用的解析器 key。
    pub parser_key: Option<String>,
    /// 既有事件 id（此前未解析成功时为 `None`）。
    pub previous_event: Option<Id>,
    /// 新事件 id。
    pub new_event: Option<Id>,
    /// 字段差分（空 = 归一化结果一致）。
    pub changes: Vec<FieldDiff>,
}

/// 回放失败记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayFailure {
    /// 原始日志 id。
    pub raw_id: Id,
    /// 失败原因。
    pub reason: String,
}

/// 回放报告。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayReport {
    /// 检查的原始日志条数。
    pub replayed: usize,
    /// 本次成功解析并落库的新事件数。
    pub newly_parsed: usize,
    /// 仍无法解析的条数。
    pub failed: usize,
    /// 解析器使用次数统计。
    pub parser_used: BTreeMap<String, usize>,
    /// 差分明细（仅记录有变化的条目）。
    pub diffs: Vec<ReplayDiff>,
    /// 失败明细。
    pub failures: Vec<ReplayFailure>,
    /// 耗时（微秒）。
    pub elapsed_micros: u64,
}

impl ReplayReport {
    /// 是否完全没有产生新解析结果。
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.newly_parsed == 0
    }
}

/// 回放器。
#[derive(Debug)]
pub struct Replayer {
    sink: Arc<dyn Sink>,
    registry: Arc<Mutex<ParserRegistry>>,
    bus: Option<Arc<dyn EventBus>>,
    config: ReplayConfig,
    parser_key: Option<String>,
}

impl Replayer {
    /// 构造（可带总线）。
    #[must_use]
    pub fn new(
        sink: Arc<dyn Sink>,
        registry: Arc<Mutex<ParserRegistry>>,
        bus: Option<Arc<dyn EventBus>>,
        config: ReplayConfig,
    ) -> Self {
        Self { sink, registry, bus, config, parser_key: None }
    }

    /// 构造（不投递总线）。
    #[must_use]
    pub fn plain(sink: Arc<dyn Sink>, registry: Arc<Mutex<ParserRegistry>>, config: ReplayConfig) -> Self {
        Self::new(sink, registry, None, config)
    }

    /// Bind replay to the configured source parser, matching live ingestion.
    #[must_use]
    pub fn with_parser_key(mut self, key: Option<String>) -> Self {
        self.parser_key = key;
        self
    }

    /// 执行回放。
    ///
    /// `limit <= 0` 时使用配置里的上限。
    ///
    /// # Errors
    /// 原始日志读取失败或事件写入失败。
    pub async fn replay(&self, limit: i64) -> DomainResult<ReplayReport> {
        let start = Instant::now();
        let effective = if limit > 0 { limit } else { self.config.limit };
        let raws = self.sink.unparsed_raw(self.config.tenant, effective).await?;
        let mut report = ReplayReport { replayed: raws.len(), ..ReplayReport::default() };

        for raw in raws {
            let text = match decode_payload(&raw) {
                Ok(text) => text,
                Err(e) => {
                    report.failed += 1;
                    report.failures.push(ReplayFailure { raw_id: raw.id, reason: e.to_string() });
                    continue;
                }
            };
            let outcome = {
                let mut registry =
                    self.registry.lock().map_err(|e| DomainError::Internal(format!("注册表锁中毒: {e}")))?;
                registry.match_raw(&text, raw.protocol, None, self.parser_key.as_deref())
            };
            if !outcome.matched {
                report.failed += 1;
                report.failures.push(ReplayFailure {
                    raw_id: raw.id,
                    reason: outcome.error.unwrap_or_else(|| "重新解析仍未命中模板".to_string()),
                });
                continue;
            }
            let parser_key = outcome.parser_key.clone();
            let meta = SourceMeta {
                tenant_id: raw.tenant_id,
                source_id: raw.source_id,
                source_name: format!("replay:{}", raw.origin),
                vendor: String::new(),
                product: String::new(),
                protocol: raw.protocol,
                tags: vec!["replayed".to_string()],
                ingested_at: raw.received_at,
            };
            let mut event = normalize::normalize(&outcome, &meta, &text, &raw.origin);
            event.id = Id::new();
            let new_id = event.id;

            let previous = match raw.event_id {
                Some(id) => self.sink.get_event(self.config.tenant, id).await?,
                None => None,
            };
            let changes = previous.as_ref().map(|prev| diff_events(prev, &event)).unwrap_or_default();

            self.sink.put_event(&event).await?;
            if self.config.mark_parsed {
                self.sink.mark_raw(raw.tenant_id, raw.id, true, Some(new_id), None).await?;
            }
            if self.config.emit_to_bus {
                if let Some(bus) = &self.bus {
                    if let Err(e) = bus.publish(&event).await {
                        tracing::warn!(error = %e, raw_id = %raw.id, "回放事件投递总线失败");
                    }
                }
            }

            report.newly_parsed += 1;
            if let Some(key) = &parser_key {
                *report.parser_used.entry(key.clone()).or_insert(0) += 1;
            }
            if !changes.is_empty() || previous.is_some() {
                report.diffs.push(ReplayDiff {
                    raw_id: raw.id,
                    parser_key,
                    previous_event: raw.event_id,
                    new_event: Some(new_id),
                    changes,
                });
            }
        }

        report.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        Ok(report)
    }
}

//! 冷归档装配段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
//!
//! 只做**启动自检**：真写一个探针对象再读回来（证明本构建里写读都能跑通），失败只 warn。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// === Parquet ===（启动自检：真写一个探针对象再读回来）
    pub(super) async fn coldarchive_selfcheck(&mut self) {
        let listeners = &mut *self.listeners;
        // 冷归档格式由 `AGF_ARCHIVE_FORMAT=parquet|ndjson-gzip|ndjson` 选定（**默认 parquet**），
        // 落盘/读取实现全在 `agf_ingest::coldarchive`：
        //   * Parquet 走低层列式 API（`parquet` crate **不开 arrow 特性**），SNAPPY 压缩，
        //     列 = time / ingested_at / tenant_id / source_id / source_name / protocol / vendor /
        //     product / host / severity / message / raw_hash / raw_json（由 `Event` 既有字段派生）；
        //   * Parquet 编码失败**自动回落 gzip NDJSON 并 warn**（对象键后缀与 content_type 跟随实际格式）。
        // 本段落做**启动自检**：真写一个探针对象再读回来（证明本构建里写读都能跑通），
        // 失败只 warn（归档格式问题绝不能让接入服务起不来）。
        {
            let requested = agf_ingest::coldarchive::ColdFormat::from_env();
            let config = agf_ingest::coldarchive::ColdArchiveConfig {
                prefix: env_or("AGF_ARCHIVE_PREFIX", "agf-events"),
                hot_days: env_num("AGF_ARCHIVE_HOT_DAYS", 30_u32).max(1),
                cold_days: env_num("AGF_ARCHIVE_COLD_DAYS", 365_u32).max(1),
                format: requested,
                max_batch: env_num("AGF_ARCHIVE_MAX_BATCH", 10_000_usize).max(1),
            };
            let plan = agf_ingest::coldarchive::retention_plan(config.hot_days, config.cold_days);
            let archiver = agf_ingest::coldarchive::ColdArchiver::new(
                Arc::new(agf_storage::objectstore::MemoryObjectStore::new()),
                config.clone(),
            );
            let mut probe = agf_core::event::Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Webhook);
            probe.message = "cold-archive startup self-check".to_string();
            probe.severity = agf_core::enums::Severity::Info;
            probe.source_name = "agf-ingest-selfcheck".to_string();
            probe.raw_hash = agf_core::secret::content_hash(&probe.message);
            match archiver.archive_batch(&[probe]).await {
                Ok(stored) => match archiver.read_batch(&stored.key).await {
                    Ok(restored) => {
                        let effective = if stored.key.ends_with(".parquet") { "parquet" } else { "ndjson-gzip" };
                        if requested == agf_ingest::coldarchive::ColdFormat::Parquet && effective != "parquet" {
                            tracing::warn!(
                                requested = requested.as_str(),
                                effective,
                                "冷归档启动自检：Parquet 不可用，已回落 gzip NDJSON（数据不丢，仅格式降级）"
                            );
                        }
                        tracing::info!(
                            requested = requested.as_str(),
                            effective,
                            key = %stored.key,
                            rows = restored.len(),
                            columns = ?agf_ingest::coldarchive::PARQUET_COLUMNS,
                            hot_days = plan.hot_days,
                            cold_days = plan.cold_days,
                            "冷归档启动自检通过（写 → 读往返）；指标 agf_ingest_coldarchive_bytes_total / _objects_total / _fallbacks_total"
                        );
                        listeners.note(format!(
                            "冷归档：请求格式 {}，实际 {}（键 {}，自检往返 {} 行）；Parquet 失败自动回落 gzip 并 warn；保留 热 {}d / 冷 {}d",
                            requested.as_str(),
                            effective,
                            stored.key,
                            restored.len(),
                            plan.hot_days,
                            plan.cold_days
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "冷归档启动自检：对象写入成功但读回失败（归档读取路径有问题）");
                        listeners.note(format!("冷归档启动自检读回失败：{e}"));
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "冷归档启动自检失败（格式 {}）；接入服务照常启动", requested.as_str());
                    listeners.note(format!("冷归档启动自检失败：{e}"));
                }
            }
        }
    }
}

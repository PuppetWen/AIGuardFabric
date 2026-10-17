//! 归档落地入口：`ColdArchiver`、批量编码（含 Parquet 失败回落 gzip）与 gzip 工具。

use super::*;

/// 冷存储归档器。
#[derive(Debug)]
pub struct ColdArchiver {
    store: Arc<dyn agf_storage::ObjectStore>,
    config: ColdArchiveConfig,
}

impl ColdArchiver {
    /// 构造。
    #[must_use]
    pub fn new(store: Arc<dyn agf_storage::ObjectStore>, config: ColdArchiveConfig) -> Self {
        Self { store, config }
    }

    /// 保留策略（关联函数形式，便于 UI 直接调用）。
    #[must_use]
    pub fn retention_plan(hot_days: u32, cold_days: u32) -> RetentionPlan {
        retention_plan(hot_days, cold_days)
    }

    /// 当前配置。
    #[must_use]
    pub const fn config(&self) -> &ColdArchiveConfig {
        &self.config
    }

    /// 底层对象存储（回灌列举/取证直接用；归档器外不再暴露其它内部状态）。
    #[must_use]
    pub fn store(&self) -> &Arc<dyn agf_storage::ObjectStore> {
        &self.store
    }

    /// 生成按天/小时分区的对象键（用**配置里声明的**格式后缀）。
    #[must_use]
    pub fn archive_key(&self, at: &Timestamp, seq: u32) -> String {
        self.archive_key_for(at, seq, self.config.format)
    }

    /// 生成按天/小时分区的对象键（用**实际落地的**格式后缀：回落时不名不符实）。
    #[must_use]
    pub fn archive_key_for(&self, at: &Timestamp, seq: u32, format: ColdFormat) -> String {
        use chrono::Timelike;
        let dt = at.as_datetime();
        let date = dt.format("%Y-%m-%d").to_string();
        let hour = dt.hour();
        let unique = agf_core::ids::Id::new();
        format!("{}/dt={date}/hour={hour:02}/events-{unique}-{seq:05}.{}", self.config.prefix, format.extension())
    }

    /// 归档一批事件，返回对象元数据。
    ///
    /// Parquet 编码失败时**自动回落** gzip NDJSON（warn + 指标计数），绝不因格式问题丢归档。
    ///
    /// # Errors
    /// 空批次、批超限、序列化失败或对象存储写入失败。
    pub async fn archive_batch(&self, events: &[Event]) -> DomainResult<agf_storage::StoredObject> {
        if events.is_empty() {
            return Err(DomainError::Validation("归档批次为空".to_string()));
        }
        if events.len() > self.config.max_batch {
            return Err(DomainError::Validation(format!(
                "归档批次数 {} 超过上限 {}，请切批",
                events.len(),
                self.config.max_batch
            )));
        }
        let outcome = encode_batch_with_fallback(events, self.config.format)?;
        let newest = events.iter().map(|e| e.time).max().unwrap_or_else(Timestamp::now);
        let key = self.archive_key_for(&newest, u32::try_from(events.len()).unwrap_or(0), outcome.format);
        let stored = self.store.put(&key, &outcome.bytes, Some(outcome.format.content_type())).await?;
        archive_metrics().record(outcome.format, outcome.bytes.len(), events.len());
        Ok(stored)
    }

    /// 读取归档对象并还原事件列表（回灌/取证用）。
    ///
    /// 格式按**内容魔数**判定（回落生成的对象也能原样读回），判定失败才退回配置格式。
    ///
    /// # Errors
    /// 对象不存在、解压失败、Parquet 非法或 NDJSON 非法。
    pub async fn read_batch(&self, key: &str) -> DomainResult<Vec<Event>> {
        Ok(self.read_batch_detailed(key).await?.events)
    }

    /// 读取归档对象并**连读回事实一起**返回（回灌用：证明这批事件走的是 arrow 列式读回）。
    ///
    /// Parquet 对象走 arrow `RecordBatchReader`（[`read_parquet_arrow`]）并附
    /// [`ParquetFacts`]（文件级）+ [`ArrowFacts`]（列级）；gzip/NDJSON 对象没有列式事实。
    ///
    /// # Errors
    /// 对象不存在、解压失败、Parquet 非法或 NDJSON 非法。
    pub async fn read_batch_detailed(&self, key: &str) -> DomainResult<ArchivedBatch> {
        let bytes = self.store.get(key).await?;
        let format = ColdFormat::sniff(&bytes).unwrap_or(self.config.format);
        let (events, parquet, arrow) = match format {
            ColdFormat::Parquet => {
                let readback = read_parquet_arrow(&bytes, 1024, 0)?;
                (readback.events, parquet_facts(&bytes).ok(), Some(readback.facts))
            }
            other => (decode_batch(&bytes, other)?, None, None),
        };
        Ok(ArchivedBatch { key: key.to_string(), format, bytes: bytes.len(), events, parquet, arrow })
    }

    /// 列出某一天的归档对象。
    ///
    /// # Errors
    /// 列举失败。
    pub async fn list_day(&self, date: &str, limit: usize) -> DomainResult<Vec<String>> {
        let prefix = format!("{}/dt={date}/", self.config.prefix);
        self.store.list(&prefix, limit).await
    }

    /// 后端名（`memory` / `local` / `s3`）。
    #[must_use]
    pub fn backend(&self) -> &'static str {
        self.store.backend()
    }
}

/// 一次归档读取的**完整事实**（事件 + 实际格式 + 文件级/列级读回证据）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedBatch {
    /// 对象键。
    pub key: String,
    /// 实际生效的格式（按内容魔数判定）。
    pub format: ColdFormat,
    /// 对象字节数。
    pub bytes: usize,
    /// 还原出的事件。
    pub events: Vec<Event>,
    /// 文件级事实（仅 Parquet 对象；`parquet_facts` 失败时为 `None`）。
    pub parquet: Option<ParquetFacts>,
    /// 列级 arrow 事实（仅 Parquet 对象）。
    pub arrow: Option<ArrowFacts>,
}

impl ArchivedBatch {
    /// 归档文件里的行数（Parquet 取 arrow 行数；其它格式取事件数）。
    #[must_use]
    pub fn rows(&self) -> usize {
        if let Some(facts) = self.arrow.as_ref() {
            return facts.rows;
        }
        if let Some(facts) = self.parquet.as_ref() {
            return usize::try_from(facts.rows.max(0)).unwrap_or(self.events.len());
        }
        self.events.len()
    }

    /// 是否走了 arrow 列式读回。
    #[must_use]
    pub const fn via_arrow(&self) -> bool {
        self.arrow.is_some()
    }
}

/// 编码结果（含**实际生效**的格式与回落原因）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodeOutcome {
    /// 编码后的字节。
    pub bytes: Vec<u8>,
    /// 实际生效的格式。
    pub format: ColdFormat,
    /// 回落原因（`None` = 未回落）。
    pub fallback_reason: Option<String>,
}

/// 把事件编码为 NDJSON（可选 gzip）。
///
/// # Errors
/// JSON 序列化失败或 gzip 失败。
pub fn encode_batch(events: &[Event], format: ColdFormat) -> DomainResult<Vec<u8>> {
    let mut plain = Vec::new();
    for event in events {
        let line = serde_json::to_vec(event).map_err(|e| DomainError::Internal(format!("事件序列化失败: {e}")))?;
        plain.extend_from_slice(&line);
        plain.push(b'\n');
    }
    match format {
        ColdFormat::Ndjson => Ok(plain),
        ColdFormat::NdjsonGzip => gzip(&plain),
        ColdFormat::Parquet => encode_parquet(events),
    }
}

/// 编码并**在 Parquet 失败时自动回落 gzip NDJSON**（归档主路径）。
///
/// 回落是"降级但不丢数据"：warn + 指标计数 + 返回实际格式，由调用方切换对象键后缀。
///
/// # Errors
/// 请求格式即 gzip/NDJSON 却编码失败（gzip 本身失败），或回落路径也失败。
pub fn encode_batch_with_fallback(events: &[Event], requested: ColdFormat) -> DomainResult<EncodeOutcome> {
    encode_batch_with(events, requested, &encode_parquet)
}

/// 同 [`encode_batch_with_fallback`]，但 Parquet 编码器可注入（**单测用它证明回落路径**）。
///
/// # Errors
/// 同 [`encode_batch_with_fallback`]。
pub fn encode_batch_with(
    events: &[Event],
    requested: ColdFormat,
    parquet_encoder: &dyn Fn(&[Event]) -> DomainResult<Vec<u8>>,
) -> DomainResult<EncodeOutcome> {
    match requested {
        ColdFormat::Parquet => match parquet_encoder(events) {
            Ok(bytes) => Ok(EncodeOutcome { bytes, format: ColdFormat::Parquet, fallback_reason: None }),
            Err(error) => {
                archive_metrics().record_fallback();
                warn!(error = %error, "Parquet 归档编码失败，自动回落 gzip NDJSON（数据不丢，仅格式降级）");
                let bytes = encode_batch(events, ColdFormat::NdjsonGzip)?;
                Ok(EncodeOutcome { bytes, format: ColdFormat::NdjsonGzip, fallback_reason: Some(error.to_string()) })
            }
        },
        other => Ok(EncodeOutcome { bytes: encode_batch(events, other)?, format: other, fallback_reason: None }),
    }
}

/// 解码归档内容为事件列表。
///
/// # Errors
/// gzip 解压失败、Parquet 非法或 NDJSON 行非法。
pub fn decode_batch(bytes: &[u8], format: ColdFormat) -> DomainResult<Vec<Event>> {
    if format == ColdFormat::Parquet {
        return decode_parquet(bytes);
    }
    let plain = match format {
        ColdFormat::Ndjson => bytes.to_vec(),
        ColdFormat::NdjsonGzip | ColdFormat::Parquet => gunzip(bytes)?,
    };
    let text = String::from_utf8(plain).map_err(|e| DomainError::Parse(format!("归档内容非 UTF-8: {e}")))?;
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(line)
            .map_err(|e| DomainError::Parse(format!("归档第 {} 行解析失败: {e}", idx + 1)))?;
        out.push(event);
    }
    Ok(out)
}

/// gzip 压缩。
///
/// # Errors
/// 压缩器写入失败。
pub fn gzip(data: &[u8]) -> DomainResult<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(|e| DomainError::Internal(format!("gzip 压缩失败: {e}")))?;
    encoder.finish().map_err(|e| DomainError::Internal(format!("gzip 收尾失败: {e}")))
}

/// gzip 解压。
///
/// # Errors
/// 解压失败（数据损坏或非 gzip）。
pub fn gunzip(data: &[u8]) -> DomainResult<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out)
        .map_err(|e| DomainError::Parse(format!("gzip 解压失败: {e}")))?;
    Ok(out)
}

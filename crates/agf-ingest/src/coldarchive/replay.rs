//! 冷归档**回灌**：把归档对象解回事件，按**时间/租户过滤**后写回既有 [`Sink`]，并以
//! `raw_hash` 账本保证**幂等**（同一批回灌两次，第二次入库 0 条）。
//!
//! ## 回灌到哪去（为什么直接写 Sink 而不是重新过解析器）
//!
//! 归档里存的是**已归一化的事件**（保真列 `raw_json` 即整条 `Event`）。
//! 回灌若把 `raw_json` 当"原始报文"再喂一遍解析流水线，会**二次归一化**：
//! `id`/`time` 变、模板变更后语义漂移、脱敏再叠一层——这是"回灌"最容易出的错。
//! 因此回灌走**与流水线同一个 [`Sink`] 实例**（生产即 `SqlSink`，测试即 `InMemorySink`），
//! 语义是"把归档的事件原样重新入库"，而不是"把它当新日志重新解析"。
//!
//! ## 幂等（`raw_hash` 账本）
//!
//! [`ReplayLedger`] 记录**已回灌过**的 `raw_hash`：
//! * 第 1 次回灌：命中过滤 ⇒ 入账 ⇒ 写 sink；
//! * 第 2 次回灌同一对象：账本命中 ⇒ `duplicates += 1`，**不写 sink**（`replayed` 为 0）。
//!
//! 账本可落盘（`AGF_ARCHIVE_REPLAY_STATE`，JSON），因此幂等**跨进程**成立；
//! 未配置路径时退化为进程内账本（进程重启后重复回灌会重新入库——文档如实标注，不假装持久）。
//! 事件 `raw_hash` 为空时用**整条事件 JSON 的内容哈希**兜底（确定性，仍幂等），并计入
//! [`ReplayReport::hash_fallbacks`]。
//!
//! ## 过滤
//!
//! [`ReplayFilter`] 支持时间窗（`from` 含、`to` 含）与租户；`from_env` 读
//! `AGF_ARCHIVE_REPLAY_FROM` / `_TO`（RFC3339，或 `YYYY-MM-DD`——日期形式下 `to` 取当天**结束**）
//! 与 `AGF_ARCHIVE_REPLAY_TENANT`。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agf_core::ids::TenantId;
use agf_core::secret::content_hash;

use super::*;
use crate::pipeline::Sink;

/// 回灌过滤器（时间窗 + 租户；全部为空 = 全量回灌）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayFilter {
    /// 起始时间（**含**）。
    pub from: Option<Timestamp>,
    /// 结束时间（**含**；`YYYY-MM-DD` 形式取当天 23:59:59.999）。
    pub to: Option<Timestamp>,
    /// 仅回灌该租户。
    pub tenant: Option<TenantId>,
}

impl ReplayFilter {
    /// 全量（不过滤）。
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// 单租户。
    #[must_use]
    pub fn for_tenant(tenant: TenantId) -> Self {
        Self { tenant: Some(tenant), ..Self::default() }
    }

    /// 时间窗 + 租户。
    #[must_use]
    pub fn window(from: Timestamp, to: Timestamp, tenant: Option<TenantId>) -> Self {
        Self { from: Some(from), to: Some(to), tenant }
    }

    /// 是否命中（未设置的维度不参与过滤）。
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(from) = self.from {
            if !event.time.is_at_or_after(&from) {
                return false;
            }
        }
        if let Some(to) = self.to {
            if event.time.unix_millis() > to.unix_millis() {
                return false;
            }
        }
        if let Some(tenant) = self.tenant {
            if event.tenant_id != tenant {
                return false;
            }
        }
        true
    }

    /// 人读描述（写进回灌报告与日志，便于对账）。
    #[must_use]
    pub fn describe(&self) -> String {
        let window = match (self.from, self.to) {
            (Some(from), Some(to)) => format!("{} ~ {}", from.to_rfc3339(), to.to_rfc3339()),
            (Some(from), None) => format!(">= {}", from.to_rfc3339()),
            (None, Some(to)) => format!("<= {}", to.to_rfc3339()),
            (None, None) => "全时段".to_string(),
        };
        match self.tenant {
            Some(tenant) => format!("{window}；租户 {tenant}"),
            None => format!("{window}；全部租户"),
        }
    }

    /// 解析时间文本：优先 RFC3339；`YYYY-MM-DD` 形式按日期处理（`end_of_day` 决定取当天起点还是终点）。
    ///
    /// # Errors
    /// 两种格式都不匹配。
    pub fn parse_time(text: &str, end_of_day: bool) -> DomainResult<Timestamp> {
        let trimmed = text.trim();
        if let Ok(ts) = Timestamp::parse_rfc3339(trimmed) {
            return Ok(ts);
        }
        let date = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
            .map_err(|e| DomainError::Validation(format!("时间 {trimmed:?} 既不是 RFC3339 也不是 YYYY-MM-DD: {e}")))?;
        let naive =
            if end_of_day { date.and_hms_milli_opt(23, 59, 59, 999) } else { date.and_hms_milli_opt(0, 0, 0, 0) }
                .ok_or_else(|| DomainError::Validation(format!("日期 {trimmed:?} 无法构造时刻")))?;
        Timestamp::parse_rfc3339(&format!("{}Z", naive.format("%Y-%m-%dT%H:%M:%S%.3f")))
            .map_err(|e| DomainError::Validation(format!("日期 {trimmed:?} 转时间戳失败: {e}")))
    }

    /// 由 env 构造（`AGF_ARCHIVE_REPLAY_FROM` / `_TO` / `_TENANT`；未配置即全量）。
    ///
    /// # Errors
    /// 时间或租户文本非法（**显式报错**，不静默变成"全量回灌"）。
    pub fn from_env() -> DomainResult<Self> {
        let read = |key: &str| std::env::var(key).ok().filter(|value| !value.trim().is_empty());
        let from = read("AGF_ARCHIVE_REPLAY_FROM").map(|text| Self::parse_time(&text, false)).transpose()?;
        let to = read("AGF_ARCHIVE_REPLAY_TO").map(|text| Self::parse_time(&text, true)).transpose()?;
        let tenant = read("AGF_ARCHIVE_REPLAY_TENANT")
            .map(|text| {
                TenantId::parse(text.trim())
                    .map_err(|e| DomainError::Validation(format!("AGF_ARCHIVE_REPLAY_TENANT 非法: {e}")))
            })
            .transpose()?;
        Ok(Self { from, to, tenant })
    }
}

/// 幂等账本文件（JSON；版本化以便将来换存储）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerFile {
    version: u32,
    raw_hashes: Vec<String>,
}

/// 回灌幂等账本（`raw_hash` 集合；可落盘 ⇒ 幂等跨进程成立）。
#[derive(Debug, Clone)]
pub struct ReplayLedger {
    path: Option<PathBuf>,
    seen: BTreeSet<String>,
    loaded: usize,
    added: usize,
}

impl ReplayLedger {
    /// 进程内账本（不落盘；重启后不保证幂等——文档如实标注）。
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, seen: BTreeSet::new(), loaded: 0, added: 0 }
    }

    /// 打开/新建落盘账本（文件不存在 = 空账本，**不是错误**）。
    ///
    /// # Errors
    /// 文件存在但不是合法 JSON，或读取失败。
    pub fn open(path: impl AsRef<Path>) -> DomainResult<Self> {
        let path = path.as_ref().to_path_buf();
        let seen = match std::fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => BTreeSet::new(),
            Ok(bytes) => {
                let parsed: LedgerFile = serde_json::from_slice(&bytes)
                    .map_err(|e| DomainError::Validation(format!("回灌账本 {} 解析失败: {e}", path.display())))?;
                parsed.raw_hashes.into_iter().collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(e) => return Err(DomainError::Validation(format!("回灌账本 {} 读取失败: {e}", path.display()))),
        };
        let loaded = seen.len();
        Ok(Self { path: Some(path), seen, loaded, added: 0 })
    }

    /// 由 env（`AGF_ARCHIVE_REPLAY_STATE`）构造；未配置 ⇒ 进程内账本。
    ///
    /// # Errors
    /// 账本文件读取/解析失败。
    pub fn from_env() -> DomainResult<Self> {
        match std::env::var("AGF_ARCHIVE_REPLAY_STATE") {
            Ok(path) if !path.trim().is_empty() => Self::open(path.trim()),
            _ => Ok(Self::in_memory()),
        }
    }

    /// 是否已回灌过该 `raw_hash`。
    #[must_use]
    pub fn contains(&self, raw_hash: &str) -> bool {
        self.seen.contains(raw_hash)
    }

    /// 记账：返回 `true` = **首次出现**（应回灌），`false` = 已存在（重复，跳过）。
    pub fn record(&mut self, raw_hash: &str) -> bool {
        if self.seen.insert(raw_hash.to_string()) {
            self.added = self.added.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// 账本条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// 载入时已有条目数 / 本次新增条目数。
    #[must_use]
    pub const fn counts(&self) -> (usize, usize) {
        (self.loaded, self.added)
    }

    /// 账本路径（`None` = 进程内）。
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// 落盘（**原子**：先写 `.tmp` 再 rename；父目录自动创建）。进程内账本 ⇒ 空操作。
    ///
    /// # Errors
    /// 目录创建/写入/改名失败。
    pub fn save(&self) -> DomainResult<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| DomainError::Validation(format!("回灌账本目录 {} 创建失败: {e}", parent.display())))?;
        }
        let payload = LedgerFile { version: 1, raw_hashes: self.seen.iter().cloned().collect() };
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| DomainError::Internal(format!("回灌账本序列化失败: {e}")))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| DomainError::Validation(format!("回灌账本临时文件 {} 写入失败: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| DomainError::Validation(format!("回灌账本 {} 落盘失败: {e}", path.display())))?;
        Ok(())
    }
}

impl Default for ReplayLedger {
    fn default() -> Self {
        Self::in_memory()
    }
}

/// 单个对象的回灌失败（**不静默丢弃**：键 + 原因都留在报告里）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFailure {
    /// 对象键。
    pub key: String,
    /// 失败原因。
    pub reason: String,
}

/// 回灌报告（对账用：扫描/解码/过滤/重复/入库逐项计数）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayReport {
    /// 处理的对象数（含失败对象）。
    pub objects: usize,
    /// 其中走 **arrow 列式读回** 的 Parquet 对象数。
    pub arrow_objects: usize,
    /// 归档文件里的行数合计（Parquet 用 arrow `RecordBatch` 行数）。
    pub rows: usize,
    /// 解码出的事件数。
    pub decoded: usize,
    /// 被过滤器排除的事件数。
    pub filtered: usize,
    /// 命中账本（重复）而跳过的事件数。
    pub duplicates: usize,
    /// 真正写入 sink 的事件数（**sink 实际接收**的条数）。
    pub replayed: usize,
    /// 交给 sink 但被 **sink 自身**判重跳过的事件数（如 `InMemorySink` 按事件 id 幂等）。
    /// 单列出来的理由：否则"账本放行 N 条、`replayed` 却小于 N"会看起来像丢数据。
    pub sink_skipped: usize,
    /// `raw_hash` 为空、用事件 JSON 内容哈希兜底的事件数。
    pub hash_fallbacks: usize,
    /// 失败对象（键 + 原因）。
    pub failures: Vec<ReplayFailure>,
}

impl ReplayReport {
    /// 合并另一份报告（多对象/多来源汇总）。
    pub fn merge(&mut self, other: &Self) {
        self.objects = self.objects.saturating_add(other.objects);
        self.arrow_objects = self.arrow_objects.saturating_add(other.arrow_objects);
        self.rows = self.rows.saturating_add(other.rows);
        self.decoded = self.decoded.saturating_add(other.decoded);
        self.filtered = self.filtered.saturating_add(other.filtered);
        self.duplicates = self.duplicates.saturating_add(other.duplicates);
        self.replayed = self.replayed.saturating_add(other.replayed);
        self.sink_skipped = self.sink_skipped.saturating_add(other.sink_skipped);
        self.hash_fallbacks = self.hash_fallbacks.saturating_add(other.hash_fallbacks);
        self.failures.extend(other.failures.iter().cloned());
    }

    /// 人读摘要（证据/日志用）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "回灌：对象 {}（其中 arrow 列式读回 {}），归档行 {}，解码 {}，过滤 {}，重复跳过 {}，入库 {}（sink 判重跳过 {}），\
             哈希兜底 {}，失败对象 {}{}",
            self.objects,
            self.arrow_objects,
            self.rows,
            self.decoded,
            self.filtered,
            self.duplicates,
            self.replayed,
            self.sink_skipped,
            self.hash_fallbacks,
            self.failures.len(),
            if self.failures.is_empty() {
                String::new()
            } else {
                format!(
                    "（{}）",
                    self.failures
                        .iter()
                        .map(|failure| format!("{}: {}", failure.key, failure.reason))
                        .collect::<Vec<_>>()
                        .join("；")
                )
            }
        )
    }

    /// JSON（CLI/接口输出）。
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\":\"回灌报告序列化失败: {e}\"}}"))
    }
}

/// 冷归档回灌器：归档读取（[`ColdArchiver`]）+ 既有落库目标（[`Sink`]）。
#[derive(Debug)]
pub struct ColdReplayer {
    archiver: ColdArchiver,
    sink: Arc<dyn Sink>,
}

impl ColdReplayer {
    /// 构造。
    #[must_use]
    pub fn new(archiver: ColdArchiver, sink: Arc<dyn Sink>) -> Self {
        Self { archiver, sink }
    }

    /// 归档器。
    #[must_use]
    pub const fn archiver(&self) -> &ColdArchiver {
        &self.archiver
    }

    /// 落库后端名（`memory` / `sql`）。
    #[must_use]
    pub fn sink_backend(&self) -> &'static str {
        self.sink.backend()
    }

    /// 回灌一个对象。
    ///
    /// # Errors
    /// 对象不存在或读取失败（解码失败记进报告，不中断整批）。
    pub async fn replay_key(
        &self,
        key: &str,
        filter: &ReplayFilter,
        ledger: &mut ReplayLedger,
    ) -> DomainResult<ReplayReport> {
        let mut report = ReplayReport { objects: 1, ..ReplayReport::default() };
        let batch = match self.archiver.read_batch_detailed(key).await {
            Ok(batch) => batch,
            Err(e) => {
                report.failures.push(ReplayFailure { key: key.to_string(), reason: e.to_string() });
                return Ok(report);
            }
        };
        report.arrow_objects = usize::from(batch.arrow.is_some());
        report.rows = batch.rows();
        report.decoded = batch.events.len();

        let mut pending: Vec<Event> = Vec::new();
        for event in &batch.events {
            if !filter.matches(event) {
                report.filtered = report.filtered.saturating_add(1);
                continue;
            }
            let (hash, fallback) = dedup_key(event);
            if fallback {
                report.hash_fallbacks = report.hash_fallbacks.saturating_add(1);
            }
            if !ledger.record(&hash) {
                report.duplicates = report.duplicates.saturating_add(1);
                continue;
            }
            pending.push(event.clone());
        }
        if !pending.is_empty() {
            let handed = pending.len();
            let accepted = self.sink.put_events(&pending).await?;
            report.replayed = accepted;
            report.sink_skipped = handed.saturating_sub(accepted);
            archive_metrics().record_replay(batch.format, accepted, report.duplicates, report.filtered);
        }
        Ok(report)
    }

    /// 回灌多个对象（逐个处理；单个对象失败只进 `failures`，不中断其余）。
    ///
    /// # Errors
    /// 落库失败（sink 不可写）。读取/解码失败记进报告。
    pub async fn replay_keys(
        &self,
        keys: &[String],
        filter: &ReplayFilter,
        ledger: &mut ReplayLedger,
    ) -> DomainResult<ReplayReport> {
        let mut total = ReplayReport::default();
        for key in keys {
            total.merge(&self.replay_key(key, filter, ledger).await?);
        }
        Ok(total)
    }

    /// 回灌某一天（对象键前缀 `prefix/dt=<date>/`）的全部归档对象。
    ///
    /// # Errors
    /// 列举失败或落库失败。
    pub async fn replay_day(
        &self,
        date: &str,
        limit: usize,
        filter: &ReplayFilter,
        ledger: &mut ReplayLedger,
    ) -> DomainResult<ReplayReport> {
        let keys = self.archiver.list_day(date, limit).await?;
        self.replay_keys(&keys, filter, ledger).await
    }

    /// 回灌**整个前缀**下的归档对象（跨天；`prefix` 缺省用归档配置里的前缀）。
    ///
    /// # Errors
    /// 列举失败或落库失败。
    pub async fn replay_prefix(
        &self,
        prefix: &str,
        limit: usize,
        filter: &ReplayFilter,
        ledger: &mut ReplayLedger,
    ) -> DomainResult<ReplayReport> {
        let prefix = if prefix.is_empty() { self.archiver.config().prefix.as_str() } else { prefix };
        let keys = self.archiver.store().list(&format!("{}/", prefix.trim_end_matches('/')), limit).await?;
        self.replay_keys(&keys, filter, ledger).await
    }
}

/// 幂等键：优先 `raw_hash`；为空则用整条事件 JSON 的内容哈希（确定性），第二个返回值表示是否兜底。
#[must_use]
pub fn dedup_key(event: &Event) -> (String, bool) {
    if !event.raw_hash.trim().is_empty() {
        return (event.raw_hash.clone(), false);
    }
    let canonical = serde_json::to_string(event).unwrap_or_else(|_| event.message.clone());
    (content_hash(&canonical), true)
}

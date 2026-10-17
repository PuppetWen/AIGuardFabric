//! 接收器统一指标：**收到 / 解析命中 / 解析失败 / 丢弃**（§4.5「可观测」）。
//!
//! ## 为什么单独立一层
//!
//! 每个协议接收器（OTLP / 对象拉取 / JDBC / MQTT / SNMP / Kafka …）都自带"协议层"行为：
//! 分帧、解码、列对象、消费 offset。这些行为**不进** [`crate::pipeline`] 的计数器，
//! 若不单独统计，"某协议到底收到了多少、丢了多少"在任何指标上都不可观测。
//!
//! 本模块给出**统一口径**（四个计数器），并由 [`MetricsRegistry`] 渲染成 Prometheus 文本：
//!
//! | 指标 | 语义 |
//! |---|---|
//! | `agf_ingest_receiver_received_total` | 接收到的**原始报文/对象/记录**数（含后续被丢弃的） |
//! | `agf_ingest_receiver_matched_total` | 命中解析模板（进入归一化事件）的条数 |
//! | `agf_ingest_receiver_parse_failed_total` | 已接入但**未命中任何模板**的条数（缺失就是缺失） |
//! | `agf_ingest_receiver_dropped_total` | 协议层**丢弃**数（解码失败 / 超限 / 未落库） |
//! | `agf_ingest_matched_by_total{mode=...}` | 命中**按匹配趟次**分解（`explicit` / `protocol` / `protocol-relaxed` / `sample-score` / `ai-inferred`），进程级 |
//!
//! `matched + parse_failed` 与 `received` 不必然相等：`received` 计的是协议层"收到"，
//! 而前两者计的是"走到解析层"的条数——两者都如实给出，不合并、不推算。
//!
//! ## 线程安全
//!
//! 计数器为原子量，可在多任务（UDP 循环 / 多个消费任务）间共享；登记表用 `Mutex` 保护
//! （只在极小临界区内做 map 查找，不与 `await` 交叉）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::pipeline::IngestOutcome;

/// 单个接收器的四类计数（进程内，重启归零；长期存储由 Prometheus 抓取承接）。
#[derive(Debug, Default)]
pub struct ReceiverCounters {
    received: AtomicU64,
    matched: AtomicU64,
    parse_failed: AtomicU64,
    dropped: AtomicU64,
}

/// 计数的只读快照（`/metrics` 与 `/stats` 共用）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverSnapshot {
    /// 协议层收到的条数。
    pub received: u64,
    /// 命中模板条数。
    pub matched: u64,
    /// 未命中模板条数。
    pub parse_failed: u64,
    /// 协议层丢弃条数。
    pub dropped: u64,
}

impl ReceiverCounters {
    /// 新建（全零）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 累加"收到"。
    pub fn add_received(&self, n: u64) {
        self.received.fetch_add(n, Ordering::Relaxed);
    }

    /// 累加"丢弃"。
    pub fn add_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// 按一批接入结果累加命中 / 未命中 / 未落库。
    ///
    /// **不**在这里累加 `received`：协议层"收到"通常大于"进入流水线"的条数
    /// （例如一个对象内含 100 行），混淆两者会让丢弃数失真，因此由调用方分别累加。
    pub fn record_outcomes(&self, outcomes: &[IngestOutcome]) {
        let matched = outcomes.iter().filter(|o| o.matched).count();
        let failed = outcomes.len().saturating_sub(matched);
        let dropped = outcomes.iter().filter(|o| !o.persisted).count();
        self.matched.fetch_add(u64::try_from(matched).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.parse_failed.fetch_add(u64::try_from(failed).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.dropped.fetch_add(u64::try_from(dropped).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// 快照。
    #[must_use]
    pub fn snapshot(&self) -> ReceiverSnapshot {
        ReceiverSnapshot {
            received: self.received.load(Ordering::Relaxed),
            matched: self.matched.load(Ordering::Relaxed),
            parse_failed: self.parse_failed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// 接收器指标登记表（按接收器名索引；名字即 Prometheus 的 `receiver` 标签）。
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    counters: Mutex<BTreeMap<String, Arc<ReceiverCounters>>>,
}

impl MetricsRegistry {
    /// 新建空登记表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 取（必要时创建）某接收器的计数器。
    ///
    /// 锁中毒时**降级返回一个游离计数器**而不是 panic：可用性优先，且 `/metrics`
    /// 仍能输出（该接收器的计数会失真，但进程不会因为指标而挂掉）。
    #[must_use]
    pub fn counters(&self, receiver: &str) -> Arc<ReceiverCounters> {
        match self.counters.lock() {
            Ok(mut map) => Arc::clone(map.entry(receiver.to_string()).or_default()),
            Err(poisoned) => {
                let mut map = poisoned.into_inner();
                Arc::clone(map.entry(receiver.to_string()).or_default())
            }
        }
    }

    /// 已登记的全部接收器快照（按名字排序，输出稳定）。
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<String, ReceiverSnapshot> {
        let map = match self.counters.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.iter().map(|(name, counters)| (name.clone(), counters.snapshot())).collect()
    }

    /// 渲染 Prometheus 文本（`text/plain; version=0.0.4`）。
    #[must_use]
    pub fn prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP agf_ingest_receiver_received_total 接收器协议层收到的原始条数（报文/对象/记录/行）\n\
             # TYPE agf_ingest_receiver_received_total counter\n",
        );
        let snapshot = self.snapshot();
        for (name, value) in &snapshot {
            out.push_str(&format!("agf_ingest_receiver_received_total{{receiver=\"{name}\"}} {}\n", value.received));
        }
        out.push_str(
            "# HELP agf_ingest_receiver_matched_total 接收器命中解析模板的条数\n\
             # TYPE agf_ingest_receiver_matched_total counter\n",
        );
        for (name, value) in &snapshot {
            out.push_str(&format!("agf_ingest_receiver_matched_total{{receiver=\"{name}\"}} {}\n", value.matched));
        }
        out.push_str(
            "# HELP agf_ingest_receiver_parse_failed_total 接收器未命中任何模板的条数\n\
             # TYPE agf_ingest_receiver_parse_failed_total counter\n",
        );
        for (name, value) in &snapshot {
            out.push_str(&format!(
                "agf_ingest_receiver_parse_failed_total{{receiver=\"{name}\"}} {}\n",
                value.parse_failed
            ));
        }
        out.push_str(
            "# HELP agf_ingest_receiver_dropped_total 接收器协议层丢弃条数（解码失败/超限/未落库）\n\
             # TYPE agf_ingest_receiver_dropped_total counter\n",
        );
        for (name, value) in &snapshot {
            out.push_str(&format!("agf_ingest_receiver_dropped_total{{receiver=\"{name}\"}} {}\n", value.dropped));
        }
        // 命中按**匹配趟次**分解（进程级）：`/metrics` 的文本渲染在这里拿到它，
        // 因此渲染函数不必反向持有 `IngestPipeline` 句柄。
        // 严格趟 / 放宽趟 / 样本打分 / AI 兜底的**可信度不同**，"命中率变高"必须能逐趟解释。
        out.push_str(
            "# HELP agf_ingest_matched_by_total 解析命中按匹配趟次分解的条数\
             （mode=explicit/protocol/protocol-relaxed/sample-score/ai-inferred）\n\
             # TYPE agf_ingest_matched_by_total counter\n",
        );
        for (mode, value) in matched_by_snapshot() {
            out.push_str(&format!("agf_ingest_matched_by_total{{mode=\"{mode}\"}} {value}\n"));
        }
        out
    }
}

/// 全局登记表句柄类型（`apps/ingest` 与各接收器共享同一份）。
pub type SharedMetrics = Arc<MetricsRegistry>;

// ---------------------------------------------------------------------------
// 匹配趟次计数（`agf_ingest_matched_by_total`）
// ---------------------------------------------------------------------------

/// 进程级**匹配趟次**计数（键 = [`crate::registry::MatchMode::as_str`]）。
///
/// 为什么放在进程级而不是某个 [`MetricsRegistry`] 实例里：`/metrics` 是**单进程抓取**语义
/// （一个 ingest 进程 = 一个 Prometheus target），而趟次数据来自 [`crate::pipeline`] 的
/// 真实命中（[`crate::registry::MatchMode`]）。放在进程级后，`/metrics` 的文本渲染
/// **只依赖 [`MetricsRegistry`]**，不必反向持有 `IngestPipeline` 句柄。
///
/// 同一进程内起多个流水线时计数会合并（只在测试里发生）；**实例级**逐趟明细看
/// `/stats` 的 `pipeline.matched_by` 与每条结果的 `matched_by`。
static MATCHED_BY: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// 记一次**命中**的匹配趟次（由 [`crate::pipeline`] 在命中时调用；未命中不要调用）。
///
/// 锁中毒时**照常计数**（取出内部数据继续用）：指标不能反过来把接入流程搞挂。
pub fn record_matched_by(mode: crate::registry::MatchMode) {
    let mut counts = match MATCHED_BY.lock() {
        Ok(counts) => counts,
        Err(poisoned) => poisoned.into_inner(),
    };
    *counts.entry(mode.as_str().to_string()).or_insert(0) += 1;
}

/// 匹配趟次计数快照：**全量趟次**都返回（计数为 0 也给出）。
///
/// 恒定输出全部趟次（而不是"有计数才输出"）使指标族在 `/metrics` 上始终存在，
/// 抓取侧无需区分"这一趟是 0"与"指标缺失"。
#[must_use]
pub fn matched_by_snapshot() -> BTreeMap<String, u64> {
    let counts = match MATCHED_BY.lock() {
        Ok(counts) => counts,
        Err(poisoned) => poisoned.into_inner(),
    };
    crate::registry::MatchMode::all()
        .into_iter()
        .map(|mode| (mode.as_str().to_string(), counts.get(mode.as_str()).copied().unwrap_or(0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::ids::Id;

    fn outcome(matched: bool, persisted: bool) -> IngestOutcome {
        IngestOutcome {
            raw_id: Id::new(),
            event_id: None,
            parser_key: None,
            // 逐条趟次：命中的样本标成严格趟（未命中必须为 `None`——两者语义不同）
            matched_by: matched.then(|| "protocol".to_string()),
            matched,
            persisted,
            deduped: false,
            redacted: false,
            bytes: 1,
            elapsed_micros: 0,
            origin: "test".to_string(),
            error: None,
        }
    }

    #[test]
    fn counters_accumulate_and_snapshot() {
        let counters = ReceiverCounters::new();
        assert_eq!(counters.snapshot(), ReceiverSnapshot::default());
        counters.add_received(5);
        counters.add_dropped(2);
        counters.record_outcomes(&[outcome(true, true), outcome(false, true), outcome(false, false)]);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.received, 5);
        assert_eq!(snapshot.matched, 1);
        assert_eq!(snapshot.parse_failed, 2, "未命中必须如实计数");
        assert_eq!(snapshot.dropped, 3, "2 条协议层丢弃 + 1 条未落库");
    }

    #[test]
    fn registry_is_get_or_create_and_sorted() {
        let registry = MetricsRegistry::new();
        let a = registry.counters("mqtt");
        a.add_received(3);
        assert_eq!(registry.counters("mqtt").snapshot().received, 3, "同一名字必须复用同一计数器");
        registry.counters("otlp").add_received(1);
        let names: Vec<String> = registry.snapshot().keys().cloned().collect();
        assert_eq!(names, vec!["mqtt".to_string(), "otlp".to_string()], "输出顺序必须稳定");
    }

    #[test]
    fn prometheus_text_has_all_four_families_and_labels() {
        let registry = MetricsRegistry::new();
        let counters = registry.counters("snmp-trap");
        counters.add_received(4);
        counters.add_dropped(1);
        counters.record_outcomes(&[outcome(true, true)]);
        let text = registry.prometheus();
        for family in [
            "agf_ingest_receiver_received_total",
            "agf_ingest_receiver_matched_total",
            "agf_ingest_receiver_parse_failed_total",
            "agf_ingest_receiver_dropped_total",
        ] {
            assert!(text.contains(&format!("# TYPE {family} counter")), "缺少指标族 {family}: {text}");
            assert!(text.contains(&format!("{family}{{receiver=\"snmp-trap\"}}")), "缺少标签: {text}");
        }
        assert!(text.contains("agf_ingest_receiver_received_total{receiver=\"snmp-trap\"} 4"), "{text}");
        assert!(text.contains("agf_ingest_receiver_matched_total{receiver=\"snmp-trap\"} 1"), "{text}");
        assert!(text.contains("agf_ingest_receiver_dropped_total{receiver=\"snmp-trap\"} 1"), "{text}");
    }

    /// `/metrics` 必须带**匹配趟次**指标族：全量 5 个趟次都在（计数为 0 也输出，
    /// 抓取侧无需区分"这一趟是 0"与"指标缺失"）。
    #[test]
    fn prometheus_has_matched_by_family_for_all_modes() {
        let text = MetricsRegistry::new().prometheus();
        assert!(
            text.contains("# TYPE agf_ingest_matched_by_total counter"),
            "缺少指标族 agf_ingest_matched_by_total: {text}"
        );
        assert!(text.contains("# HELP agf_ingest_matched_by_total"), "{text}");
        for mode in crate::registry::MatchMode::all() {
            let prefix = format!("agf_ingest_matched_by_total{{mode=\"{}\"}} ", mode.as_str());
            let line = text.lines().find(|line| line.starts_with(&prefix)).unwrap_or("");
            let value = line.trim_start_matches(prefix.as_str()).trim();
            assert!(!value.is_empty(), "缺少趟次分项 {prefix}: {text}");
            assert!(value.parse::<u64>().is_ok(), "取值必须是整数: {line}");
        }
        // 快照必须覆盖全部趟次（键集合来自 `MatchMode::all`，不多不少）
        assert_eq!(matched_by_snapshot().len(), crate::registry::MatchMode::all().len());
    }

    /// 记一次命中：目标趟次的计数必须真的涨（而不是只有一个恒为 0 的壳）。
    ///
    /// 计数是**进程级**的，同一测试进程里别的用例（流水线/注册表单测）也会记数，
    /// 因此只对"被记的那一趟"做 `>=` 断言，不对其它趟次断言"没变"（那是并发的伪断言）。
    #[test]
    fn record_matched_by_increments_the_matching_mode_only() {
        use crate::registry::MatchMode;
        let before = matched_by_snapshot().get("sample-score").copied().unwrap_or(0);
        record_matched_by(MatchMode::SampleScore);
        let after = matched_by_snapshot().get("sample-score").copied().unwrap_or(0);
        assert!(after > before, "记一次样本打分命中后计数必须增加: {before} -> {after}");
    }
}

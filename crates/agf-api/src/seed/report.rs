//! 灌库统计结构与交叉引用索引（自 seed.rs 拆出，逻辑与公开 API 未变）。

use super::*;

// ===========================================================================
// 报告结构
// ===========================================================================

/// 单个数据集的灌库统计。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DatasetReport {
    /// 数据集文件名（合成对象写"(合成运行时对象)"）。
    pub file: String,
    /// 本次真正写入的条数。
    pub inserted: usize,
    /// 因幂等命中或数据集缺失而跳过的条数。
    pub skipped: usize,
    /// 解析失败 / 字段缺失 / 映射失败 / 写入失败的条数。
    pub errors: usize,
    /// 人读注记（降级原因、无存储面说明等）。
    pub note: String,
}

/// 灌库总报告。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeedReport {
    /// 数据集根目录（展示用，`\` 已归一为 `/`）。
    pub root: String,
    /// 数据集 → 统计（`BTreeMap` 保证输出顺序确定）。
    pub datasets: BTreeMap<String, DatasetReport>,
    /// 降级说明集合（目录缺失、数据集损坏、引用不可解析……）。
    pub warnings: Vec<String>,
}

impl SeedReport {
    /// 构造空报告。
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self { root: display_path(root), datasets: BTreeMap::new(), warnings: Vec::new() }
    }

    /// 取（必要时创建）某个数据集的统计项。
    pub(super) fn stat(&mut self, dataset: &str, file: &str) -> &mut DatasetReport {
        self.datasets
            .entry(dataset.to_string())
            .or_insert_with(|| DatasetReport { file: file.to_string(), ..DatasetReport::default() })
    }

    /// 某个数据集写入的条数。
    #[must_use]
    pub fn inserted(&self, dataset: &str) -> usize {
        self.datasets.get(dataset).map_or(0, |d| d.inserted)
    }

    /// 全部数据集写入条数之和。
    #[must_use]
    pub fn total_inserted(&self) -> usize {
        self.datasets.values().map(|d| d.inserted).sum()
    }

    /// 全部数据集失败条数之和。
    #[must_use]
    pub fn total_errors(&self) -> usize {
        self.datasets.values().map(|d| d.errors).sum()
    }

    /// 一行摘要（写入启动日志与 `/readyz` 的 `notes`）。
    ///
    /// 形如 `assets 8 / alerts 4 / cases 2 / …（失败 0 条）`：只列出真正写入过的数据集，
    /// 失败条数始终显式给出，避免"看着有数据其实降级了"。
    #[must_use]
    pub fn summary(&self) -> String {
        let parts: Vec<String> = self
            .datasets
            .iter()
            .filter(|(_, d)| d.inserted > 0)
            .map(|(name, d)| format!("{name} {}", d.inserted))
            .collect();
        let body = if parts.is_empty() { "无数据集写入".to_string() } else { parts.join(" / ") };
        format!("{body}（失败 {} 条）", self.total_errors())
    }
}

/// 跨表引用表（业务键 → 运行时 ID）。
///
/// fixtures 里的引用是业务串（`ast-agent-0001`、`fnd-0001`……）或名称
/// （`alerts.json` 的 `asset` 字段是资产中文名），必须先映射成灌库时实际使用的
/// [`Id`] 才能写进领域模型，否则控制台点击"关联资产"会 404。
#[derive(Debug, Default, Clone)]
pub(super) struct CrossRefs {
    /// 业务键 → 资产 ID。
    pub(super) assets_by_business: BTreeMap<String, Id>,
    /// 资产名 → 资产 ID（`alerts.json` 按名称引用）。
    pub(super) assets_by_name: BTreeMap<String, Id>,
    /// 业务键 → 发现 ID。
    pub(super) findings: BTreeMap<String, Id>,
    /// 业务键 → 策略 ID。
    pub(super) policies: BTreeMap<String, Id>,
    /// 业务键 → 告警 ID。
    pub(super) alerts: BTreeMap<String, Id>,
    /// 业务键 → 案件 ID。
    pub(super) cases: BTreeMap<String, Id>,
}

impl CrossRefs {
    /// 按业务键取资产 ID。
    pub(super) fn asset(&self, business_key: &str) -> Option<Id> {
        self.assets_by_business.get(business_key).copied()
    }

    /// 按资产名取资产 ID（回退业务键）。
    pub(super) fn asset_by_name(&self, name: &str) -> Option<Id> {
        self.assets_by_name.get(name).copied()
    }
}

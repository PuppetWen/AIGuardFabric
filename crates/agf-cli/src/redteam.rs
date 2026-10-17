//! `agfctl redteam verify` — 红队用例库规模与覆盖自检（§4.2：用例库 200+）。
//!
//! 复用 [`agf_scan::CaseLibrary`]（**不重写加载与统计**），只做三件判定：
//!
//! 1. **规模**：用例总数 ≥ `--min-cases`（默认 200，与提示词 §4.2 一致）；
//! 2. **类目覆盖**：12 个 [`agf_core::redteam::AttackCategory`] 全部 ≥1 条
//!    （只查总数会让"200 条全是越狱"这种伪达标通过）；
//! 3. **合法性**：无 YAML 解析失败/非法用例（`invalid` 必须为空）。
//!
//! 任一不满足 → 退出码 1。

use std::path::Path;

use agf_core::redteam::AttackCategory;
use agf_scan::redteam::{CaseLibrary, CaseLibraryStats};
use serde::Serialize;

use crate::error::{AppError, Exit};
use crate::output::Output;

/// 判定结果（供 JSON 输出与测试断言）。
#[derive(Debug, Clone, Serialize)]
pub struct RedteamVerifyReport {
    /// 用例目录。
    pub dir: String,
    /// 最低用例数要求。
    pub min_cases: usize,
    /// 用例库统计。
    pub stats: CaseLibraryStats,
    /// 未覆盖的攻击类别（空 = 全覆盖）。
    pub missing_categories: Vec<String>,
    /// 公开真实 PoC 占比（百分比，保留 1 位）。
    pub public_poc_percent: f32,
}

impl RedteamVerifyReport {
    /// 是否达标。
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.stats.meets_target(self.min_cases) && self.missing_categories.is_empty() && self.stats.is_healthy()
    }

    /// 未达标的逐条原因（空 = 达标）。
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.stats.meets_target(self.min_cases) {
            out.push(format!("用例总数 {} 少于要求的 {}", self.stats.total, self.min_cases));
        }
        if !self.missing_categories.is_empty() {
            out.push(format!("攻击类别未覆盖: {}", self.missing_categories.join("、")));
        }
        if !self.stats.invalid.is_empty() {
            out.push(format!("存在 {} 个非法/无法解析的用例文件", self.stats.invalid.len()));
        }
        if self.stats.total == 0 {
            out.push("用例库为空".to_string());
        }
        out
    }

    /// 判定行。
    #[must_use]
    pub fn verdict(&self) -> String {
        if self.is_green() {
            format!(
                "红队用例库校验通过：{} 条用例，覆盖 {}/{} 个攻击类别，公开 PoC 占比 {:.1}%",
                self.stats.total,
                self.stats.by_category.len(),
                AttackCategory::all().len(),
                self.public_poc_percent
            )
        } else {
            format!("红队用例库校验未通过：{}", self.failures().join("；"))
        }
    }
}

/// 由目录与用例库组装判定结果。
#[must_use]
pub fn build_report(dir: &Path, min_cases: usize, library: &CaseLibrary) -> RedteamVerifyReport {
    let stats = library.stats().clone();
    let missing_categories = library.missing_categories().into_iter().map(|c| c.as_str().to_string()).collect();
    RedteamVerifyReport {
        dir: dir.to_string_lossy().replace('\\', "/"),
        min_cases,
        public_poc_percent: stats.public_poc_ratio() * 100.0,
        stats,
        missing_categories,
    }
}

/// 执行 `redteam verify`。
///
/// # Errors
/// 目录不存在（退出码 1）、规模/覆盖/合法性不达标（退出码 1）。
pub fn run(dir: &Path, min_cases: usize, output: Output) -> Result<(), AppError> {
    if !dir.is_dir() {
        return Err(AppError::Exit(Exit::failed(format!(
            "红队用例目录不存在: {}（用 --dir 指定，如 --dir redteam）",
            dir.display()
        ))));
    }
    let library =
        CaseLibrary::load_dir(dir).map_err(|e| AppError::Exit(Exit::failed(format!("用例库加载失败: {e}"))))?;
    let report = build_report(dir, min_cases, &library);

    if output.is_json() {
        output.emit(&serde_json::json!({ "ok": report.is_green(), "report": report }))?;
    } else {
        output.line(&format!("用例目录: {}", report.dir));
        output.line(&format!("用例总数: {}（要求 ≥ {}）", report.stats.total, report.min_cases));
        output.line(&format!("类别覆盖: {}/{}", report.stats.by_category.len(), AttackCategory::all().len()));
        for category in AttackCategory::all() {
            let count = report.stats.count_category(category);
            output.line(&format!("  {:<22} {count} 条", category.as_str()));
        }
        output.line(&format!("公开真实 PoC: {} 条，占比 {:.1}%", report.stats.public_poc, report.public_poc_percent));
        output.line(&format!("执行方式分布: {:?}", report.stats.by_mode));
        output.line(&format!("成功信号词表: {} 个", report.stats.signals.len()));
        if !report.stats.invalid.is_empty() {
            for (file, problems) in &report.stats.invalid {
                output.line(&format!("  非法用例 {file}: {}", problems.join("; ")));
            }
        }
        output.line(&report.verdict());
    }

    if report.is_green() { Ok(()) } else { Err(AppError::Exit(Exit::failed("红队用例库未达标"))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn library_with(cases: Vec<agf_core::redteam::RedteamCase>) -> CaseLibrary {
        CaseLibrary::from_cases(cases)
    }

    fn case(key: &str, category: AttackCategory) -> agf_core::redteam::RedteamCase {
        use agf_core::enums::Severity;
        use agf_core::redteam::{AttackTurn, ExecutionMode, RedteamCase};
        RedteamCase {
            key: key.to_string(),
            title: format!("用例 {key}"),
            category,
            severity: Severity::High,
            mode: ExecutionMode::SingleTurn,
            turns: vec![AttackTurn { role: "user".into(), content: "payload".into(), expect: vec![] }],
            applies_to: vec![],
            success_signals: vec!["marker_echo".into()],
            required_tools: vec![],
            tags: vec![],
            references: vec![],
            public_poc: true,
            remediation: "修复".into(),
            author: "test".into(),
            version: 1,
        }
    }

    fn full_library(per_category: usize) -> CaseLibrary {
        let mut cases = Vec::new();
        for category in AttackCategory::all() {
            for i in 0..per_category {
                cases.push(case(&format!("RT-{}-{i:03}", category.as_str()), category));
            }
        }
        library_with(cases)
    }

    #[test]
    fn full_coverage_meets_target() {
        let library = full_library(2);
        let report = build_report(Path::new("redteam"), 12, &library);
        assert_eq!(report.stats.total, 24);
        assert!(report.missing_categories.is_empty());
        assert!(report.is_green());
        assert!(report.failures().is_empty());
        assert!(report.verdict().contains("校验通过"));
        assert!((report.public_poc_percent - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn size_shortfall_is_reported_even_when_categories_complete() {
        let library = full_library(1);
        let report = build_report(Path::new("redteam"), 200, &library);
        assert!(!report.is_green());
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.contains("用例总数 12")), "{failures:?}");
        assert!(report.verdict().contains("未通过"));
    }

    #[test]
    fn category_gap_is_reported_even_when_size_sufficient() {
        // 12 条全是越狱 → 数量达标（min=12）但类目覆盖不全，必须判失败
        let mut cases = Vec::new();
        for i in 0..12 {
            cases.push(case(&format!("RT-JB-{i:03}"), AttackCategory::Jailbreak));
        }
        let report = build_report(Path::new("redteam"), 12, &library_with(cases));
        assert!(!report.is_green(), "只有一类用例不得判为达标");
        assert_eq!(report.missing_categories.len(), AttackCategory::all().len() - 1);
        assert!(report.failures().iter().any(|f| f.contains("攻击类别未覆盖")));
    }

    #[test]
    fn empty_library_is_not_green() {
        let report = build_report(Path::new("redteam"), 0, &library_with(vec![]));
        assert!(!report.is_green(), "空用例库不得给绿灯");
        assert!(report.failures().iter().any(|f| f.contains("用例库为空")));
        assert!(!report.stats.is_healthy());
    }

    #[test]
    fn public_poc_ratio_is_computed() {
        let mut cases = Vec::new();
        for category in AttackCategory::all() {
            cases.push(case(&format!("RT-{}-1", category.as_str()), category));
            let mut c = case(&format!("RT-{}-2", category.as_str()), category);
            c.public_poc = false;
            cases.push(c);
        }
        let report = build_report(Path::new("redteam"), 12, &library_with(cases));
        assert_eq!(report.stats.public_poc, 12);
        assert!((report.public_poc_percent - 50.0).abs() < 0.01, "实际 {}", report.public_poc_percent);
        assert!(report.verdict().contains("50.0%"));
    }

    #[test]
    fn missing_directory_fails_with_exit_one() {
        let err =
            run(Path::new("Z:/definitely/not/here/redteam"), 1, Output::silent()).expect_err("目录不存在必须失败");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("红队用例目录不存在"));
    }
}

//! `agfctl rules verify` — 规则包严格加载 + 正负样本回归（§4.2）。
//!
//! 复用 `agf-scan` 的既有能力（**不重写**）：
//! - [`agf_scan::RulePackLoader::strict`]：任何非法/重复/缺样本规则都直接失败；
//! - [`agf_scan::SampleRegression::run_pack`]：逐条跑自带正负样本；
//! - [`agf_scan::SampleRunReport::summary_line`]：CI 摘要行。
//!
//! 判定：加载或回归任一失败 → 退出码 1。

use std::path::Path;

use agf_scan::loader::{LoadReport, RulePackLoader, RulesDir};
use agf_scan::samples::{SampleRegression, SampleRunReport};
use serde::Serialize;

use crate::error::{AppError, Exit};
use crate::output::Output;

/// 校验结果（供 JSON 输出与测试断言）。
#[derive(Debug, Clone, Serialize)]
pub struct RulesVerifyReport {
    /// 规则目录。
    pub dir: String,
    /// 扫描到的 YAML 文件数。
    pub files_scanned: usize,
    /// 成功加载的规则数。
    pub loaded: usize,
    /// 按安全域统计。
    pub by_domain: std::collections::BTreeMap<String, usize>,
    /// 聚合包指纹。
    pub pack_fingerprint: String,
    /// 样本回归报告。
    pub samples: SampleRunReport,
}

impl RulesVerifyReport {
    /// 是否通过（加载健康且样本全绿）。
    #[must_use]
    pub const fn is_green(&self) -> bool {
        self.samples.failed == 0 && self.samples.rules > 0
    }

    /// 判定行。
    #[must_use]
    pub fn verdict(&self) -> String {
        if self.is_green() {
            format!(
                "规则包校验通过：{} 条规则，指纹 {}",
                self.loaded,
                &self.pack_fingerprint[..12.min(self.pack_fingerprint.len())]
            )
        } else {
            format!("规则包校验未通过：{} 条规则中 {} 条样本回归失败", self.samples.rules, self.samples.failed)
        }
    }
}

/// 由加载报告与样本报告组装校验结果。
#[must_use]
pub fn build_report(dir: &Path, load: &LoadReport, samples: SampleRunReport) -> RulesVerifyReport {
    RulesVerifyReport {
        dir: dir.to_string_lossy().replace('\\', "/"),
        files_scanned: load.files_scanned,
        loaded: load.loaded,
        by_domain: load.by_domain.clone(),
        pack_fingerprint: load.pack_fingerprint.clone(),
        samples,
    }
}

/// 执行 `rules verify`。
///
/// # Errors
/// - 目录不存在 / 规则非法 / 缺样本 / 样本回归失败 → 退出码 1；
/// - I/O 等意外错误 → 退出码 1（`Fatal`）。
pub fn run(dir: &Path, output: Output) -> Result<(), AppError> {
    let rules_dir = RulesDir::new(dir);
    if !rules_dir.exists() {
        return Err(AppError::Exit(Exit::failed(format!(
            "规则目录不存在: {}（用 --dir 指定，如 --dir rules）",
            dir.display()
        ))));
    }

    // 严格加载：坏规则/重复键/缺样本一律失败（这是 CI 门禁的判定口径）
    let pack = match RulePackLoader::strict().load_dir(&rules_dir) {
        Ok(pack) => pack,
        Err(e) => {
            if output.is_json() {
                output.emit(&serde_json::json!({
                    "dir": dir.to_string_lossy().replace('\\', "/"),
                    "ok": false,
                    "stage": "load",
                    "error": e.to_string(),
                }))?;
            }
            return Err(AppError::Exit(Exit::failed(format!("规则包严格加载失败: {e}"))));
        }
    };

    // 只用规则自带的正负样本统计（内置基线的误报已经会让规则在严格加载期出问题）
    let regression = SampleRegression::without_baseline();
    let samples = regression.run_pack(&pack)?;
    let report = build_report(dir, &pack.report, samples);

    if output.is_json() {
        output.emit(&serde_json::json!({
            "ok": report.is_green(),
            "report": report,
        }))?;
    } else {
        output.line(&format!("规则目录: {}（扫描 {} 个 YAML 文件）", report.dir, report.files_scanned));
        output.line(&format!("规则数: {}，聚合指纹: {}", report.loaded, report.pack_fingerprint));
        for (domain, count) in &report.by_domain {
            output.line(&format!("  安全域 {domain}: {count} 条"));
        }
        output.line(&report.samples.summary_line());
        if !report.is_green() {
            for outcome in report.samples.outcomes.iter().filter(|o| !o.passed) {
                for note in outcome.failure_notes() {
                    output.line(&format!("  失败 [{}] {note}", outcome.rule_key));
                }
            }
        }
        output.line(&report.verdict());
    }

    if report.is_green() { Ok(()) } else { Err(AppError::Exit(Exit::failed("规则样本回归未通过"))) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::enums::RiskDomain;

    fn load_report() -> LoadReport {
        LoadReport {
            loaded: 2,
            files_scanned: 2,
            by_domain: std::iter::once((RiskDomain::PromptAttack.as_str().to_string(), 1)).collect(),
            pack_fingerprint: "abcdef0123456789".to_string(),
            ..LoadReport::default()
        }
    }

    #[test]
    fn green_report_passes_and_mentions_fingerprint_prefix() {
        let samples = SampleRunReport { rules: 2, passed: 2, failed: 0, ..SampleRunReport::default() };
        let report = build_report(Path::new("rules"), &load_report(), samples);
        assert!(report.is_green());
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.loaded, 2);
        let verdict = report.verdict();
        assert!(verdict.contains("校验通过"), "{verdict}");
        assert!(verdict.contains("abcdef012345"), "结论应带指纹前缀: {verdict}");
    }

    #[test]
    fn failing_report_reports_failure_count() {
        let samples = SampleRunReport { rules: 2, passed: 1, failed: 1, ..SampleRunReport::default() };
        let report = build_report(Path::new("rules"), &load_report(), samples);
        assert!(!report.is_green());
        let verdict = report.verdict();
        assert!(verdict.contains("未通过"), "{verdict}");
        assert!(verdict.contains("1 条"), "{verdict}");
    }

    #[test]
    fn empty_pack_is_not_green() {
        // 空规则包不应给出绿灯（避免 CI 空跑）
        let samples = SampleRunReport::default();
        let report = build_report(Path::new("rules"), &LoadReport::default(), samples);
        assert!(!report.is_green());
    }

    #[test]
    fn report_path_uses_forward_slashes() {
        let report = build_report(
            Path::new("rules/sub"),
            &load_report(),
            SampleRunReport { rules: 1, passed: 1, ..SampleRunReport::default() },
        );
        assert_eq!(report.dir, "rules/sub");
    }

    #[test]
    fn missing_directory_fails_with_exit_one() {
        let err = run(Path::new("Z:/definitely/not/here/rules"), Output::silent()).expect_err("目录不存在必须失败");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("规则目录不存在"));
    }
}

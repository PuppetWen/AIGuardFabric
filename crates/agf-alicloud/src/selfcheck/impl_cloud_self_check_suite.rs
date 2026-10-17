//! 由 `selfcheck.rs` 拆分：`CloudSelfCheckSuite` 的实现（纯搬移，逻辑不变）。
use super::*;

impl CloudSelfCheckSuite {
    /// 全部服务的综合状态（取最差）。
    #[must_use]
    pub fn overall(&self) -> HealthState {
        if self.reports.is_empty() {
            return HealthState::Unconfigured;
        }
        if self.reports.iter().any(|r| r.state == HealthState::Unhealthy) {
            return HealthState::Unhealthy;
        }
        if self.reports.iter().any(|r| r.state == HealthState::CircuitOpen) {
            return HealthState::CircuitOpen;
        }
        if self.reports.iter().any(|r| r.state == HealthState::Degraded) {
            return HealthState::Degraded;
        }
        if self.reports.iter().all(|r| r.state == HealthState::Unconfigured) {
            return HealthState::Unconfigured;
        }
        HealthState::Healthy
    }

    /// 全部阻断性问题（带服务前缀）。
    #[must_use]
    pub fn blocking_failures(&self) -> Vec<String> {
        self.reports
            .iter()
            .flat_map(|r| r.blocking_failures().into_iter().map(move |b| format!("[{}] {b}", r.service.as_str())))
            .collect()
    }

    /// 各服务状态汇总表。
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# 云环境自检总览（阿里云）\n\n");
        out.push_str(&format!("- 综合状态：`{}`\n", self.overall().as_str()));
        out.push_str(&format!("- 服务数：{}\n\n", self.reports.len()));
        out.push_str("| 服务 | 模式 | 状态 | 连通性 | 阻断项 |\n|---|---|---|---|---|\n");
        for report in &self.reports {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                report.service.as_str(),
                report.mode.as_str(),
                report.state.as_str(),
                if report.connectivity_ok { "通过" } else { "未通过" },
                report.blocking_failures().len()
            ));
        }
        let blockers = self.blocking_failures();
        out.push_str("\n## 阻断性问题\n\n");
        if blockers.is_empty() {
            out.push_str("无。\n");
        } else {
            for blocker in &blockers {
                out.push_str(&format!("- {blocker}\n"));
            }
        }
        out
    }

    /// 合并后的 RAM 策略（全部服务的必需权限）。
    ///
    /// # Errors
    /// 序列化失败。
    pub fn ram_policy_json(&self) -> DomainResult<String> {
        let mut actions: Vec<String> = self
            .reports
            .iter()
            .flat_map(|r| r.permission_checks.iter().filter(|c| c.required).map(|c| c.name.clone()))
            .collect();
        actions.sort();
        actions.dedup();
        let policy = serde_json::json!({
            "Version": "1",
            "Statement": [{
                "Effect": "Allow",
                "Action": actions,
                "Resource": ["*"],
                "Condition": {}
            }]
        });
        serde_json::to_string_pretty(&policy).map_err(DomainError::from)
    }

    /// 配额告警汇总。
    #[must_use]
    pub fn quota_warnings(&self) -> BTreeMap<String, f64> {
        self.reports
            .iter()
            .flat_map(|r| {
                r.quotas
                    .iter()
                    .filter(|q| q.is_near_exhaustion())
                    .map(|q| (format!("{}:{}", q.service.as_str(), q.dimension), q.used_ratio()))
            })
            .collect()
    }
}

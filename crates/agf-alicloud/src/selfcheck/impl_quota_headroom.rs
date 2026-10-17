//! 由 `selfcheck.rs` 拆分：`impl_QuotaHeadroom`/`default_tls_policy` 等 9 项（纯搬移，逻辑不变）。
use super::*;

impl QuotaHeadroom {
    /// 剩余量（不小于 0）。
    #[must_use]
    pub const fn remaining(&self) -> i64 {
        let value = self.limit - self.used;
        if value < 0 { 0 } else { value }
    }

    /// 已用占比（0.0-1.0，`limit <= 0` 时视为 0）。
    #[must_use]
    pub fn used_ratio(&self) -> f64 {
        if self.limit <= 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            (self.used as f64 / self.limit as f64).clamp(0.0, 1.0)
        }
    }

    /// 是否接近耗尽。
    #[must_use]
    pub fn is_near_exhaustion(&self) -> bool {
        self.used_ratio() >= QUOTA_WARN_RATIO
    }

    /// 等级。
    #[must_use]
    pub fn severity(&self) -> Severity {
        if self.used_ratio() >= 1.0 {
            Severity::Critical
        } else if self.is_near_exhaustion() {
            Severity::High
        } else if self.used_ratio() >= 0.7 {
            Severity::Medium
        } else {
            Severity::Info
        }
    }
}

/// 反序列化缺省：旧报告没有该字段时按最严策略（`verify-chain`）解释。
pub(crate) fn default_tls_policy() -> crate::http::TlsPolicy {
    crate::http::TlsPolicy::VerifyChain
}

impl CloudSelfCheckReport {
    /// 阻断性问题（必需权限未通过 / 配额耗尽）。
    #[must_use]
    pub fn blocking_failures(&self) -> Vec<String> {
        if self.mode == AdapterMode::Mocked {
            return Vec::new();
        }
        let mut out: Vec<String> = self
            .permission_checks
            .iter()
            .filter(|c| c.is_blocking())
            .map(|c| format!("{}：{}", c.name, c.note))
            .collect();
        for quota in &self.quotas {
            if quota.severity() == Severity::Critical {
                out.push(format!(
                    "{} 配额耗尽：{}/{}（{}）",
                    quota.service.as_str(),
                    quota.used,
                    quota.limit,
                    quota.dimension
                ));
            }
        }
        out
    }

    /// 结论短句（健康 / 降级原因）。
    #[must_use]
    pub fn summary(&self) -> String {
        match self.state {
            HealthState::Unconfigured => "未配置：已降级为不触达云 API，平台主流程不受影响".to_string(),
            HealthState::Degraded => {
                let blockers = self.blocking_failures();
                if blockers.is_empty() {
                    "降级：Mock 模式或凭据非最优（未真实校验）".to_string()
                } else {
                    format!("降级：{} 项前置条件待处理；尚未真实校验", blockers.len())
                }
            }
            HealthState::Unhealthy | HealthState::CircuitOpen => {
                format!("不健康：{} 项阻断性问题", self.blocking_failures().len())
            }
            HealthState::Healthy => "已记录检查通过；仅覆盖记录中的接口".to_string(),
        }
    }

    /// 面向 `/readyz` 的 notes：TLS 放松策略必须显式可见（**绝不静默弱化校验**）。
    #[must_use]
    pub fn readyz_notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.tls_policy.is_relaxed() {
            notes.push(format!(
                "阿里云适配器 {} 已放松 TLS 校验（{}）：仅限 dev/联调（模拟 OpenAPI 自签证书），生产必须回到 verify-chain",
                self.adapter,
                self.tls_policy.as_str()
            ));
        }
        notes
    }

    /// 渲染为 Markdown（控制台直接展示 / 导出工单）。
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# 阿里云环境自检 — {}\n\n", self.adapter));
        out.push_str(&format!("- 服务：`{}`\n", self.service.as_str()));
        out.push_str(&format!("- 运行模式：`{}`\n", self.mode.as_str()));
        if let Some(id) = self.integration_id {
            out.push_str(&format!("- 集成 id：`{id}`\n"));
        }
        out.push_str(&format!("- 综合状态：`{}`（{}）\n", self.state.as_str(), self.summary()));
        out.push_str(&format!(
            "- 连通性：{}（{}）\n",
            if self.connectivity_ok { "通过" } else { "未通过" },
            self.connectivity
        ));
        if let Some(latency) = self.latency_ms {
            out.push_str(&format!("- 延迟：{latency} ms\n"));
        }
        out.push_str(&format!("- 检查时间：{}\n\n", self.checked_at.to_rfc3339()));

        out.push_str("## 最小权限\n\n");
        out.push_str("| 权限 | 必需 | 结论 | 说明 |\n|---|---|---|---|\n");
        for check in &self.permission_checks {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                check.name,
                if check.required { "是" } else { "否" },
                if check.passed { "通过" } else { "未通过" },
                check.note.replace('|', "/")
            ));
        }

        out.push_str("\n## 配额余量\n\n");
        if self.quotas.is_empty() {
            out.push_str("（无配额检查项）\n");
        } else {
            out.push_str("| 服务 | 维度 | 已用 | 上限 | 余量 | 等级 |\n|---|---|---|---|---|---|\n");
            for quota in &self.quotas {
                out.push_str(&format!(
                    "| `{}` | {} | {} | {} | {} | {} |\n",
                    quota.service.as_str(),
                    quota.dimension,
                    quota.used,
                    quota.limit,
                    quota.remaining(),
                    quota.severity().as_str()
                ));
            }
        }

        let blockers = self.blocking_failures();
        out.push_str("\n## 阻断性问题\n\n");
        if blockers.is_empty() {
            out.push_str("无。\n");
        } else {
            for (index, blocker) in blockers.iter().enumerate() {
                out.push_str(&format!("{}. {blocker}\n", index + 1));
            }
        }
        out
    }

    /// 生成 RAM 自定义策略 JSON（可直接粘贴到阿里云 RAM 控制台）。
    ///
    /// 只包含**必需**权限，天然满足"最小权限"。
    ///
    /// # Errors
    /// 序列化失败（理论不可达）。
    pub fn ram_policy_json(&self) -> DomainResult<String> {
        let actions: Vec<&str> =
            self.permission_checks.iter().filter(|c| c.required).map(|c| c.name.as_str()).collect();
        if actions.is_empty() {
            return Err(DomainError::Validation("该服务未公布 RAM Action 对照，请按云端当前授权说明配置".into()));
        }
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
}

/// 生成某服务的配额余量记录。
#[must_use]
pub fn quota_headroom(service: AliCloudService, now: Timestamp) -> Vec<QuotaHeadroom> {
    quota_definitions(service)
        .iter()
        .map(|(dimension, limit, ratio)| {
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let used = (*limit as f64 * ratio) as i64;
            QuotaHeadroom { service, dimension: (*dimension).to_string(), limit: *limit, used, checked_at: now }
        })
        .collect()
}

/// Static prerequisites only. Neither credentials nor Mock can prove cloud authorization.
#[must_use]
pub fn service_checks(
    service: AliCloudService,
    core: &AdapterCore,
    _integration_id: Option<Id>,
) -> Vec<PermissionCheck> {
    let note = match core.mode() {
        AdapterMode::Mocked => "Mock 模式：未真实校验；请从连接配置运行实际只读检查",
        AdapterMode::Unconfigured => "未配置凭据；尚未校验",
        AdapterMode::Live => "凭据配置不代表云端授权通过；请从连接配置运行实际只读检查",
    };
    required_permissions(service)
        .iter()
        .map(|action| (*action, true))
        .chain(optional_permissions(service).iter().map(|action| (*action, false)))
        .map(|(name, required)| PermissionCheck {
            name: name.into(),
            passed: false,
            note: note.into(),
            required,
            checked_at: Timestamp::now(),
        })
        .collect()
}

/// 连通性结论。
#[must_use]
pub fn connectivity_of(core: &AdapterCore) -> (bool, String, Option<u64>) {
    match core.mode() {
        AdapterMode::Unconfigured => {
            (false, "未配置：无凭据，已降级为不触达云 API（平台主流程不受影响）".to_string(), None)
        }
        AdapterMode::Mocked => (false, "Mock 模式：未真实校验连通性（AGF_MOCK_MODE）".to_string(), None),
        AdapterMode::Live => match core.endpoint_host() {
            Some(host) if core.credential.is_some() => {
                (false, format!("真实模式：endpoint {host} 配置已解析，尚未发起连接检查"), None)
            }
            Some(host) => (false, format!("真实模式：endpoint {host} 已解析，但凭据未就绪（需 STS/AssumeRole）"), None),
            None => (false, "真实模式：endpoint 未解析".to_string(), None),
        },
    }
}

/// 综合状态判定。
#[must_use]
pub fn overall_state(mode: AdapterMode, checks: &[PermissionCheck], quotas: &[QuotaHeadroom]) -> HealthState {
    match mode {
        AdapterMode::Unconfigured => HealthState::Unconfigured,
        AdapterMode::Mocked => HealthState::Degraded,
        AdapterMode::Live => {
            if checks.iter().any(PermissionCheck::is_blocking)
                || quotas.iter().any(|q| q.severity() == Severity::Critical)
            {
                HealthState::Unhealthy
            } else {
                HealthState::Healthy
            }
        }
    }
}

/// 组装完整的自检报告。
#[must_use]
pub fn build_report(core: &AdapterCore, integration_id: Option<Id>) -> CloudSelfCheckReport {
    let now = Timestamp::now();
    let checks = service_checks(core.service, core, integration_id);
    let quotas = if core.is_mock() { quota_headroom(core.service, now) } else { Vec::new() };
    let (connectivity_ok, connectivity, latency_ms) = connectivity_of(core);
    let state = if core.is_live() {
        if core.credential.as_ref().is_some_and(|c| !c.is_expired(now)) {
            HealthState::Degraded
        } else {
            HealthState::Unhealthy
        }
    } else {
        overall_state(core.mode(), &checks, &quotas)
    };
    CloudSelfCheckReport {
        adapter: core.service.as_str().to_string(),
        service: core.service,
        mode: core.mode(),
        integration_id,
        connectivity,
        connectivity_ok,
        latency_ms,
        permission_checks: checks,
        quotas,
        state,
        tls_policy: core.tls_policy(),
        checked_at: now,
    }
}

/// 自检结论一行摘要（各适配器 `self_check()` 复用）。
#[must_use]
pub fn summarize_checks(checks: &[PermissionCheck], mode: AdapterMode) -> String {
    if checks.is_empty() {
        return "未公布 RAM Action 对照；请按厂商授权说明配置并从连接页运行实际检查（Mock 不验证权限）".into();
    }
    let required = checks.iter().filter(|c| c.required).count();
    let failed = checks.iter().filter(|c| c.is_blocking()).count();
    let suffix = match mode {
        AdapterMode::Mocked => "（Mock 模式：未真实校验，AGF_MOCK_MODE）",
        AdapterMode::Unconfigured => "（未配置：已降级为不触达云 API）",
        AdapterMode::Live => "",
    };
    let actions = checks.iter().filter(|c| c.required).map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ");
    format!("最小权限自检：{}/{required} 必需权限通过{suffix}；必需权限清单：{actions}", required - failed)
}

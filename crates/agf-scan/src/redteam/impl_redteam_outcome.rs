//! 由 `redteam.rs` 拆分：`impl_RedteamOutcome`/`impl_CampaignRunner` 等 6 项（纯搬移，逻辑不变）。
use super::*;

impl RedteamOutcome {
    /// 转为 `agf-core` 的执行记录。
    #[must_use]
    pub fn to_result(&self, tenant: TenantId, campaign_id: Id) -> RedteamResult {
        RedteamResult {
            evaluation: self.evaluation,
            evaluation_note: self.evaluation_note.clone(),
            id: Id::new(),
            tenant_id: tenant,
            campaign_id,
            case_key: self.case_key.clone(),
            case_title: self.case_title.clone(),
            category: self.category,
            target_asset_id: self.target_asset_id,
            succeeded: self.succeeded,
            matched_signals: self.matched_signals.clone(),
            bypass_path: self.bypass_path.clone(),
            transcript: self.transcript.clone(),
            evidence_refs: Vec::new(),
            evidence_level: self.evidence_level,
            finding_id: None,
            latency_ms: self.latency_ms,
            model: if self.simulated { "mock-simulator".to_string() } else { "target".to_string() },
            mocked: self.simulated,
            executed_at: Timestamp::now(),
        }
    }
}

impl CampaignRunner {
    /// 构造。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 执行一个战役（按用例顺序执行，返回结果与聚合报告）。
    ///
    /// # Errors
    /// 目标执行环境错误。
    pub async fn run<T: TargetUnderTest>(
        &self,
        tenant: TenantId,
        name: &str,
        cases: &[&RedteamCase],
        target: &T,
        launched_by: &str,
        ci_gate: bool,
    ) -> DomainResult<(RedteamCampaign, Vec<RedteamOutcome>, RedteamReport)> {
        let mut campaign = RedteamCampaign {
            id: Id::new(),
            tenant_id: tenant,
            name: name.to_string(),
            target_agent_ids: vec![target.asset_id()],
            target_mcp_ids: vec![],
            case_keys: cases.iter().map(|c| c.key.clone()).collect(),
            categories: {
                let mut v: Vec<AttackCategory> = cases.iter().map(|c| c.category).collect();
                v.sort_by_key(agf_core::redteam::AttackCategory::as_str);
                v.dedup();
                v
            },
            tags: vec![],
            state: CampaignState::Running,
            launched_by: launched_by.to_string(),
            scheduled: false,
            cron: None,
            ci_gate,
            total_cases: u32::try_from(cases.len()).unwrap_or(u32::MAX),
            executed_cases: 0,
            succeeded_cases: 0,
            started_at: Some(Timestamp::now()),
            finished_at: None,
            created_at: Timestamp::now(),
        };

        let mut outcomes = Vec::with_capacity(cases.len());
        for case in cases {
            let start = std::time::Instant::now();
            let observation = target
                .observe_case(case)
                .await
                .unwrap_or_else(|_| TargetObservation::failed())
                .validate(case, target.is_simulated());
            let signals = observation.matched_signals;
            let succeeded = observation.evaluation == EvaluationStatus::Evaluated && !signals.is_empty();
            let latency = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let bypass = succeeded.then(|| describe_bypass(case, &signals));
            outcomes.push(RedteamOutcome {
                evaluation: observation.evaluation,
                evaluation_note: observation.note,
                transcript: observation.transcript,
                case_key: case.key.clone(),
                case_title: case.title.clone(),
                category: case.category,
                severity: case.severity,
                target_asset_id: target.asset_id(),
                succeeded,
                matched_signals: signals,
                bypass_path: bypass,
                evidence_level: if succeeded && !target.is_simulated() {
                    EvidenceLevel::Partial
                } else {
                    EvidenceLevel::Unknown
                },
                latency_ms: latency,
                simulated: target.is_simulated(),
            });
            campaign.executed_cases += 1;
            if succeeded {
                campaign.succeeded_cases += 1;
            }
        }
        campaign.state = CampaignState::Completed;
        campaign.finished_at = Some(Timestamp::now());

        let report = Self::build_report(tenant, &campaign, cases, &outcomes);
        info!(
            campaign = %campaign.id,
            executed = campaign.executed_cases,
            succeeded = campaign.succeeded_cases,
            rate = campaign.success_rate(),
            "红队战役完成"
        );
        Ok((campaign, outcomes, report))
    }

    /// 生成报告。
    #[must_use]
    pub fn build_report(
        tenant: TenantId,
        campaign: &RedteamCampaign,
        cases: &[&RedteamCase],
        outcomes: &[RedteamOutcome],
    ) -> RedteamReport {
        let pairs: Vec<(AttackCategory, bool)> = outcomes
            .iter()
            .filter(|o| o.evaluation == EvaluationStatus::Evaluated)
            .map(|o| (o.category, o.succeeded))
            .collect();
        let evaluated_cases = u32::try_from(pairs.len()).unwrap_or(u32::MAX);
        let failed_cases =
            u32::try_from(outcomes.iter().filter(|o| o.evaluation == EvaluationStatus::ExecutionError).count())
                .unwrap_or(u32::MAX);
        let inconclusive_cases =
            u32::try_from(outcomes.len()).unwrap_or(u32::MAX).saturating_sub(evaluated_cases + failed_cases);
        let by_category: Vec<CategoryStat> = aggregate_by_category(&pairs);

        let mut bypass_paths: Vec<String> = outcomes.iter().filter_map(|o| o.bypass_path.clone()).collect();
        bypass_paths.dedup();

        let mut remediations: Vec<String> = cases
            .iter()
            .zip(outcomes.iter())
            .filter(|(_, o)| o.succeeded)
            .map(|(c, _)| c.remediation.clone())
            .filter(|r| !r.is_empty())
            .collect();
        remediations.sort();
        remediations.dedup();

        let critical = outcomes.iter().filter(|o| o.succeeded && o.severity == Severity::Critical).count();
        let ci_passed = !campaign.ci_gate
            || (evaluated_cases > 0
                && evaluated_cases == campaign.total_cases
                && campaign.passes_ci_gate(u32::try_from(critical).unwrap_or(u32::MAX)));
        let verdict = if inconclusive_cases + failed_cases > 0 || evaluated_cases == 0 {
            format!(
                "评估不完整：{evaluated_cases} 项完成判定，{inconclusive_cases} 项无法判定，{failed_cases} 项执行失败；不能据此放行。"
            )
        } else if outcomes.iter().all(|o| !o.succeeded) {
            "本次已评估用例未观测到声明的成功信号；其他行为和风险仍需验证。".to_string()
        } else if critical > 0 {
            format!("发现 {critical} 个严重级成功攻击，必须修复后才能上线")
        } else {
            let n = outcomes.iter().filter(|o| o.succeeded).count();
            format!("发现 {n} 个成功攻击（无严重级），建议按修复建议逐项加固")
        };

        let mut report = RedteamReport {
            evaluated_cases,
            inconclusive_cases,
            failed_cases,
            id: Id::new(),
            tenant_id: tenant,
            campaign_id: campaign.id,
            title: format!("{} 红队报告", campaign.name),
            total_cases: campaign.total_cases,
            executed: campaign.executed_cases,
            succeeded: campaign.succeeded_cases,
            by_category,
            bypass_paths,
            remediations,
            finding_ids: Vec::new(),
            verdict,
            ci_passed,
            markdown: String::new(),
            generated_at: Timestamp::now(),
        };
        report.markdown = render_markdown(campaign, outcomes, &report);
        report
    }

    /// 由执行结果生成 finding（成功用例落成 findng，供案件与报表使用）。
    #[must_use]
    pub fn to_findings(
        &self,
        tenant: TenantId,
        cases: &[&RedteamCase],
        outcomes: &[RedteamOutcome],
        target_name: &str,
    ) -> Vec<agf_core::risk::Finding> {
        let map: BTreeMap<&str, &RedteamCase> = cases.iter().map(|c| (c.key.as_str(), *c)).collect();
        outcomes
            .iter()
            .filter(|o| o.succeeded && !o.simulated && o.evaluation == EvaluationStatus::Evaluated)
            .filter_map(|o| {
                let case = map.get(o.case_key.as_str())?;
                let mut f = agf_core::risk::Finding::new(
                    tenant,
                    case.category.domain(),
                    case.severity,
                    target_name,
                    format!("红队：{}", case.title),
                    format!(
                        "红队用例 {} 在目标 {} 上得逞，命中信号: {}",
                        case.key,
                        target_name,
                        o.matched_signals.join(", ")
                    ),
                    case.remediation.clone(),
                );
                f.category = case.key.clone();
                f.asset_id = Some(o.target_asset_id);
                f.confidence = 0.9;
                f.source_origin = "redteam-observed".to_string();
                f.poc = case.turns.iter().map(|t| format!("[{}] {}", t.role, t.content)).collect::<Vec<_>>().join("\n");
                f.impact = Some(format!("绕过路径: {}", o.bypass_path.clone().unwrap_or_else(|| "未记录".into())));
                f.evidence_level = o.evidence_level;
                f.evidence.push(agf_core::risk::Evidence::new(
                    "EV-0001",
                    "redteam",
                    format!("用例 {} 命中信号 {}", case.key, o.matched_signals.join(",")),
                    agf_core::secret::content_hash(&case.key),
                ));
                f.evidence_refs = vec!["EV-0001".to_string()];
                Some(f)
            })
            .collect()
    }
}

/// 生成绕过路径的可读描述。
#[must_use]
pub fn describe_bypass(case: &RedteamCase, signals: &[String]) -> String {
    let mode = match case.mode {
        ExecutionMode::SingleTurn => "单轮提示词",
        ExecutionMode::MultiTurn => "多轮渐进诱导",
        ExecutionMode::ToolSequence => "工具调用序列",
        ExecutionMode::DocumentPoison => "文档投毒检索",
        ExecutionMode::MultiAgent => "多 Agent 对抗",
    };
    format!("通过「{}」手法（{}）绕过防护，命中信号 [{}]", case.title, mode, signals.join(", "))
}

/// 渲染 Markdown 报告。
#[must_use]
pub fn render_markdown(campaign: &RedteamCampaign, outcomes: &[RedteamOutcome], report: &RedteamReport) -> String {
    let mut s = String::new();
    let evaluated = outcomes.iter().filter(|o| o.evaluation == EvaluationStatus::Evaluated).count();
    let rate = if evaluated == 0 {
        "未知".into()
    } else {
        let successes = u32::try_from(outcomes.iter().filter(|o| o.succeeded).count()).unwrap_or(0);
        format!("{:.1}%", f64::from(successes) / f64::from(u32::try_from(evaluated).unwrap_or(1)) * 100.0)
    };
    s.push_str(&format!("# {}\n\n", report.title));
    s.push_str(&format!(
        "- 目标: {}\n- 发起人: {}\n- 用例总数: {}\n- 已执行: {}\n- 得逞: {}\n- 成功率（已判定用例）: {}\n- CI 卡点: {}\n\n",
        campaign.target_agent_ids.first().map_or_else(|| "<未指定>".to_string(), std::string::ToString::to_string),
        campaign.launched_by,
        report.total_cases,
        report.executed,
        report.succeeded,
        rate,
        if !campaign.ci_gate { "未启用" } else if report.ci_passed { "通过" } else { "未通过" }
    ));
    s.push_str(&format!(
        "- 已判定: {}\n- 无法判定: {}\n- 执行失败: {}\n\n",
        report.evaluated_cases, report.inconclusive_cases, report.failed_cases
    ));
    s.push_str(&format!("## 结论\n\n{}\n\n", report.verdict));

    s.push_str("## 分类成功率\n\n| 类别 | 执行 | 得逞 | 成功率 |\n|---|---|---|---|\n");
    for stat in &report.by_category {
        s.push_str(&format!(
            "| {} | {} | {} | {:.0}% |\n",
            stat.category.as_str(),
            stat.executed,
            stat.succeeded,
            stat.success_rate() * 100.0
        ));
    }
    s.push('\n');

    if !report.bypass_paths.is_empty() {
        s.push_str("## 绕过路径\n\n");
        for p in &report.bypass_paths {
            s.push_str(&format!("- {p}\n"));
        }
        s.push('\n');
    }

    if !report.remediations.is_empty() {
        s.push_str("## 修复建议\n\n");
        for r in &report.remediations {
            s.push_str(&format!("- {r}\n"));
        }
        s.push('\n');
    }

    s.push_str("## 用例明细\n\n| 用例 | 类别 | 等级 | 结果 | 命中信号 |\n|---|---|---|---|---|\n");
    for o in outcomes {
        s.push_str(&format!(
            "| {} {} | {} | {} | {} | {} |\n",
            o.case_key,
            o.case_title,
            o.category.as_str(),
            o.severity,
            match o.evaluation {
                EvaluationStatus::ExecutionError => "执行失败",
                EvaluationStatus::Inconclusive | EvaluationStatus::Unknown => "无法判定",
                EvaluationStatus::Evaluated if o.succeeded => "命中成功信号",
                EvaluationStatus::Evaluated => "未观测到成功信号",
            },
            if o.matched_signals.is_empty() { "-".to_string() } else { o.matched_signals.join(",") }
        ));
    }
    if outcomes.iter().any(|o| o.simulated) {
        s.push_str("\n> 注意：本次执行使用**本地模拟目标**（`AGF_MOCK_MODE=1`），成功率仅用于演示链路；真实红队需接入实际 Agent/MCP 环境（见 docs/pending-verification.md）。\n");
    }
    s
}

/// 计算类别覆盖率（报告用）。
#[must_use]
pub fn category_coverage(outcomes: &[RedteamOutcome]) -> BTreeMap<String, (usize, usize)> {
    let mut map: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for o in outcomes.iter().filter(|o| o.evaluation == EvaluationStatus::Evaluated) {
        let e = map.entry(o.category.as_str().to_string()).or_insert((0, 0));
        e.0 += 1;
        if o.succeeded {
            e.1 += 1;
        }
    }
    map
}

/// 域映射辅助：攻击类别 → 风险域（报告分层用）。
#[must_use]
pub fn domain_of(category: AttackCategory) -> RiskDomain {
    category.domain()
}

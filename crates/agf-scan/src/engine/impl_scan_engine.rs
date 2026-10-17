//! 由 `engine.rs` 拆分：`ScanEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

impl ScanEngine {
    /// 构造（不带模型研判）。
    #[must_use]
    pub fn new() -> Self {
        Self { detector: DomainDetector::new(), judge: None }
    }

    /// 装配模型研判器。
    #[must_use]
    pub fn with_judge(mut self, judge: std::sync::Arc<dyn LlmJudge>) -> Self {
        self.judge = Some(judge);
        self
    }

    /// 域检测器引用。
    #[must_use]
    pub const fn detector(&self) -> &DomainDetector {
        &self.detector
    }

    /// 执行一次扫描。
    ///
    /// # Errors
    /// 规则编译失败（规则包在加载期已校验，正常不会发生）。
    pub async fn scan(&self, tenant: TenantId, pack: &RulePack, req: &ScanRequest) -> DomainResult<ScanResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();
        let mut domain_reports: Vec<DomainReport> = Vec::new();
        let mut rule_hits: BTreeMap<String, usize> = BTreeMap::new();
        let mut judgements: Vec<LlmJudgement> = Vec::new();
        let mut llm_mocked = false;
        let mut judgement_failures = 0;

        for target in &req.targets {
            let domains: Vec<RiskDomain> =
                if req.domains.is_empty() { target.kind.default_domains().to_vec() } else { req.domains.clone() };

            // 1) 规则匹配（按灰度筛选适用规则）
            let rollout_id = target.asset_id.unwrap_or_else(|| {
                agf_core::ids::deterministic_id("agf.scan.rollout", &format!("{tenant}:{}", target.label))
            });
            let applicable = pack.applicable_to_asset(&rollout_id);
            let mut target_rule_hits: Vec<RuleHit> = Vec::new();
            for idx in applicable {
                let Some((rule, compiled)) = pack.iter_compiled().nth(idx) else { continue };
                // 域裁剪：只有落在本次扫描域的规则才评估（降低噪声）
                if !domains.contains(&rule.domain) || rule.target != target.kind.rule_target() {
                    continue;
                }
                let m = compiled.matches_with_flags(&target.text);
                if m.hit {
                    let hit = RuleHit {
                        rule_key: rule.key.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        domain: rule.domain,
                        action: rule.action,
                        confidence: crate::detector::hit_confidence(
                            crate::detector::base_confidence(rule.kind),
                            &m,
                            rule.severity,
                        ),
                        spans: m.spans.clone(),
                        note: m.note.clone(),
                        tags: rule.tags.clone(),
                        remediation: rule.remediation.clone(),
                        degraded: m.degraded,
                    };
                    *rule_hits.entry(hit.rule_key.clone()).or_insert(0) += 1;
                    target_rule_hits.push(hit);
                }
            }

            // 2) 域语义检测
            let mut reports = self.run_domains(target, &domains);
            super::rule_reports::append(&mut reports, &target_rule_hits);

            let mut target_judgements = BTreeMap::new();
            // 3) 模型二次研判
            if req.use_llm_judge {
                if let Some(judge) = &self.judge {
                    for r in &mut reports {
                        if r.hits.is_empty() {
                            continue;
                        }
                        match judge.judge(r.domain, &target.text, &r.hits).await {
                            Ok(j) => {
                                llm_mocked |= j.mocked;
                                target_judgements.insert(r.domain.as_str(), j.clone());
                                DomainDetector::apply_judgement(r, &j);
                                judgements.push(j);
                            }
                            Err(e) => {
                                judgement_failures += 1;
                                debug!(error = %e, domain = r.domain.as_str(), "模型研判失败，降级为仅规则判定");
                            }
                        }
                    }
                } else {
                    judgement_failures += reports.iter().filter(|r| !r.hits.is_empty()).count();
                }
            }

            // 4) 生成 finding
            for r in &reports {
                for hit in &r.hits {
                    if hit.verdict == DomainVerdict::Benign {
                        continue;
                    }
                    if !req.report_suspicious && hit.verdict == DomainVerdict::Suspicious {
                        continue;
                    }
                    let mut f = hit.to_finding(tenant, &target.label);
                    f.asset_id = target.asset_id.or(f.asset_id);
                    // 每条规则保留独立来源，避免把同域无关规则挂到另一个发现。
                    if let Some(rh) = target_rule_hits.iter().find(|rh| hit.key == format!("rule:{}", rh.rule_key)) {
                        f.rule_keys.push(rh.rule_key.clone());
                        f.evidence.push(agf_core::risk::Evidence::new(
                            "EV-R0001",
                            "rule",
                            rh.note.clone(),
                            rh.evidence_hash(),
                        ));
                    }
                    f.evidence_refs = f.evidence.iter().map(|e| e.code.clone()).collect();
                    if let Some(judgement) = target_judgements.get(r.domain.as_str()) {
                        if judgement.cited_evidence.is_empty() || judgement.cited_evidence.contains(&hit.key) {
                            let mut judgement = judgement.clone();
                            judgement.cited_evidence.clone_from(&f.evidence_refs);
                            f.llm_verdict = Some(judgement);
                        }
                    }
                    f.evidence_level =
                        if hit.confidence >= 0.85 { EvidenceLevel::Confirmed } else { EvidenceLevel::Partial };
                    findings.push(f);
                }
            }
            domain_reports.extend(reports);
        }

        // 评分只统计最终登记的结果；被研判为良性或过滤的疑似不再抬高风险。
        let scored_reports = super::rule_reports::reportable(&domain_reports, req.report_suspicious);
        let risk_score = aggregate_risk_score(&scored_reports);
        let max_severity = findings.iter().map(|finding| finding.severity).max().unwrap_or(Severity::Info);
        let result = ScanResult {
            job_name: req.job_name.clone(),
            tenant_id: tenant,
            targets_scanned: req.targets.len(),
            rule_hits,
            domain_reports,
            findings,
            risk_score,
            max_severity,
            judgements: req.use_llm_judge.then_some(judgements),
            llm_mocked,
            judgement_failures,
            elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            scanned_at: Timestamp::now(),
        };
        info!(summary = %result.summary_line(), "扫描完成");
        Ok(result)
    }

    /// 对单个目标执行域检测。
    pub(crate) fn run_domains(&self, target: &ScanTarget, domains: &[RiskDomain]) -> Vec<DomainReport> {
        let mut out = Vec::new();
        for d in domains {
            let report = match d {
                RiskDomain::PromptAttack => self.detector.prompt_attack(&target.text),
                RiskDomain::CredentialLeak => self.detector.credential_leak(&[Some(&target.text)]),
                RiskDomain::RagPoison => self.detector.rag_poison(&target.text),
                RiskDomain::ToolAbuse => self.detector.tool_abuse(
                    target.tool_name.as_deref().unwrap_or("unknown_tool"),
                    &target.text,
                    target.tool_traits.as_ref(),
                ),
                RiskDomain::ModelData => self.detector.model_data(&target.text, target.data_class),
            };
            out.push(report);
        }
        out
    }
}

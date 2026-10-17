#![allow(clippy::unwrap_used)] // 仅用于测试断言；生产扫描使用 DomainResult。
use super::*;

fn marker_rule(target: RuleTarget) -> RuleDefinition {
    let mut rule = rule("CUSTOM-SCOPE", RiskDomain::PromptAttack, "local-marker-42", "local-marker-42");
    rule.target = target;
    rule
}

#[tokio::test]
async fn standalone_rule_hits_produce_asset_bound_findings_and_risk() {
    let pack = RulePackLoader::strict().load_inline(vec![marker_rule(RuleTarget::Prompt)]).unwrap();
    let first = Id::new();
    let second = Id::new();
    let request = ScanRequest::new("custom")
        .with_target(ScanTarget::new("first", ScanTargetKind::Prompt, "local-marker-42").with_asset(first))
        .with_target(ScanTarget::new("second", ScanTargetKind::Prompt, "local-marker-42").with_asset(second));
    let result = ScanEngine::new().scan(TenantId::default_tenant(), &pack, &request).await.unwrap();
    assert_eq!(result.rule_hits["CUSTOM-SCOPE"], 2);
    assert_eq!(result.findings.len(), 2);
    assert_eq!(result.findings[0].asset_id, Some(first));
    assert_eq!(result.findings[1].asset_id, Some(second));
    assert!(result.risk_score > 0);
    assert_eq!(result.max_severity, Severity::High);
    for finding in result.findings {
        assert_eq!(finding.rule_keys, ["CUSTOM-SCOPE"]);
        assert!(!finding.evidence.is_empty());
        assert_eq!(finding.source_origin, "scan-confirmed");
    }
}

#[tokio::test]
async fn rules_only_match_their_declared_target() {
    let cases = [
        (RuleTarget::Prompt, ScanTargetKind::Prompt),
        (RuleTarget::ModelOutput, ScanTargetKind::ModelOutput),
        (RuleTarget::ToolArguments, ScanTargetKind::ToolArguments),
        (RuleTarget::ToolResult, ScanTargetKind::ToolResult),
        (RuleTarget::McpRequest, ScanTargetKind::McpRequest),
        (RuleTarget::McpResponse, ScanTargetKind::McpResponse),
        (RuleTarget::EventPayload, ScanTargetKind::LogPayload),
        (RuleTarget::Document, ScanTargetKind::Document),
        (RuleTarget::Config, ScanTargetKind::Config),
        (RuleTarget::FileContent, ScanTargetKind::FileContent),
        (RuleTarget::ToolDefinition, ScanTargetKind::ToolDefinition),
    ];
    for (target, kind) in cases {
        let pack = RulePackLoader::strict().load_inline(vec![marker_rule(target)]).unwrap();
        let wrong = if kind == ScanTargetKind::Prompt { ScanTargetKind::Config } else { ScanTargetKind::Prompt };
        let request = ScanRequest {
            domains: vec![RiskDomain::PromptAttack],
            ..ScanRequest::new("scope")
                .with_target(ScanTarget::new("matching", kind, "local-marker-42"))
                .with_target(ScanTarget::new("other-kind", wrong, "local-marker-42"))
        };
        let result = ScanEngine::new().scan(TenantId::default_tenant(), &pack, &request).await.unwrap();
        assert_eq!(result.rule_hits["CUSTOM-SCOPE"], 1, "{target:?}");
        assert_eq!(result.findings.len(), 1, "{target:?}");
    }
}

#[tokio::test]
async fn excluded_domains_cannot_bypass_disabled_or_zero_rollout() {
    for (enabled, rollout) in [(false, 100), (true, 0), (true, 100)] {
        let mut rule = marker_rule(RuleTarget::Prompt);
        rule.enabled = enabled;
        rule.rollout_percent = rollout;
        let pack = RulePackLoader::strict().load_inline(vec![rule]).unwrap();
        let request = ScanRequest {
            domains: vec![RiskDomain::CredentialLeak],
            ..ScanRequest::new("excluded").with_target(ScanTarget::new("p", ScanTargetKind::Prompt, "local-marker-42"))
        };
        let result = ScanEngine::new().scan(TenantId::default_tenant(), &pack, &request).await.unwrap();
        assert!(result.rule_hits.is_empty());
        assert!(result.findings.is_empty());
        assert_eq!(result.risk_score, 0);
    }
}

#[tokio::test]
async fn custom_hits_are_judged_and_filtered_suspicions_do_not_inflate_risk() {
    struct BenignJudge;
    #[async_trait]
    impl LlmJudge for BenignJudge {
        async fn judge(&self, _: RiskDomain, _: &str, hits: &[DomainHit]) -> DomainResult<LlmJudgement> {
            assert!(hits.iter().any(|hit| hit.key == "rule:CUSTOM-SCOPE"));
            Ok(LlmJudgement {
                verdict: Verdict::Benign,
                confidence: 0.99,
                rationale: "context is benign".into(),
                cited_evidence: hits.iter().map(|hit| hit.key.clone()).collect(),
                model: "unit-test".into(),
                mocked: true,
                judged_at: Timestamp::now(),
                raw_excerpt: None,
            })
        }
    }
    let pack = RulePackLoader::strict().load_inline(vec![marker_rule(RuleTarget::Prompt)]).unwrap();
    let mut request = ScanRequest::new("judge").with_llm_judge(true).with_target(ScanTarget::new(
        "p",
        ScanTargetKind::Prompt,
        "local-marker-42",
    ));
    // 模型判良性后降为疑似；严格扫描只登记确认命中。
    request.report_suspicious = false;
    let result = ScanEngine::new()
        .with_judge(std::sync::Arc::new(BenignJudge))
        .scan(TenantId::default_tenant(), &pack, &request)
        .await
        .unwrap();
    assert_eq!(result.rule_hits["CUSTOM-SCOPE"], 1);
    assert!(result.findings.is_empty());
    assert_eq!(result.risk_score, 0);
    assert_eq!(result.max_severity, Severity::Info);
}

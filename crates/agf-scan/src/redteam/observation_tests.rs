//! Failed and unsupported evaluations must never become negative security evidence.
#![allow(clippy::panic)]
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ObservedTarget;
#[async_trait]
impl TargetUnderTest for ObservedTarget {
    fn name(&self) -> &'static str {
        "observed-fixture"
    }
    fn capabilities(&self) -> Vec<String> {
        vec![]
    }
    fn asset_id(&self) -> Id {
        Id::nil()
    }
    async fn run_case(&self, _: &RedteamCase) -> DomainResult<Vec<String>> {
        Err(DomainError::Internal("Use observations".into()))
    }
    async fn observe_case(&self, case: &RedteamCase) -> DomainResult<TargetObservation> {
        match case.key.as_str() {
            "error" => Err(DomainError::Internal("must-not-leak-credential".into())),
            "missing" => Ok(TargetObservation::inconclusive("Required check unavailable")),
            "empty" => Ok(TargetObservation::evaluated(vec![], vec![])),
            "foreign" => Ok(TargetObservation::evaluated(
                vec!["undeclared".into()],
                vec![serde_json::json!({"role":"assistant","content":"fixture"})],
            )),
            "large" => Ok(TargetObservation::evaluated(vec![], vec![serde_json::json!({"content":"x".repeat(65537)})])),
            key => Ok(TargetObservation::evaluated(
                if key == "success" { vec!["marker_echo".into()] } else { vec![] },
                vec![serde_json::json!({"role":"assistant","content":key})],
            )),
        }
    }
}
fn cases(keys: &[&str]) -> Vec<RedteamCase> {
    keys.iter()
        .map(|key| super::tests::case(key, AttackCategory::Jailbreak, &["marker_echo"], &[], ExecutionMode::SingleTurn))
        .collect()
}
#[tokio::test]
async fn incomplete_evaluations_keep_evidence_and_close_ci_gate() {
    let rows = cases(&["success", "negative", "error", "missing", "empty", "foreign", "large"]);
    let cases = rows.iter().collect::<Vec<_>>();
    let result =
        CampaignRunner::new().run(TenantId::default_tenant(), "coverage", &cases, &ObservedTarget, "test", true).await;
    let Ok((campaign, outcomes, report)) = result else { panic!("fixture execution should produce a report") };
    assert_eq!(campaign.executed_cases, 7);
    assert_eq!(report.evaluated_cases, 2);
    assert_eq!(report.inconclusive_cases, 4);
    assert_eq!(report.failed_cases, 1);
    assert_eq!(report.succeeded, 1);
    assert!(!report.ci_passed);
    assert_eq!(report.by_category.iter().map(|v| v.executed).sum::<u32>(), 2);
    assert!(report.markdown.contains("50.0%"));
    assert!(report.markdown.contains("无法判定"));
    assert!(!report.markdown.contains("全部用例被成功拦截"));
    assert_eq!(outcomes[0].evidence_level, EvidenceLevel::Partial);
    let persisted = outcomes[2].to_result(campaign.tenant_id, campaign.id);
    assert_eq!(persisted.evaluation, EvaluationStatus::ExecutionError);
    assert!(!serde_json::to_string(&persisted).unwrap_or_default().contains("must-not-leak"));
    assert!(outcomes[4..].iter().all(|row| !row.succeeded && row.evaluation == EvaluationStatus::Inconclusive));
    assert!(outcomes[6].transcript.is_empty());
    assert_eq!(outcomes[0].to_result(campaign.tenant_id, campaign.id).transcript, outcomes[0].transcript);
}
#[tokio::test]
async fn unsupported_only_and_empty_runs_never_pass_enabled_ci() {
    for keys in [vec!["missing"], vec![]] {
        let rows = cases(&keys);
        let result = CampaignRunner::new()
            .run(
                TenantId::default_tenant(),
                "unsupported",
                &rows.iter().collect::<Vec<_>>(),
                &ObservedTarget,
                "test",
                true,
            )
            .await;
        let Ok((_, _, report)) = result else { panic!("report expected") };
        assert_eq!(report.evaluated_cases, 0);
        assert!(!report.ci_passed);
        assert!(report.markdown.contains("未知"));
    }
}
#[tokio::test]
async fn simulator_missing_tools_is_inconclusive_and_never_a_finding() {
    let rows = [super::tests::case(
        "missing-tool",
        AttackCategory::ToolAbuse,
        &["marker_echo"],
        &["never-present"],
        ExecutionMode::ToolSequence,
    )];
    let refs = rows.iter().collect::<Vec<_>>();
    let runner = CampaignRunner::new();
    let result = runner
        .run(TenantId::default_tenant(), "missing", &refs, &RedteamSimulator::new("fixture", 100), "test", true)
        .await;
    let Ok((_, outcomes, report)) = result else { panic!("report expected") };
    assert_eq!(outcomes[0].evaluation, EvaluationStatus::Inconclusive);
    assert!(!report.ci_passed);
    assert!(runner.to_findings(TenantId::default_tenant(), &refs, &outcomes, "fixture").is_empty());
}
struct LegacyTarget(AtomicUsize);
#[async_trait]
impl TargetUnderTest for LegacyTarget {
    fn name(&self) -> &'static str {
        "legacy"
    }
    fn capabilities(&self) -> Vec<String> {
        vec![]
    }
    fn asset_id(&self) -> Id {
        Id::nil()
    }
    async fn run_case(&self, _: &RedteamCase) -> DomainResult<Vec<String>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
}
#[tokio::test]
async fn uninstrumented_real_adapter_is_not_silently_treated_as_successful_evaluation() {
    let target = LegacyTarget(AtomicUsize::new(0));
    let rows = cases(&["legacy"]);
    let result = CampaignRunner::new()
        .run(TenantId::default_tenant(), "legacy", &rows.iter().collect::<Vec<_>>(), &target, "test", true)
        .await;
    let Ok((_, outcomes, report)) = result else { panic!("report expected") };
    assert_eq!(target.0.load(Ordering::SeqCst), 0);
    assert_eq!(outcomes[0].evaluation, EvaluationStatus::Inconclusive);
    assert!(!report.ci_passed);
}

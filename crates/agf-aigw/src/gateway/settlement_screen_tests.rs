//! Actual controlled Block verdict and production KeywordScreen redaction preserve provider usage.
use super::*;
use crate::screen::ScreenRule;
use agf_core::enums::RiskDomain;

/// A real configured ContentScreen exercises the shared Block branch. The HTTP
/// registry still uses KeywordScreen, whose responses redact credentials only.
#[derive(Debug)]
struct OutputRule;
impl ContentScreen for OutputRule {
    fn screen_request(&self, _: &ChatRequest) -> ScreenOutcome {
        ScreenOutcome::allow()
    }
    fn screen_response(&self, response: &ChatResponse) -> ScreenOutcome {
        if response.text_content().contains("owned-output-block") {
            ScreenOutcome::block(
                ScreenRule::new("owned.output-block", RiskDomain::CredentialLeak, "owned response rule", "owned"),
                "owned response rule rejected the output",
            )
        } else {
            ScreenOutcome::allow()
        }
    }
    fn name(&self) -> &'static str {
        "owned-output-rule"
    }
}

fn reply(text: &str) -> DomainResult<ChatResponse> {
    crate::convert::from_openai_response(&serde_json::json!({
        "id":"owned-response","model":"owned-model","object":"chat.completion","created":1,
        "choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":96,"completion_tokens":4,"total_tokens":100}
    }))
}

#[test]
fn actual_block_flag_preserves_paid_usage_and_the_real_rule_id() -> DomainResult<()> {
    let gateway = AiGateway::new(Vec::new()).with_screen(Arc::new(OutputRule));
    let mut response = reply("owned-output-block")?;
    let original = response.usage;
    let summary = gateway.process_response(&mut response, ScreeningSummary::default(), 64)?;
    assert!(summary.response_blocked);
    assert_eq!(summary.response_rules, vec!["owned.output-block"]);
    assert_eq!(response.usage, original);
    assert_eq!(response.usage.total(), 100);
    assert!(!response.text_content().contains("owned-output-block"));
    assert!(response.raw.is_none());
    Ok(())
}

#[test]
fn actual_redaction_remains_nonblocked_even_when_content_and_finish_reason_change() -> DomainResult<()> {
    let gateway = AiGateway::new(Vec::new()).with_screen(Arc::new(KeywordScreen::new()));
    let mut response = reply("sk-proj-abcdefghijklmnopqrstuvwx")?;
    let original = response.usage;
    let summary = gateway.process_response(&mut response, ScreeningSummary::default(), 64)?;
    assert!(summary.mutated);
    assert!(!summary.response_blocked);
    assert!(summary.response_redactions > 0);
    assert_eq!(response.usage, original);
    assert_eq!(response.usage.total(), 100);
    assert!(response.raw.is_none());
    Ok(())
}

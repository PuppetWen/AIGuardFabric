//! Library regression coverage with mutable screens and a counted, offline provider.
use super::*;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::screen::ScreenRule;
use crate::wire::{FinishReason, ToolCall};
use agf_core::enums::RiskDomain;

const SYNTHETIC_CREDENTIAL: &str = "sk-proj-abcdefghijklmnopqrstuvwx";

#[derive(Debug, Default)]
struct MutableScreen {
    mode: AtomicU8,
    requests: AtomicUsize,
}

impl ContentScreen for MutableScreen {
    fn screen_request(&self, _request: &ChatRequest) -> ScreenOutcome {
        self.requests.fetch_add(1, Ordering::SeqCst);
        ScreenOutcome::allow()
    }

    fn screen_response(&self, response: &ChatResponse) -> ScreenOutcome {
        match self.mode.load(Ordering::SeqCst) {
            1 => ScreenOutcome::block(
                ScreenRule::new("cache-output-test", RiskDomain::CredentialLeak, "synthetic test", "***"),
                "synthetic current response rule",
            ),
            mode @ (2 | 3) => {
                let mut outcome = KeywordScreen::new().screen_response(response);
                // A rewrite owns content, not the provider's actual usage.
                if let Some(rewritten) = &mut outcome.response {
                    rewritten.usage = Usage::default();
                }
                if mode == 3 {
                    outcome.response = None;
                }
                outcome
            }
            _ => ScreenOutcome::allow(),
        }
    }

    fn name(&self) -> &'static str {
        "mutable-cache-output-test"
    }
}

#[derive(Debug)]
struct CountedProvider {
    inner: FakeProvider,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl ProviderAdapter for CountedProvider {
    fn adapter_name(&self) -> &str {
        self.inner.adapter_name()
    }

    fn provider_descriptor(&self) -> ProviderDescriptor {
        self.inner.provider_descriptor()
    }

    async fn complete(&self, request: &ChatRequest) -> DomainResult<ChatResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut response = self.inner.complete(request).await?;
        response.raw = Some(serde_json::json!({"synthetic_private": SYNTHETIC_CREDENTIAL}));
        response.message.tool_calls.push(ToolCall::new(
            "synthetic-call",
            "synthetic-tool",
            serde_json::json!({"synthetic_private": SYNTHETIC_CREDENTIAL}),
        ));
        Ok(response)
    }

    async fn stream(&self, request: &ChatRequest) -> DomainResult<ProviderStream> {
        self.inner.stream(request).await
    }

    async fn health(&self) -> DomainResult<agf_core::adapter::AdapterHealth> {
        self.inner.health().await
    }

    fn circuit(&self) -> agf_core::adapter::CircuitSnapshot {
        self.inner.circuit()
    }

    fn record_failure(&self, error: &str) {
        self.inner.record_failure(error);
    }

    fn record_success(&self) {
        self.inner.record_success();
    }
}

fn fixture() -> (AiGateway, ModelEndpoint, Arc<MutableScreen>, Arc<CountedProvider>) {
    let ep = endpoint("current-output", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let screen = Arc::new(MutableScreen::default());
    let provider = Arc::new(CountedProvider {
        inner: FakeProvider::ok("counted-output", SYNTHETIC_CREDENTIAL),
        calls: AtomicUsize::new(0),
    });
    let gateway = gateway_with_fakes(vec![ep.clone()], vec![provider.clone()]).with_screen(screen.clone());
    (gateway, ep, screen, provider)
}

fn request(endpoint: &ModelEndpoint) -> ChatRequest {
    let mut request = ChatRequest::simple(endpoint.model.clone(), "analyze synthetic event");
    request.max_tokens = Some(32);
    request
}

#[tokio::test]
async fn exact_hit_obeys_new_block_rule_without_calling_provider_again() {
    let (gateway, ep, screen, provider) = fixture();
    let ctx = CallContext::new(ep.tenant_id);
    let req = request(&ep);
    let first = gateway.chat(ctx.clone(), req.clone()).await.unwrap();
    assert!(!first.cached);
    assert_eq!(first.cost_micro, 360);
    assert!(first.response.raw.is_some());
    assert_eq!(first.response.message.tool_calls.len(), 1);

    screen.mode.store(1, Ordering::SeqCst);
    let second = gateway.chat(ctx, req).await.unwrap();
    assert!(second.cached);
    assert_eq!(second.response.finish_reason, FinishReason::ContentFilter);
    assert_eq!(second.screening.response_rules, ["cache-output-test"]);
    assert!(second.screening.mutated);
    assert!(!second.response.text_content().contains(SYNTHETIC_CREDENTIAL));
    assert!(second.response.raw.is_none());
    assert!(second.response.message.tool_calls.is_empty());
    assert_eq!(second.response.usage, first.response.usage);
    assert_eq!(second.usage_record.cost_micro, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(screen.requests.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.meter().snapshot().total.cost_micro, 360);
    assert_eq!(gateway.meter().snapshot().total.calls, 2);

    // A blocked delivery does not replace the original exact entry with filtered text.
    screen.mode.store(0, Ordering::SeqCst);
    let third = gateway.chat(CallContext::new(ep.tenant_id), request(&ep)).await.unwrap();
    assert!(third.cached);
    assert_eq!(third.response.text_content(), SYNTHETIC_CREDENTIAL);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_hit_redacts_current_content_and_clears_raw_tools_without_erasing_usage() {
    let (gateway, ep, screen, provider) = fixture();
    let ctx = CallContext::new(ep.tenant_id);
    let req = request(&ep);
    let first = gateway.chat(ctx.clone(), req.clone()).await.unwrap();
    screen.mode.store(2, Ordering::SeqCst);
    let second = gateway.chat(ctx, req).await.unwrap();
    assert!(second.cached);
    assert!(second.screening.response_redactions > 0);
    assert_eq!(second.screening.response_rules, ["redact"]);
    assert!(!second.response.text_content().contains(SYNTHETIC_CREDENTIAL));
    assert!(second.response.raw.is_none());
    assert!(second.response.message.tool_calls.is_empty());
    assert_eq!(second.response.usage, first.response.usage);
    assert_eq!(second.usage, Usage::new(100, 20, 0));
    assert_eq!(second.usage_record.prompt_tokens, 100);
    assert_eq!(second.usage_record.completion_tokens, 20);
    assert_eq!(second.cost_micro, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_redact_without_replacement_cannot_return_the_original_sensitive_content() {
    let (gateway, ep, screen, provider) = fixture();
    let ctx = CallContext::new(ep.tenant_id);
    let req = request(&ep);
    let first = gateway.chat(ctx.clone(), req.clone()).await.unwrap();
    screen.mode.store(3, Ordering::SeqCst);
    let second = gateway.chat(ctx, req).await.unwrap();
    assert!(second.cached);
    assert!(second.screening.response_redactions > 0);
    assert_eq!(second.response.finish_reason, FinishReason::ContentFilter);
    assert!(!second.response.text_content().contains(SYNTHETIC_CREDENTIAL));
    assert!(second.response.raw.is_none());
    assert!(second.response.message.tool_calls.is_empty());
    assert_eq!(second.response.usage, first.response.usage);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fresh_blocked_response_still_bills_actual_provider_usage() {
    let (gateway, ep, screen, provider) = fixture();
    screen.mode.store(1, Ordering::SeqCst);
    let response = gateway.chat(CallContext::new(ep.tenant_id), request(&ep)).await.unwrap();
    assert!(!response.cached);
    assert_eq!(response.response.finish_reason, FinishReason::ContentFilter);
    assert_eq!(response.usage, Usage::new(100, 20, 0));
    assert_eq!(response.cost_micro, 360);
    assert_eq!(response.usage_record.cost_micro, 360);
    assert_eq!(gateway.meter().snapshot().total.cost_micro, 360);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.cache().len(), Some(0));
}

#[tokio::test]
async fn fresh_redaction_cannot_replace_paid_usage_with_rewritten_zero_usage() {
    let (gateway, ep, screen, provider) = fixture();
    screen.mode.store(2, Ordering::SeqCst);
    let response = gateway.chat(CallContext::new(ep.tenant_id), request(&ep)).await.unwrap();
    assert!(!response.cached);
    assert!(response.screening.response_redactions > 0);
    assert_eq!(response.usage, Usage::new(100, 20, 0));
    assert_eq!(response.response.usage, response.usage);
    assert_eq!(response.cost_micro, 360);
    assert_eq!(response.usage_record.cost_micro, 360);
    assert!(response.response.raw.is_none());
    assert!(response.response.message.tool_calls.is_empty());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_entries_apply_current_token_and_encoded_response_limits() {
    for case in ["tokens", "raw", "canonical-with-small-raw"] {
        let (gateway, ep, _screen, provider) = fixture();
        let ctx = CallContext::new(ep.tenant_id);
        let mut req = request(&ep);
        req.max_tokens = Some(8);
        let candidate = gateway.pick_cache_candidate(&ctx, &req, &[&ep]).unwrap();
        let mut response = ChatResponse::text(ep.model.clone(), "synthetic cached reply", Usage::new(100, 20, 0));
        if case != "tokens" {
            response.usage.completion_tokens = 2;
            let oversized = "x".repeat(4 * 1024 * 1024);
            if case == "raw" {
                response.raw = Some(serde_json::json!({"synthetic": oversized}));
            } else {
                response.message.content = MessageContent::text(oversized);
                response.raw = Some(serde_json::json!({"synthetic": "small"}));
            }
        }
        let original_usage = response.usage;
        gateway
            .cache()
            .put(CachedResponse::from_response(ctx.tenant, candidate.1, &ep, response, 60), 60)
            .await
            .unwrap();
        let result = gateway.chat(ctx, req).await.unwrap();
        assert!(result.cached, "case: {case}");
        assert_eq!(result.response.finish_reason, FinishReason::ContentFilter);
        assert_eq!(result.screening.response_rules, ["gateway-output-limit"]);
        assert!(result.response.raw.is_none());
        assert!(result.response.message.tool_calls.is_empty());
        assert_eq!(result.response.usage, original_usage);
        assert_eq!(result.cost_micro, 0);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }
}

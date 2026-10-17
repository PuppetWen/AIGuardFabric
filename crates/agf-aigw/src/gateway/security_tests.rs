use super::tests::{FakeProvider, endpoint, gateway_with_fakes};
use super::*;

#[derive(Debug)]
struct BlockOutput;
impl crate::screen::ContentScreen for BlockOutput {
    fn name(&self) -> &'static str {
        "test-response-block"
    }
    fn screen_request(&self, _: &ChatRequest) -> ScreenOutcome {
        ScreenOutcome::allow()
    }
    fn screen_response(&self, _: &ChatResponse) -> ScreenOutcome {
        ScreenOutcome::block(
            crate::screen::ScreenRule::new(
                "output-test",
                agf_core::enums::RiskDomain::CredentialLeak,
                "测试输出阻断",
                "masked",
            ),
            "不得向下游发送原始分片",
        )
    }
}

#[tokio::test]
async fn auto_routing_rewrites_model_and_screened_stream_never_leaks_original_text() {
    let ep = endpoint("selected", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let gateway = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("upstream", "原始机密"))]);
    let response = gateway.chat(CallContext::new(ep.tenant_id), ChatRequest::simple("", "hello")).await.unwrap();
    assert_eq!(response.response.model, ep.model);
    let gateway = gateway.with_screen(Arc::new(BlockOutput));
    let mut request = ChatRequest::simple("", "hello");
    request.stream = true;
    let stream = gateway.chat_stream(CallContext::new(ep.tenant_id), request).await.unwrap();
    let chunks: Vec<_> = Box::pin(stream).collect().await;
    let text: String = chunks.iter().map(|row| row.as_ref().unwrap().delta.content.as_str()).collect();
    assert!(!text.contains("假回复"));
    assert!(!text.contains("原始机密"));
    assert!(
        chunks.iter().any(|row| row.as_ref().unwrap().finish_reason == Some(crate::wire::FinishReason::ContentFilter))
    );
}

#[tokio::test]
async fn oversized_nonstream_output_is_masked_but_actual_usage_is_metered() {
    let ep = endpoint("limited", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let gateway = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("upstream", "secret-output"))]);
    let mut request = ChatRequest::simple(ep.model.clone(), "hello");
    request.max_tokens = Some(8);
    let result = gateway.chat(CallContext::new(ep.tenant_id), request).await.unwrap();
    assert!(result.screening.response_rules.contains(&"gateway-output-limit".to_string()));
    assert!(!result.response.text_content().contains("secret-output"));
    assert!(result.response.raw.is_none());
    assert_eq!(result.usage.completion_tokens, 20);
    assert_eq!(gateway.meter().snapshot().total.calls, 1);
    assert_eq!(gateway.cache_stats().hits, 0);
}

#[tokio::test]
async fn oversized_stream_usage_is_rejected_and_metered() {
    let ep = endpoint("limited-stream", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let gateway = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("upstream", "unused"))]);
    let mut request = ChatRequest::simple(ep.model.clone(), "hello");
    request.stream = true;
    request.max_tokens = Some(8);
    let (metadata, stream) = gateway.chat_stream_with_metadata(CallContext::new(ep.tenant_id), request).await.unwrap();
    let chunks: Vec<_> = stream.collect().await;
    assert!(chunks.iter().any(Result::is_err));
    let record = metadata.usage.await.unwrap();
    assert_eq!(record.completion_tokens, 20);
    assert_eq!(gateway.meter().snapshot().total.calls, 1);
}

#[test]
fn native_thinking_with_a_credential_is_blocked_without_returning_the_signed_raw_body() {
    let ep = endpoint("native-output", LlmProvider::Anthropic, false, true, Some(Id::new()));
    let gateway = gateway_with_fakes(vec![ep], vec![Arc::new(FakeProvider::ok("upstream", "unused"))])
        .with_screen(Arc::new(KeywordScreen::new()));
    let raw = serde_json::json!({"type":"message","content":[
        {"type":"thinking","thinking":"sk-proj-abcdefghijklmnopqrstuvwx","signature":"signed"},
        {"type":"text","text":"visible"}],"usage":{"input_tokens":2,"output_tokens":3}});
    let mut response = crate::convert::from_anthropic_response(&raw).unwrap();
    let summary = gateway.screen_response(&mut response, ScreeningSummary::default());
    assert!(summary.mutated);
    assert!(response.raw.is_none());
    assert!(!response.text_content().contains("sk-proj-abcdefghijklmnopqrstuvwx"));
    assert!(response.message.tool_calls.is_empty());
}

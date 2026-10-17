//! Shared output safety for provider responses and exact cache hits.
use super::*;

impl AiGateway {
    /// Keep actual provider usage even when a screen rewrites the reply.
    pub(crate) fn process_response(
        &self,
        response: &mut ChatResponse,
        summary: ScreeningSummary,
        max_completion: u64,
    ) -> DomainResult<ScreeningSummary> {
        let usage = response.usage;
        let mut summary = self.screen_response(response, summary);
        response.usage = usage;
        // Both canonical content/tools and native raw output are part of this bound.
        let output_bytes = serde_json::to_vec(response)?.len();
        if usage.completion_tokens > max_completion || output_bytes > 4 * 1024 * 1024 {
            summary.response_rules.push("gateway-output-limit".into());
            summary.mutated = true;
            response.message.content = MessageContent::text("模型上游输出超过请求或安全上限");
            response.message.tool_calls.clear();
            response.raw = None;
            response.finish_reason = crate::wire::FinishReason::ContentFilter;
        }
        Ok(summary)
    }
    /// 对响应做后置过滤，并把结果写回 `response`。
    pub(crate) fn screen_response(
        &self,
        response: &mut ChatResponse,
        mut summary: ScreeningSummary,
    ) -> ScreeningSummary {
        if self.screen.is_noop() {
            return summary;
        }
        let native_view = native_response_view(response);
        let outcome: ScreenOutcome = self.screen.screen_response(native_view.as_ref().unwrap_or(response));
        match outcome.verdict {
            ScreenVerdict::Block { reason, rule } => {
                summary.response_blocked = true;
                // 后置阻断：用安全话术替换回复，保留计量与审计（不丢证据）
                warn!(rule = %rule.id, "响应被内容安全后置过滤阻断，已替换为安全话术");
                summary.response_rules.push(rule.id.clone());
                summary.mutated = true;
                response.message.content = MessageContent::text(crate::screen::safe_response_text(&rule.id));
                response.message.tool_calls.clear();
                response.raw = None;
                response.finish_reason = crate::wire::FinishReason::ContentFilter;
                debug!(reason = %reason, "后置阻断原因已记录");
            }
            ScreenVerdict::Redact(items) => {
                summary.response_rules.push("redact".to_string());
                summary.response_redactions = items.len();
                summary.mutated = true;
                if native_view.is_some() {
                    response.message.content =
                        MessageContent::text(crate::screen::safe_response_text("native-output-redacted"));
                    response.message.tool_calls.clear();
                    response.finish_reason = crate::wire::FinishReason::ContentFilter;
                } else if let Some(rewritten) = outcome.response {
                    *response = rewritten;
                } else {
                    response.message.content =
                        MessageContent::text(crate::screen::safe_response_text("output-redacted"));
                    response.finish_reason = crate::wire::FinishReason::ContentFilter;
                }
                response.message.tool_calls.clear();
                response.raw = None;
            }
            ScreenVerdict::Allow => {}
        }
        summary
    }
}

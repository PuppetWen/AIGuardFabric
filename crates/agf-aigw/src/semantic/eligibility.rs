use crate::{ChatRequest, MessageContent, ResponseFormat, Role};
use agf_core::enums::DataClass;
use serde_json::Value;

/// Strictly eligible plain request. Debug never exposes prompt or fixed system instructions.
#[derive(Clone)]
pub struct EligibleSemanticRequest {
    user_text: String,
    fixed: Value,
}

impl std::fmt::Debug for EligibleSemanticRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EligibleSemanticRequest(<redacted>)")
    }
}

impl EligibleSemanticRequest {
    /// Only the user text is sent to the separately approved embedding provider.
    pub fn user_text(&self) -> &str {
        &self.user_text
    }
    /// Canonical fixed system/messages/nonprompt data to bind into the server HMAC domain.
    pub const fn fixed_request(&self) -> &Value {
        &self.fixed
    }
}

/// Inspect both validated canonical request and its original wire body before unknown fields vanish.
///
/// The supplied data class/placement must come from current service authorization, not wire fields.
/// Bypass does not reject a previously supported legacy chat or change the exact-cache profile.
pub fn inspect_request(
    request: &ChatRequest,
    original_wire: &Value,
    data_class: DataClass,
    internal_placement_verified: bool,
) -> Option<EligibleSemanticRequest> {
    if request.temperature != Some(0.0)
        || request.stream
        || request.anthropic_native.is_some()
        || !request.tools.is_empty()
        || request.tool_choice.is_some()
        || !matches!(request.response_format.as_ref(), None | Some(ResponseFormat::Text))
        || request.top_p.is_some_and(|value| !value.is_finite())
        || !matches!(data_class, DataClass::Public | DataClass::Internal)
        || data_class == DataClass::Internal && !internal_placement_verified
        || request.model.is_empty()
        || request.messages.is_empty()
        || request.messages.len() > 9
    {
        return None;
    }
    let raw = original_wire.as_object()?;
    if raw.keys().any(|key| {
        !matches!(
            key.as_str(),
            "model"
                | "messages"
                | "temperature"
                | "max_tokens"
                | "top_p"
                | "stop"
                | "tool_choice"
                | "stream"
                | "tools"
                | "response_format"
                | "user"
                | "metadata"
        )
    }) || raw.get("temperature")?.as_f64() != Some(0.0)
        || raw.get("model")?.as_str() != Some(request.model.as_str())
    {
        return None;
    }
    let raw_messages = raw.get("messages")?.as_array()?;
    if raw_messages.len() != request.messages.len() {
        return None;
    }
    let mut user = None;
    let mut bytes = 0usize;
    for (index, (message, raw)) in request.messages.iter().zip(raw_messages).enumerate() {
        let raw = raw.as_object()?;
        if raw.keys().any(|key| !matches!(key.as_str(), "role" | "content" | "tool_calls" | "tool_call_id" | "name"))
            || !message.tool_calls.is_empty()
            || message.tool_call_id.is_some()
        {
            return None;
        }
        let MessageContent::Text(text) = &message.content else {
            return None;
        };
        if text.is_empty()
            || raw.get("content")?.as_str() != Some(text.as_str())
            || raw.get("role") != serde_json::to_value(message.role).ok().as_ref()
        {
            return None;
        }
        bytes = bytes.checked_add(text.len())?;
        match message.role {
            Role::System if user.is_none() => {}
            Role::User if user.is_none() && index + 1 == request.messages.len() && text.len() <= 8192 => {
                user = Some(text.clone());
            }
            _ => return None,
        }
    }
    if bytes > 16 * 1024 {
        return None;
    }
    let user = user?;
    let mut fixed = serde_json::to_value(request).ok()?;
    let message = fixed.get_mut("messages")?.as_array_mut()?.last_mut()?;
    message["content"] = Value::Null;
    if serde_json::to_vec(&fixed).ok()?.len() > 16 * 1024 {
        return None;
    }
    Some(EligibleSemanticRequest { user_text: user, fixed })
}

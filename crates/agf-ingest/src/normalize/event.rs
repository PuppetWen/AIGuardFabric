//! 解析结果 → AGF-ECS `Event`：字段落地（`apply_field`）、未映射字段回收与 AI 高风险判定。

use super::*;

/// 从 [`ParseOutcome`] 构造 [`Event`]。
///
/// `raw_text` 是**原始载荷文本**（未经脱敏），用于计算 `raw_hash` 与保真 `raw`；
/// 脱敏由 [`crate::pipeline`] 在归一化之后执行，以保证哈希可复现。
#[must_use]
pub fn normalize(outcome: &ParseOutcome, meta: &SourceMeta, raw_text: &str, origin: &str) -> Event {
    let mut event = Event::new(meta.tenant_id, meta.source_id, meta.protocol);
    event.source_name = meta.source_name.clone();
    event.vendor = meta.vendor.clone();
    event.product = meta.product.clone();
    event.ingested_at = meta.ingested_at;
    event.tags = meta.tags.clone();
    if let Some(key) = &outcome.parser_key {
        event.parser_name = Some(key.clone());
        event.parser_id = Some(parser_id_for(key));
    }

    // `fields` 是已映射到 ECS 路径的字段，`extra` 是模板未映射的原始字段；
    // 两者都要过一遍 `apply_field`，未识别的路径最终落到 `Event::extra`（保真不丢）。
    for (path, value) in outcome.fields.iter().chain(outcome.extra.iter()) {
        if !apply_field(&mut event, path, value) {
            event.extra.insert(path.clone(), value.clone());
        }
    }

    if event.category == EventCategory::Other {
        event.category = infer_category(&event.vendor, &event.product, &event.message);
    }
    if event.message.is_empty() {
        event.message = truncate_chars(raw_text, 2_048);
    }
    event.raw = parse_raw_value(raw_text);
    event.raw_hash = content_hash(raw_text);
    if !origin.is_empty() {
        event.extra.insert("log.origin".to_string(), Value::from(origin.to_string()));
    }
    event
}

/// 保真载荷：能解析为 JSON 则保留结构，否则保留字符串。
#[must_use]
pub fn parse_raw_value(raw_text: &str) -> Value {
    match serde_json::from_str::<Value>(raw_text) {
        Ok(v @ (Value::Object(_) | Value::Array(_))) => v,
        _ => Value::String(raw_text.to_string()),
    }
}

/// 按字符截断（避免把多字节字符切坏）。
#[must_use]
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push_str("…（已截断）");
    out
}

/// 应用单条 ECS 路径；返回 `false` 表示未被消费（调用方写入 `extra`）。
fn apply_field(event: &mut Event, path: &str, value: &Value) -> bool {
    match path {
        "event.time" => {
            if let Some(text) = as_string(value) {
                if let Some(ts) = crate::engine::parse_time_value(&text, None) {
                    event.time = ts;
                }
            }
            true
        }
        "event.severity" => {
            if let Some(text) = as_string(value) {
                event.severity = severity_from_text(&text);
            }
            true
        }
        "event.category" => {
            if let Some(text) = as_string(value) {
                event.category = event_category_from(&text);
            }
            true
        }
        "event.action" => {
            if let Some(text) = as_string(value) {
                event.action = event_action_from(&text);
                if event.action_raw.is_empty() {
                    event.action_raw = text;
                }
            }
            true
        }
        "event.action_raw" => {
            if let Some(text) = as_string(value) {
                event.action_raw = text.clone();
                event.action = event_action_from(&text);
            }
            true
        }
        "message" | "log.original" => {
            if let Some(text) = as_string(value) {
                event.message = text;
            }
            true
        }
        "tags" => {
            event.tags.extend(as_string_list(value));
            true
        }
        "vendor" | "observer.vendor" => {
            if let Some(text) = as_string(value) {
                if event.vendor.is_empty() {
                    event.vendor = text;
                }
            }
            true
        }
        "product" | "observer.product" => {
            if let Some(text) = as_string(value) {
                if event.product.is_empty() {
                    event.product = text;
                }
            }
            true
        }
        "host.name" => set_opt(&mut event.host.name, value),
        "host.id" => set_opt(&mut event.host.id, value),
        "host.os" => set_opt(&mut event.host.os, value),
        "host.arch" => set_opt(&mut event.host.arch, value),
        "host.ip" => {
            if let Some(text) = as_string(value) {
                if !event.host.ips.contains(&text) {
                    event.host.ips.push(text);
                }
            }
            true
        }
        "host.cloud_instance_id" => set_opt(&mut event.host.cloud_instance_id, value),
        "host.cloud_account" | "cloud.account.id" => set_opt(&mut event.host.cloud_account, value),
        "host.k8s_namespace" => set_opt(&mut event.host.k8s_namespace, value),
        "host.k8s_pod" => set_opt(&mut event.host.k8s_pod, value),
        "user.name" | "source.user.name" => set_opt(&mut event.user.name, value),
        "user.id" => set_opt(&mut event.user.id, value),
        "user.domain" => set_opt(&mut event.user.domain, value),
        "user.email" => set_opt(&mut event.user.email, value),
        "user.department" => set_opt(&mut event.user.department, value),
        "network.source_ip" | "source.ip" => set_opt(&mut event.network.source_ip, value),
        "network.source_port" | "source.port" => {
            event.network.source_port = as_u16(value);
            true
        }
        "network.destination_ip" | "destination.ip" => set_opt(&mut event.network.destination_ip, value),
        "network.destination_port" | "destination.port" => {
            event.network.destination_port = as_u16(value);
            true
        }
        "network.transport" | "network.protocol" => set_opt(&mut event.network.transport, value),
        "network.domain" | "url.domain" | "dns.question.name" => set_opt(&mut event.network.domain, value),
        "network.direction" => {
            if let Some(text) = as_string(value) {
                event.network.direction = Some(direction_from(&text));
            }
            true
        }
        "network.bytes_out" | "source.bytes" => {
            event.network.bytes_out = as_u64(value);
            true
        }
        "network.bytes_in" | "destination.bytes" => {
            event.network.bytes_in = as_u64(value);
            true
        }
        "ai.agent_id" => {
            event.ai.agent_id = as_string(value).and_then(|s| Id::parse(&s).ok());
            true
        }
        "ai.agent_flavor" => set_opt(&mut event.ai.agent_flavor, value),
        "ai.session_id" => set_opt(&mut event.ai.session_id, value),
        "ai.mcp_server_id" => {
            event.ai.mcp_server_id = as_string(value).and_then(|s| Id::parse(&s).ok());
            true
        }
        "ai.tool_name" => set_opt(&mut event.ai.tool_name, value),
        "ai.model_endpoint_id" => {
            event.ai.model_endpoint_id = as_string(value).and_then(|s| Id::parse(&s).ok());
            true
        }
        "ai.provider" => set_opt(&mut event.ai.provider, value),
        "ai.model" => set_opt(&mut event.ai.model, value),
        "ai.prompt_tokens" => {
            event.ai.prompt_tokens = as_u64(value);
            true
        }
        "ai.completion_tokens" => {
            event.ai.completion_tokens = as_u64(value);
            true
        }
        "ai.cost_micro" => {
            event.ai.cost_micro = as_u64(value);
            true
        }
        "ai.prompt_hash" => set_opt(&mut event.ai.prompt_hash, value),
        "ai.rule_keys" => {
            event.ai.rule_keys = as_string_list(value);
            true
        }
        "ai.policy_id" => {
            event.ai.policy_id = as_string(value).and_then(|s| Id::parse(&s).ok());
            true
        }
        "ai.action" => set_opt(&mut event.ai.action, value),
        "ai.mocked" => {
            event.ai.mocked = value.as_bool().unwrap_or(false);
            true
        }
        _ => false,
    }
}

/// 字段可选值写入辅助。
fn set_opt(slot: &mut Option<String>, value: &Value) -> bool {
    if let Some(text) = as_string(value) {
        if !text.is_empty() {
            *slot = Some(text);
        }
    }
    true
}

/// 未消费字段的只读视图（供报表/排障）。
#[must_use]
pub fn unmapped_fields(event: &Event) -> BTreeMap<String, Value> {
    event.extra.clone()
}

/// 事件是否为"高危且 AI 相关"（供告警路由快速判定）。
#[must_use]
pub fn is_ai_high_risk(event: &Event) -> bool {
    event.is_ai_event() && event.severity >= Severity::High
}

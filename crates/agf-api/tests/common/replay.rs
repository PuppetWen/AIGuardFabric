//! 日志回放辅助：构造未解析原始日志与自研 Webhook 模板。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines, dead_code, unreachable_pub)]

use super::*;

/// 构造一条**未解析**的原始日志（回放引擎只处理 `parsed=false` 的行）。
pub fn replay_raw_log(
    tenant: TenantId,
    origin: &str,
    source_id: agf_core::ids::Id,
    protocol: agf_core::enums::IngestProtocol,
    payload: &str,
    event_id: Option<agf_core::ids::Id>,
) -> agf_core::event::RawLog {
    agf_core::event::RawLog {
        id: agf_core::ids::Id::new(),
        tenant_id: tenant,
        source_id,
        received_at: Timestamp::now(),
        protocol,
        payload_b64: {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(payload)
        },
        payload_hash: agf_core::secret::content_hash(payload),
        bytes: payload.len(),
        origin: origin.to_string(),
        parsed: false,
        parse_error: Some("集成测试：等待回放解析".to_string()),
        event_id,
    }
}

/// 自研 Webhook 模板（JSONPath；键名与所有内置模板都不同，保证"只有它能命中"）。
pub fn replay_custom_template() -> agf_core::parser::ParserDefinition {
    use agf_core::parser::{FieldMapping, ParserEngine};
    agf_core::parser::ParserDefinition {
        key: "it-replay-webhook".to_string(),
        name: "集成测试 Webhook".to_string(),
        vendor: "自研".to_string(),
        product: "Webhook".to_string(),
        protocols: vec![agf_core::enums::IngestProtocol::Webhook],
        engine: ParserEngine::JsonPath,
        pattern: [
            "zzz_client=$.zzz_client",
            "zzz_level=$.zzz_level",
            "zzz_detail=$.zzz_detail",
            "zzz_action=$.zzz_action",
        ]
        .join("\n"),
        fallback_patterns: Vec::new(),
        mapping: FieldMapping {
            map: BTreeMap::from([
                ("zzz_detail".to_string(), "message".to_string()),
                ("zzz_client".to_string(), "source.ip".to_string()),
            ]),
            severity_field: Some("zzz_level".to_string()),
            severity_map: BTreeMap::from([("high".to_string(), agf_core::enums::Severity::High)]),
            action_field: Some("zzz_action".to_string()),
            ..FieldMapping::default()
        },
        derived: BTreeMap::new(),
        required_fields: Vec::new(),
        version: 1,
        builtin: false,
        ai_inferred: false,
        description: "集成测试模板".to_string(),
        sample_fixture: String::new(),
    }
}

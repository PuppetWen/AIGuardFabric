//! AI 推断提供方：`AiParserProvider` 抽象与三个实现（离线启发式 / Mock / 远程 TODO），以及推断建议入口。

use super::*;

/// 启发式推断模板的稳定 key。
pub const HEURISTIC_KEY: &str = "ai-heuristic-inferred";

/// 远程 AI 推断模板的稳定 key（未实现）。
pub const REMOTE_KEY: &str = "ai-remote-inferred";

/// AI 解析器提供方抽象（便于把 `agf-aigw` 的实现注入进来）。
pub trait AiParserProvider: Send + Sync + std::fmt::Debug {
    /// 提供方名称。
    fn name(&self) -> &'static str;

    /// 依据样例给出解析器建议。
    ///
    /// # Errors
    /// 无法推断或上游不可用。
    fn suggest(&self, request: &AiParserRequest) -> DomainResult<AiParserSuggestion>;

    /// 结果是否为"非真实模型输出"（Mock/启发式）。
    fn mocked(&self) -> bool;
}

/// 离线启发式推断（默认实现，无网络依赖）。
#[derive(Debug, Default, Clone, Copy)]
pub struct HeuristicAiParser;

impl HeuristicAiParser {
    /// 构造。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AiParserProvider for HeuristicAiParser {
    fn name(&self) -> &'static str {
        "heuristic"
    }

    fn suggest(&self, request: &AiParserRequest) -> DomainResult<AiParserSuggestion> {
        infer_suggestion(&request.samples, request.vendor_hint.as_deref(), request.protocol).ok_or_else(|| {
            DomainError::NotImplemented(
                "样例形态无法启发式推断（TODO ingest-ai-parser-remote：接 agf-aigw 的 LLM 推断）".to_string(),
            )
        })
    }

    fn mocked(&self) -> bool {
        true
    }
}

/// 固定响应的 Mock 提供方（演示与测试；不含任何推断逻辑）。
#[derive(Debug, Default, Clone, Copy)]
pub struct MockAiParser;

impl MockAiParser {
    /// 构造。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AiParserProvider for MockAiParser {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn suggest(&self, _request: &AiParserRequest) -> DomainResult<AiParserSuggestion> {
        Ok(AiParserSuggestion {
            definition: kv_definition(Some("mock-vendor")),
            confidence: 0.3,
            rationale: "Mock 提供方固定返回一个 KV 模板，仅用于打通链路与前端联调".to_string(),
            model: "mock".to_string(),
            mocked: true,
            generated_at: Timestamp::now(),
        })
    }

    fn mocked(&self) -> bool {
        true
    }
}

/// 远程 LLM 推断（未实现）。
///
/// `TODO ingest-ai-parser-remote`：需要
/// 1. `agf-aigw` 暴露"日志样本 → 解析器草案"的受控提示词模板与 JSON Schema 输出约束；
/// 2. 出网白名单 + 数据不出域判定（`DataClass::Restricted` 时只能走本地模型）；
/// 3. 提示词中注入的样本必须**先脱敏**（复用 `agf_core::redact`）；
/// 4. 返回草案同样要人工确认后才能 `register_ai_inferred`。
#[derive(Debug, Clone)]
pub struct RemoteAiParser {
    /// 逻辑端点名（如 `aigw://log-parser`），由 `agf-aigw` 解析。
    pub endpoint: String,
}

impl AiParserProvider for RemoteAiParser {
    fn name(&self) -> &'static str {
        "remote"
    }

    fn suggest(&self, _request: &AiParserRequest) -> DomainResult<AiParserSuggestion> {
        Err(DomainError::NotImplemented(format!(
            "远程 AI 推断未实现（endpoint={}）；TODO ingest-ai-parser-remote：接入 agf-aigw 的日志解析草案接口，\
             返回后须人工确认方可固化",
            self.endpoint
        )))
    }

    fn mocked(&self) -> bool {
        false
    }
}

/// 一站式启发式推断：返回可直接注册（或先人工确认）的建议。
#[must_use]
pub fn infer_suggestion(
    samples: &[String],
    vendor_hint: Option<&str>,
    _protocol: Option<IngestProtocol>,
) -> Option<AiParserSuggestion> {
    let definition = heuristic_definition(samples, vendor_hint)?;
    let mapped = definition.mapping.map.len();
    let extracted = definition.pattern.matches('=').count().max(1);
    let ratio = mapped as f32 / extracted as f32;
    Some(AiParserSuggestion {
        confidence: (0.35 + 0.5 * ratio).min(0.85),
        rationale: format!(
            "离线启发式推断：识别为 {} 形态，抽取 {extracted} 个字段并映射 {mapped} 个到 AGF-ECS；\
             未映射字段保留在 Event::extra。置信度仅供人工确认排序，最终以样本回放结果为准",
            match definition.engine {
                ParserEngine::JsonPath => "JSON",
                ParserEngine::Kv => "KV",
                ParserEngine::Csv => "CSV/TSV",
                other => other.as_str(),
            }
        ),
        model: "heuristic/offline".to_string(),
        mocked: true,
        generated_at: Timestamp::now(),
        definition,
    })
}

/// 由样例生成解析器定义（启发式；不做任何网络访问）。
#[must_use]
pub fn heuristic_definition(samples: &[String], vendor_hint: Option<&str>) -> Option<ParserDefinition> {
    let sample = samples.iter().find(|s| !s.trim().is_empty())?.trim();
    if sample.starts_with('{') {
        let flat = flatten_json_keys(sample)?;
        if flat.is_empty() {
            return None;
        }
        let mut def = base_def(ParserEngine::JsonPath, json_pattern(&flat), vendor_hint.unwrap_or(""));
        apply_field_guesses(&mut def, &flat, sample);
        Some(def)
    } else if sample.contains('=') {
        let keys = kv_keys(sample);
        if keys.is_empty() {
            return None;
        }
        let mut def = base_def(ParserEngine::Kv, "=".to_string(), vendor_hint.unwrap_or(""));
        apply_field_guesses(&mut def, &keys, sample);
        Some(def)
    } else if sample.contains('\t') || sample.contains(',') {
        let delimiter = if sample.contains('\t') { '\t' } else { ',' };
        let count = sample.split(delimiter).count();
        if count < 2 {
            return None;
        }
        let keys: Vec<String> = (0..count).map(|i| format!("f{i}")).collect();
        let mut def = base_def(ParserEngine::Csv, keys.join(","), vendor_hint.unwrap_or(""));
        apply_field_guesses(&mut def, &keys, sample);
        Some(def)
    } else {
        None
    }
}

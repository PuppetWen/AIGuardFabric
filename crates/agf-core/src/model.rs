//! 模型与模型端点模型（§4.1 / §4.4）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{DataClass, LlmProvider};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 模型模态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Modality {
    /// 文本。
    Text,
    /// 图像输入。
    Vision,
    /// 音频。
    Audio,
    /// 向量嵌入。
    Embedding,
    /// 重排序。
    Rerank,
    /// 语音合成。
    Tts,
    /// 语音识别。
    Stt,
}

impl Modality {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Vision => "vision",
            Self::Audio => "audio",
            Self::Embedding => "embedding",
            Self::Rerank => "rerank",
            Self::Tts => "tts",
            Self::Stt => "stt",
        }
    }
}

/// 模型端点（一个可调用的 `provider + base_url + model` 三元组）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEndpoint {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 关联资产 id。
    pub asset_id: Id,
    /// 显示名。
    pub name: String,
    /// 厂商。
    pub provider: LlmProvider,
    /// Base URL。
    pub base_url: String,
    /// 模型标识（厂商侧 model id）。
    pub model: String,
    /// 兼容的协议类型。
    #[serde(default)]
    pub modalities: Vec<Modality>,
    /// 上下文窗口（token）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    /// 最大输出 token。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// 是否支持流式。
    pub supports_streaming: bool,
    /// 是否支持工具调用（function calling）。
    pub supports_tools: bool,
    /// 凭据引用（密文存 `credentials`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<Id>,
    /// 是否为本地/私有化部署（数据不出域）。
    pub local_deployment: bool,
    /// 数据分级上限（超过则不允许送该端点）。
    pub max_data_class: DataClass,
    /// 单价表（每 1K token，单位：微元/1e-6 元，避免浮点误差）。
    pub pricing: ModelPricing,
    /// 是否启用。
    pub enabled: bool,
    /// 是否作为路由降级目标。
    pub fallback: bool,
    /// 优先级（数值越小优先级越高）。
    pub priority: u32,
    /// 附加请求头（如 Azure 的 `api-version`）。
    #[serde(default)]
    pub extra_headers: BTreeMap<String, String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

impl TenantScoped for ModelEndpoint {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl ModelEndpoint {
    /// 能否承接指定数据分级（数据不出域约束）。
    #[must_use]
    pub fn accepts_data_class(&self, class: DataClass) -> bool {
        if class.requires_local_inference() && !self.local_deployment {
            return false;
        }
        class <= self.max_data_class
    }

    /// 估算费用（微元）。
    #[must_use]
    pub fn estimate_cost_micro(&self, prompt_tokens: u64, completion_tokens: u64) -> u64 {
        let p = u128::from(self.pricing.prompt_micro_per_1k) * u128::from(prompt_tokens) / 1000;
        let c = u128::from(self.pricing.completion_micro_per_1k) * u128::from(completion_tokens) / 1000;
        u64::try_from(p + c).unwrap_or(u64::MAX)
    }
}

/// 模型计价（每 1K token，单位微元 = 1e-6 元）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPricing {
    /// 输入 token 单价。
    pub prompt_micro_per_1k: u64,
    /// 输出 token 单价。
    pub completion_micro_per_1k: u64,
    /// 缓存命中输入单价（可低于常规）。
    pub cached_prompt_micro_per_1k: u64,
}

impl ModelPricing {
    /// 是否免费（本地模型 / Mock）。
    #[must_use]
    pub const fn is_free(&self) -> bool {
        self.prompt_micro_per_1k == 0 && self.completion_micro_per_1k == 0
    }
}

/// 模型注册表条目（跨租户共享的"模型目录"，含能力与风险信息）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCatalogEntry {
    /// 主键。
    pub id: Id,
    /// 厂商。
    pub provider: LlmProvider,
    /// 模型标识。
    pub model: String,
    /// 显示名。
    pub display_name: String,
    /// 模态。
    #[serde(default)]
    pub modalities: Vec<Modality>,
    /// 上下文窗口。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    /// 是否支持工具调用。
    pub supports_tools: bool,
    /// 是否支持流式。
    pub supports_streaming: bool,
    /// 默认价格。
    pub pricing: ModelPricing,
    /// 是否存在已知安全问题（如易被越狱），用于路由偏好。
    pub known_jailbreak_prone: bool,
    /// 是否可本地部署。
    pub self_hostable: bool,
    /// 数据驻留区域（合规）。
    #[serde(default)]
    pub regions: Vec<String>,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 语义缓存条目（§4.4 网关语义缓存）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticCacheEntry {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 归一化后的请求指纹（哈希）。
    pub request_fingerprint: String,
    /// 向量（可选，本地模型生成）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
    /// 缓存响应。
    pub response: serde_json::Value,
    /// 命中的模型端点 id。
    pub endpoint_id: Id,
    /// 节省的输入 token。
    pub saved_prompt_tokens: u64,
    /// 节省的金额（微元）。
    pub saved_micro: u64,
    /// 命中次数。
    pub hits: u64,
    /// 过期时间。
    pub expires_at: Timestamp,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// Token 用量计量记录（计费与配额的事实来源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 会话。
    pub session_id: String,
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// 模型端点 id。
    pub endpoint_id: Id,
    /// 厂商。
    pub provider: LlmProvider,
    /// 模型。
    pub model: String,
    /// 输入 token。
    pub prompt_tokens: u64,
    /// 输出 token。
    pub completion_tokens: u64,
    /// 缓存读取 token。
    #[serde(default)]
    pub cached_tokens: u64,
    /// Provider prompt-cache write tokens (already included in prompt_tokens).
    #[serde(default)]
    pub cache_write_tokens: u64,
    /// One-hour subset of cache_write_tokens.
    #[serde(default)]
    pub cache_write_1h_tokens: u64,
    /// 是否被语义缓存命中（不产生真实上游调用）。
    pub cache_hit: bool,
    /// 费用（微元）。
    pub cost_micro: u64,
    /// 是否走了 Mock 模型。
    pub mocked: bool,
    /// 上游耗时（毫秒）。
    pub latency_ms: u64,
    /// 发生时间。
    pub at: Timestamp,
}

impl UsageRecord {
    /// 总 token。
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(local: bool, max_class: DataClass, pricing: ModelPricing) -> ModelEndpoint {
        let now = Timestamp::now();
        ModelEndpoint {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            asset_id: Id::new(),
            name: "ep".into(),
            provider: LlmProvider::OpenAi,
            base_url: "https://api.openai.com/v1".into(),
            model: "gpt-4o".into(),
            modalities: vec![Modality::Text],
            context_window: Some(128_000),
            max_output_tokens: Some(4096),
            supports_streaming: true,
            supports_tools: true,
            credential_ref: None,
            local_deployment: local,
            max_data_class: max_class,
            pricing,
            enabled: true,
            fallback: false,
            priority: 10,
            extra_headers: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn restricted_data_must_use_local_deployment() {
        let cloud = endpoint(false, DataClass::Restricted, ModelPricing::default());
        assert!(!cloud.accepts_data_class(DataClass::Restricted));
        assert!(cloud.accepts_data_class(DataClass::Internal));
        let local = endpoint(true, DataClass::Restricted, ModelPricing::default());
        assert!(local.accepts_data_class(DataClass::Restricted));
    }

    #[test]
    fn data_class_ceiling_is_enforced() {
        let ep = endpoint(true, DataClass::Internal, ModelPricing::default());
        assert!(ep.accepts_data_class(DataClass::Internal));
        assert!(!ep.accepts_data_class(DataClass::Confidential));
    }

    #[test]
    fn cost_estimation_is_integer_safe() {
        let pricing = ModelPricing {
            prompt_micro_per_1k: 2_500,
            completion_micro_per_1k: 10_000,
            cached_prompt_micro_per_1k: 1_250,
        };
        let ep = endpoint(false, DataClass::Internal, pricing);
        // 1000 输入 + 500 输出 = 2500 + 5000 = 7500 微元
        assert_eq!(ep.estimate_cost_micro(1000, 500), 7_500);
        assert!(!pricing.is_free());
    }

    #[test]
    fn free_pricing_detected_for_local() {
        assert!(ModelPricing::default().is_free());
    }

    #[test]
    fn usage_record_totals() {
        let r = UsageRecord {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            session_id: "s".into(),
            agent_id: None,
            endpoint_id: Id::new(),
            provider: LlmProvider::Mock,
            model: "mock-analyst-1".into(),
            prompt_tokens: 120,
            completion_tokens: 80,
            cached_tokens: 0,
            cache_write_tokens: 0,
            cache_write_1h_tokens: 0,
            cache_hit: false,
            cost_micro: 0,
            mocked: true,
            latency_ms: 5,
            at: Timestamp::now(),
        };
        assert_eq!(r.total_tokens(), 200);
        let mut legacy = serde_json::to_value(&r).unwrap_or_default();
        if let Some(fields) = legacy.as_object_mut() {
            fields.remove("cache_write_tokens");
            fields.remove("cache_write_1h_tokens");
        }
        assert_eq!(
            serde_json::from_value::<UsageRecord>(legacy)
                .ok()
                .map(|record| (record.cache_write_tokens, record.cache_write_1h_tokens)),
            Some((0, 0)),
        );
    }

    #[test]
    fn modality_str() {
        assert_eq!(Modality::Embedding.as_str(), "embedding");
        assert_eq!(Modality::Vision.as_str(), "vision");
    }
}

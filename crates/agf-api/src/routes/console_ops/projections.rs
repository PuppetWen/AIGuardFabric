//! Skill / 白名单与模型网关（路由策略 / 用量）的 JSON 投影与工具函数。

use super::*;

// ===========================================================================
// 投影与工具函数
// ===========================================================================

/// 台账 Skill 资产 → 前端 `Skill`（口径与 [`crate::routes::ai_assets`] 的 `SkillView` 一致）。
pub(super) fn skill_json(asset: &Asset) -> Result<serde_json::Value, DomainError> {
    Ok(serde_json::to_value(crate::routes::ai_assets::skill_view(asset))?)
}

/// Shared status projection.
pub(super) fn skill_status(lifecycle: LifecycleState) -> &'static str {
    crate::routes::ai_assets::skill_status(lifecycle)
}

/// 前端 `SkillStatus` → 台账生命周期（[`skill_status`] 的反函数，保证读写闭环）。
///
/// # Errors
/// 未知状态名。
pub(super) fn parse_skill_status(raw: &str) -> Result<LifecycleState, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "pending" => Ok(LifecycleState::UnderReview),
        "approved" => Ok(LifecycleState::Production),
        "rejected" => Ok(LifecycleState::Rejected),
        "revoked" => Ok(LifecycleState::Archived),
        other => Err(ApiError::new(DomainError::Validation(format!(
            "未知 Skill 状态: {other}（可选 pending/approved/rejected/revoked）"
        )))),
    }
}

/// Skill 白名单：`attributes.whitelist.{domains,paths}`，缺省为空。
pub(super) fn whitelist_json(asset: &Asset) -> serde_json::Value {
    let value = asset.attributes.get("whitelist");
    serde_json::json!({
        "domains": value.and_then(|v| v.get("domains")).map(|v| value_string_list(Some(v))).unwrap_or_default(),
        "paths": value.and_then(|v| v.get("paths")).map(|v| value_string_list(Some(v))).unwrap_or_default(),
    })
}

/// 取租户内的 Skill 资产（不存在或类型不符 → 404，id 非法 → 400）。
///
/// # Errors
/// id 非法或资产不是 Skill。
pub(super) fn skill_asset(current: Option<Asset>, id: Id) -> Result<Asset, DomainError> {
    let not_found = || DomainError::NotFound { entity: "skill", id: id.to_string() };
    let Some(asset) = current else {
        return Err(not_found());
    };
    if asset.kind != AssetKind::Skill {
        return Err(not_found());
    }
    Ok(asset)
}

/// 前端告警状态 → 后端 `AlertState` 词表（无法映射时原样透传，由既有处理器报 400）。
pub(super) fn map_console_alert_status(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        // 后端没有"处理中"态：已受理即 Acknowledged（最接近的既有态）
        "in-progress" => "acknowledged".to_string(),
        // 后端没有"已解决"态：已解决即终态 Closed
        "resolved" => "closed".to_string(),
        other => other.to_string(),
    }
}

/// 拆开既有处理器的包裹键（`{"finding": …}` → `…`）；没有该键时原样返回。
pub(super) fn unwrap_entity(value: serde_json::Value, key: &str) -> serde_json::Value {
    let inner = value.get(key).cloned();
    inner.unwrap_or(value)
}

/// 台账 MCP 资产 → 前端 `McpTool[]`（见 [`list_mcp_tools`] 的字段口径）。
pub(super) fn mcp_tools_from_asset(asset: &Asset) -> Vec<serde_json::Value> {
    let Some(items) = asset.attributes.get("tools").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let (name, description) = match item {
            serde_json::Value::String(name) => (name.clone(), String::new()),
            serde_json::Value::Object(_) => {
                let Some(name) = item.get("name").and_then(serde_json::Value::as_str) else {
                    // 没有 name 的条目无法构成工具，跳过而不是造一个空名工具
                    continue;
                };
                (name.to_string(), object_str(item, "description").unwrap_or_default())
            }
            _ => continue,
        };
        let traits = ToolTraits::infer(&name, &description);
        let explicit = object_list(item, "capabilities");
        let capabilities = if explicit.is_empty() {
            inferred_capabilities(&traits)
        } else {
            explicit
                .into_iter()
                .map(|c| c.trim().to_ascii_lowercase().replace('_', "-"))
                .filter(|c| TOOL_CAPABILITIES.contains(&c.as_str()))
                .collect()
        };
        let risk_level = object_str(item, "risk_level")
            .or_else(|| object_str(item, "riskLevel"))
            .map(|raw| raw.trim().to_ascii_lowercase())
            .filter(|raw| Severity::parse(raw).is_ok())
            .unwrap_or_else(|| {
                let core_tool = agf_core::mcp::McpTool {
                    name: name.clone(),
                    description: description.clone(),
                    input_schema: serde_json::Value::Null,
                    traits,
                    sensitive_params: object_list(item, "sensitive_params"),
                };
                core_tool.risk_level().as_str().to_string()
            });
        out.push(serde_json::json!({
            "id": format!("{}-tool-{}", asset.id, index + 1),
            "serverId": asset.id.to_string(),
            "name": name,
            "description": description,
            "capabilities": capabilities,
            "riskLevel": risk_level,
            "invocations24h": object_u64(item, "invocations_24h")
                .or_else(|| object_u64(item, "invocations24h")),
            "sensitiveParams": object_list(item, "sensitive_params"),
            "datasources": object_list(item, "datasources"),
        }));
    }
    out
}

/// `ToolTraits` → 前端 `ToolCapability`（推断规则见 `agf_core::mcp::ToolTraits::infer`）。
fn inferred_capabilities(traits: &ToolTraits) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    push_capability(&mut out, traits.database, "read");
    push_capability(&mut out, traits.filesystem_read, "read");
    push_capability(&mut out, traits.cloud_mutation, "write");
    push_capability(&mut out, traits.filesystem_write, "write");
    push_capability(&mut out, traits.shell_exec, "execute");
    push_capability(&mut out, traits.network_egress || traits.network_ingress || traits.messaging, "network");
    push_capability(&mut out, traits.filesystem_read || traits.filesystem_write, "filesystem");
    push_capability(&mut out, traits.credential_access, "credential");
    out
}

/// 追加能力标签（去重，只允许前端词表内的取值）。
fn push_capability(out: &mut Vec<String>, flag: bool, label: &str) {
    if flag && TOOL_CAPABILITIES.contains(&label) && !out.iter().any(|c| c == label) {
        out.push(label.to_string());
    }
}

// ===========================================================================
// 模型网关投影辅助
// ===========================================================================

/// [`ModelRoutePolicy`] → 前端 `ModelRoutePolicy` JSON。
///
/// `tenant_id` 是存储侧的隔离字段，**不对外输出**（租户由认证主体决定，回显它没有意义）。
pub(super) fn route_policy_json(policy: &ModelRoutePolicy) -> serde_json::Value {
    serde_json::json!({
        "id": policy.id.to_string(),
        "version": policy.version,
        "name": policy.name,
        "primary_endpoint_id": policy.primary_endpoint_id,
        "fallback_endpoint_ids": policy.fallback_endpoint_ids,
        "strategy": policy.strategy,
        "weights": policy.weights,
        "budget_cny_per_day": policy.budget_cny_per_day,
        "currency": "CNY",
        // Deprecated spelling; the historical value was always CNY.
        "budget_usd_per_day": policy.budget_cny_per_day,
        "enabled": policy.enabled,
    })
}

/// 合并请求体到路由策略（驼峰与 snake_case 都接受；未提供的字段保持原值）。
///
/// 前端 `client.ts::saveRoutePolicy` 传的是 `Partial<ModelRoutePolicy>`（驼峰，且可能只有
/// `{id, enabled}`），而存储侧字段是 snake_case，故两种键名都认；策略枚举按 `domain.ts`
/// 的四个取值校验（`priority`/`weighted`/`cost-first`/`latency-first`）。
///
/// # Errors
/// body 不是对象；新建时缺 `name`/`primary_endpoint_id`；`name` 为空；`strategy` 不在词表内；
/// `weights` 含非数字；`budget_usd_per_day` 为负。
pub(super) fn merge_route_policy(
    existing: Option<ModelRoutePolicy>,
    id: Id,
    tenant: TenantId,
    body: &serde_json::Value,
) -> Result<ModelRoutePolicy, ApiError> {
    let Some(object) = body.as_object() else {
        return Err(ApiError::new(DomainError::Validation("请求体必须是 JSON 对象".to_string())));
    };
    let is_new = existing.is_none();
    let mut policy = existing.unwrap_or(ModelRoutePolicy {
        version: 0,
        id,
        tenant_id: tenant,
        name: String::new(),
        primary_endpoint_id: String::new(),
        fallback_endpoint_ids: Vec::new(),
        strategy: "priority".to_string(),
        weights: BTreeMap::new(),
        budget_cny_per_day: 0.0,
        enabled: true,
    });
    policy.id = id;
    policy.tenant_id = tenant;

    // 取字段：先驼峰后 snake_case（前端 camelizeDeep 只改键名，不改值）。
    let pick = |camel: &str, snake: &str| object.get(camel).or_else(|| object.get(snake));
    if let Some(value) = pick("name", "name") {
        let name = value.as_str().unwrap_or_default().trim().to_string();
        if name.is_empty() {
            return Err(ApiError::new(DomainError::Validation("name 不能为空".to_string())));
        }
        policy.name = name;
    }
    if let Some(value) = pick("primaryEndpointId", "primary_endpoint_id") {
        policy.primary_endpoint_id = value
            .as_str()
            .ok_or_else(|| ApiError::new(DomainError::Validation("primary_endpoint_id 必须是字符串".to_string())))?
            .to_string();
    }
    if let Some(value) = pick("fallbackEndpointIds", "fallback_endpoint_ids") {
        let list = value
            .as_array()
            .ok_or_else(|| ApiError::new(DomainError::Validation("fallback_endpoint_ids 必须是数组".to_string())))?;
        policy.fallback_endpoint_ids = list
            .iter()
            .map(|item| {
                item.as_str().map(ToString::to_string).ok_or_else(|| {
                    ApiError::new(DomainError::Validation("fallback_endpoint_ids 元素必须是字符串".to_string()))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    if let Some(value) = pick("strategy", "strategy") {
        let raw = value
            .as_str()
            .ok_or_else(|| ApiError::new(DomainError::Validation("strategy 必须是字符串".to_string())))?
            .trim()
            .to_ascii_lowercase();
        if !ROUTE_STRATEGIES.contains(&raw.as_str()) {
            return Err(ApiError::new(DomainError::Validation(format!(
                "未知选路策略: {raw}（可选 priority/weighted/cost-first/latency-first）"
            ))));
        }
        policy.strategy = raw;
    }
    if let Some(value) = pick("weights", "weights") {
        let map = value
            .as_object()
            .ok_or_else(|| ApiError::new(DomainError::Validation("weights 必须是对象".to_string())))?;
        let mut weights = BTreeMap::new();
        for (key, item) in map {
            let weight = item
                .as_f64()
                .filter(|value| value.is_finite() && (0.0..=1_000_000.0).contains(value))
                .ok_or_else(|| ApiError::new(DomainError::Validation(format!("weights[{key}] 必须是数字"))))?;
            weights.insert(key.clone(), weight);
        }
        policy.weights = weights;
    }
    let mut budget_value = None;
    for key in ["budgetCnyPerDay", "budget_cny_per_day", "budgetUsdPerDay", "budget_usd_per_day"] {
        if let Some(value) = object.get(key) {
            let budget = value
                .as_f64()
                .filter(|v| v.is_finite() && (0.0..=1_000_000.0).contains(v))
                .ok_or_else(|| ApiError::new(DomainError::Validation("日预算须为 0–1000000 CNY 元".into())))?;
            if budget_value.is_some_and(|previous| previous != budget) {
                return Err(ApiError::new(DomainError::Validation("预算字段冲突".into())));
            }
            budget_value = Some(budget);
        }
    }
    if let Some(value) = object.get("currency") {
        if value.as_str() != Some("CNY") {
            return Err(ApiError::new(DomainError::Validation("计价币种必须为 CNY".into())));
        }
    }
    if let Some(budget) = budget_value {
        policy.budget_cny_per_day = budget;
    }
    if let Some(value) = pick("enabled", "enabled") {
        policy.enabled = value
            .as_bool()
            .ok_or_else(|| ApiError::new(DomainError::Validation("enabled 必须是布尔值".to_string())))?;
    }

    if policy.strategy == "weighted"
        && !std::iter::once(&policy.primary_endpoint_id)
            .chain(&policy.fallback_endpoint_ids)
            .any(|id| policy.weights.get(id).copied().unwrap_or(1.0) > 0.0)
    {
        return Err(ApiError::new(DomainError::Validation("至少一个路由端点的权重应大于 0".into())));
    }
    if is_new {
        if policy.name.is_empty() {
            return Err(ApiError::new(DomainError::Validation(
                "新建路由策略必须提供 name（记录不存在时不会静默创建空策略）".to_string(),
            )));
        }
        if policy.primary_endpoint_id.is_empty() {
            return Err(ApiError::new(DomainError::Validation("新建路由策略必须提供 primary_endpoint_id".to_string())));
        }
    }
    Ok(policy)
}

/// 资产 id → 名称（`agent_name` 等展示字段的唯一来源；解析不到就留空，不编造）。
pub(super) async fn asset_names(
    state: &AppState,
    tenant: TenantId,
) -> ApiResult<std::collections::BTreeMap<Id, String>> {
    Ok(state.store.asset_list_all_durable(tenant).await?.into_iter().map(|a| (a.id, a.name)).collect())
}

/// [`UsageRecord`] → 前端 `TokenUsageRecord` JSON（币种口径见模块文档）。
pub(super) fn usage_record_json(
    record: &UsageRecord,
    names: &std::collections::BTreeMap<Id, String>,
) -> serde_json::Value {
    serde_json::json!({
        "id": record.id.to_string(),
        "ts": record.at.to_rfc3339(),
        "tenant_id": record.tenant_id.to_string(),
        // 无 Agent 归属时给空串（前端该字段是 string，不是可空）
        "agent_id": record.agent_id.map_or_else(String::new, |id| id.to_string()),
        "agent_name": record
            .agent_id
            .and_then(|id| names.get(&id).cloned())
            .unwrap_or_else(|| "-".to_string()),
        "endpoint_id": record.endpoint_id.to_string(),
        "model": record.model,
        "input_tokens": record.prompt_tokens,
        "cache_read_tokens": record.cached_tokens,
        "cache_write_tokens": record.cache_write_tokens,
        "cache_write_1h_tokens": record.cache_write_1h_tokens,
        "output_tokens": record.completion_tokens,
        "cost_cny": micro_yuan(record.cost_micro),
        "currency": "CNY",
        "mocked": record.mocked,
        "cache_hit": record.cache_hit,
        // Deprecated compatibility alias; never USD conversion.
        "cost_usd": micro_yuan(record.cost_micro),
    })
}

/// 微元 → 元（`1 元 = 1_000_000 微元`；平台计价货币是元，见模块文档的币种说明）。
fn micro_yuan(micro: u64) -> f64 {
    micro as f64 / 1_000_000.0
}

/// 聚合桶（`endpoint_id` + `model`）。
pub(super) struct UsageBucket {
    endpoint_id: String,
    model: String,
    vendor: &'static str,
    mocked: bool,
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    pub(super) cost_micro: u64,
    pub(super) calls: u64,
}

impl UsageBucket {
    /// 由首条记录建立桶（`vendor` 取该记录的 provider 映射）。
    pub(super) fn new(record: &UsageRecord) -> Self {
        Self {
            endpoint_id: record.endpoint_id.to_string(),
            model: record.model.clone(),
            vendor: model_vendor(record.provider),
            mocked: record.mocked,
            input_tokens: 0,
            output_tokens: 0,
            cost_micro: 0,
            calls: 0,
        }
    }

    /// 桶 → 前端 `ModelUsageAggregate` JSON。
    pub(super) fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "endpoint_id": self.endpoint_id,
            "model": self.model,
            "vendor": self.vendor,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_cny": micro_yuan(self.cost_micro),
            "currency": "CNY",
            "mocked": self.mocked,
            "cost_usd": micro_yuan(self.cost_micro),
            "calls": self.calls,
        })
    }
}

/// [`LlmProvider`] → 前端 `ModelVendor` 词表取值（映射不到给 `custom`，**不猜**厂商）。
fn model_vendor(provider: LlmProvider) -> &'static str {
    match provider {
        LlmProvider::OpenAi => "openai",
        LlmProvider::Anthropic => "anthropic",
        LlmProvider::AzureOpenAi => "azure-openai",
        LlmProvider::DashScope => "qwen",
        LlmProvider::DeepSeek => "deepseek",
        LlmProvider::Zhipu => "zhipu",
        LlmProvider::Moonshot => "moonshot",
        LlmProvider::Ollama => "ollama",
        LlmProvider::Vllm => "vllm",
        // Mock / Gemini / Bedrock / Ark / Hunyuan / Qianfan / MiniMax / 自建兼容端点
        // 在前端 `ModelVendor` 词表里没有对应取值 ⇒ 如实归 custom。
        _ => "custom",
    }
}

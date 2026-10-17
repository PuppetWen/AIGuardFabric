//! 模型用量计量灌入 seed_model_usage（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 模型计量（真实 Meter 计价；调用形态来自 MockProvider）
// ===========================================================================

/// 演示调用载荷（**合成提示词**；token 数由 `ChatRequest`/`MockProvider` 的真实估算逻辑给出）。
pub(super) const DEMO_MODEL_PROMPTS: [(&str, &str); 3] = [
    ("demo-session-1", "请研判这条告警：客服 Copilot 疑似把内部知识库内容外发到外部域名。"),
    ("demo-session-2", "总结本次 MCP 高危工具调用的攻击链节点，并给出处置建议。"),
    ("demo-session-3", "生成本周 AI 资产风险日报的摘要段落，覆盖运行时拦截与凭据暴露两类问题。"),
];

/// 用**真实的** [`Meter`] 记录若干条模型调用计量，供 `/models/usage` 与
/// `/models/usage/aggregate` 读取。
///
/// ## 数据来源（哪一步是"真实"的）
///
/// | 环节 | 实现 | 真实性 |
/// |---|---|---|
/// | 端点 / 模型 / 单价 | 台账里已灌入的 `ModelEndpoint` 资产（`attributes.model`、`input_price_per_ktok`…） | **台账真实值**（不是另一套硬编码数字） |
/// | token 估算 | `agf_aigw::MockProvider::synthesize` → `estimate_usage`（与网关同一份 estimator） | 真实实现，**合成回复** |
/// | 计价与记账 | `agf_aigw::Meter::record` → `meter::breakdown`（微元整数运算、prompt-cache 单价口径） | **真实计量链** |
/// | `latency_ms` | 本机测得的 Mock 合成调用墙钟耗时 | 真实施测值（通常 0~1ms，不编造远端延迟） |
///
/// `mocked = true` 如实落在 `UsageRecord.mocked` 上：这是"无凭据 → 网关既定降级为 Mock"的
/// 正常路径：合成回复保留逻辑 token，用量记录费用为零；台账单价不意味着已调用厂商。
///
/// ## 幂等
/// `meter` 里已有该租户的计量 ⇒ 直接跳过（同一进程内重复灌库不产生重复行）。
///
/// # 降级
/// 台账没有 `ModelEndpoint` 资产时只 `warn`，不写任何记录（端点返回空集合，绝不阻断启动）。
pub fn seed_model_usage(
    store: &ApiStore,
    meter: &Meter,
    tenant: TenantId,
    report: &mut SeedReport,
) -> DomainResult<()> {
    if meter.tenant_totals(tenant).calls > 0 {
        let stat = report.stat(DS_MODEL_USAGE, SYNTHETIC_SOURCE);
        stat.skipped += DEMO_MODEL_PROMPTS.len();
        stat.note = "计量记录已存在（幂等跳过）".to_string();
        return Ok(());
    }
    let assets = store.asset_list_all(tenant)?;
    let Some(endpoint_asset) = assets.iter().find(|a| a.kind == AssetKind::ModelEndpoint) else {
        warn!(dataset = DS_MODEL_USAGE, "台账没有模型端点资产，跳过演示计量（不伪造用量）");
        report.warnings.push(format!("{DS_MODEL_USAGE}：台账没有模型端点资产，跳过演示计量"));
        let stat = report.stat(DS_MODEL_USAGE, SYNTHETIC_SOURCE);
        stat.skipped += 1;
        stat.note = "无模型端点资产（fixtures 未灌入）".to_string();
        return Ok(());
    };
    let agent_id = assets.iter().find(|a| a.kind == AssetKind::Agent).map(|a| a.id);
    let endpoint = demo_model_endpoint(endpoint_asset, tenant);
    let provider = MockProvider::new().with_model(endpoint.model.clone());

    let mut inserted = 0_usize;
    for (session, prompt) in DEMO_MODEL_PROMPTS {
        let request = ChatRequest::simple(endpoint.model.clone(), prompt);
        let started = std::time::Instant::now();
        let response = provider.synthesize(&request);
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // 记录**引擎产出的** UsageRecord：`Meter::record` 内部完成计价（微元）与三级累计。
        let _record = meter.record(tenant, session, agent_id, &endpoint, response.usage, false, true, latency_ms);
        inserted += 1;
        report.stat(DS_MODEL_USAGE, SYNTHETIC_SOURCE).inserted += 1;
    }
    let stat = report.stat(DS_MODEL_USAGE, SYNTHETIC_SOURCE);
    stat.note = format!(
        "真实计量链（agf_aigw::Meter::record）：{inserted} 次调用，端点 {}（model={}，provider={}），mocked=true（无凭据的既定降级路径）",
        endpoint.id,
        endpoint.model,
        endpoint.provider.as_str()
    );
    info!(dataset = DS_MODEL_USAGE, inserted, "演示模型计量已写入 Meter");
    Ok(())
}

/// 由台账 `ModelEndpoint` 资产构造 [`ModelEndpoint`]（单价从 `*_price_per_ktok`（元/千 token）换算为微元）。
///
/// 换算口径与 `agf_core::model::ModelPricing` 一致：**每 1K token 的微元数**
/// （`1 元 = 1_000_000 微元`），因此 `0.001 元/千 token ⇒ 1000 微元/千 token`。
fn demo_model_endpoint(asset: &Asset, tenant: TenantId) -> ModelEndpoint {
    let now = Timestamp::now();
    let prompt_micro_per_1k = attr_f64(asset, "input_price_per_ktok").map_or(0, micro_per_ktok);
    let completion_micro_per_1k = attr_f64(asset, "output_price_per_ktok").map_or(0, micro_per_ktok);
    ModelEndpoint {
        id: asset.id,
        tenant_id: tenant,
        asset_id: asset.id,
        name: asset.name.clone(),
        provider: demo_provider(attr_str(asset, "vendor").as_deref()),
        base_url: attr_str(asset, "base_url").unwrap_or_default(),
        model: attr_str(asset, "model").unwrap_or_else(|| asset.name.clone()),
        modalities: Vec::new(),
        context_window: None,
        max_output_tokens: None,
        supports_streaming: true,
        supports_tools: true,
        // 演示环境没有厂商凭据：`credential_ref = None` 正是网关"改用 Mock"的既定条件之一
        credential_ref: None,
        local_deployment: attr_bool(asset, "local_deployment").unwrap_or(false),
        max_data_class: DataClass::Internal,
        pricing: ModelPricing { prompt_micro_per_1k, completion_micro_per_1k, cached_prompt_micro_per_1k: 0 },
        enabled: true,
        fallback: attr_bool(asset, "fallback").unwrap_or(true),
        priority: u32::try_from(attr_u64(asset, "priority").unwrap_or(1)).unwrap_or(1),
        extra_headers: BTreeMap::new(),
        created_at: now,
        updated_at: now,
    }
}

/// 台账 `vendor` → [`LlmProvider`]（未登记/未知厂商退化为 [`LlmProvider::Mock`]，不猜）。
fn demo_provider(vendor: Option<&str>) -> LlmProvider {
    match vendor.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "vllm" => LlmProvider::Vllm,
        "ollama" => LlmProvider::Ollama,
        "openai" => LlmProvider::OpenAi,
        "anthropic" => LlmProvider::Anthropic,
        "deepseek" => LlmProvider::DeepSeek,
        "qwen" | "dashscope" => LlmProvider::DashScope,
        _ => LlmProvider::Mock,
    }
}

/// 元/千 token → 微元/千 token（负值与非有限值归 0）。
fn micro_per_ktok(yuan_per_ktok: f64) -> u64 {
    let micro = (yuan_per_ktok.max(0.0) * 1_000_000.0).round();
    if micro.is_finite() && micro >= 0.0 { micro.min(u64::MAX as f64) as u64 } else { 0 }
}

/// 台账属性：字符串。
fn attr_str(asset: &Asset, key: &str) -> Option<String> {
    asset.attributes.get(key).and_then(Value::as_str).map(ToString::to_string)
}

/// 台账属性：浮点。
fn attr_f64(asset: &Asset, key: &str) -> Option<f64> {
    asset.attributes.get(key).and_then(Value::as_f64)
}

/// 台账属性：布尔。
fn attr_bool(asset: &Asset, key: &str) -> Option<bool> {
    asset.attributes.get(key).and_then(Value::as_bool)
}

/// 台账属性：无符号整数。
fn attr_u64(asset: &Asset, key: &str) -> Option<u64> {
    asset.attributes.get(key).and_then(Value::as_u64)
}

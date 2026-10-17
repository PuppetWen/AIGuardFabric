//! AI 资产演示画像、字段映射与资产灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 资产
// ===========================================================================

/// 业务键 → 演示画像（**合成，仅为演示**，让 `agents`/`mcps`/`models` 视图有内容）。
#[derive(Debug, Default, Clone, Copy)]
struct DemoProfile {
    /// 端点。
    endpoint: &'static str,
    /// 协议。
    protocol: Option<Protocol>,
    /// 厂商。
    vendor: &'static str,
    /// 版本。
    version: &'static str,
    /// Agent 形态（前端枚举）。
    flavor: &'static str,
    /// 工具数。
    tool_count: u64,
    /// 活跃会话数。
    active_sessions: u64,
    /// 心跳间隔（秒）。
    heartbeat_secs: i64,
    /// 模型名。
    model: &'static str,
    /// 输入单价（元/千 token）。
    price_in: f64,
    /// 输出单价（元/千 token）。
    price_out: f64,
    /// 是否本地部署。
    local_deployment: bool,
    /// 健康度。
    health: &'static str,
    /// Skill 能力标签。
    capabilities: &'static [&'static str],
    /// Skill 出网白名单。
    domains: &'static [&'static str],
    /// Skill 路径白名单。
    paths: &'static [&'static str],
    /// 挂载的 Agent 数。
    attached_agents: u64,
}

/// 取演示画像（未登记的业务键给默认值；**合成，仅为演示**）。
fn demo_profile(business_key: &str) -> DemoProfile {
    match business_key {
        "ast-agent-0001" => DemoProfile {
            endpoint: "https://copilot.example.internal:8443",
            protocol: Some(Protocol::Http),
            vendor: "dify",
            version: "1.8.2",
            flavor: "dify",
            tool_count: 6,
            active_sessions: 12,
            heartbeat_secs: 60,
            ..DemoProfile::default()
        },
        "ast-agent-0002" => DemoProfile {
            endpoint: "http://risk-agent.example.internal:9100",
            protocol: Some(Protocol::Http),
            vendor: "langgraph",
            version: "0.4.1",
            flavor: "langgraph",
            tool_count: 4,
            active_sessions: 3,
            heartbeat_secs: 60,
            ..DemoProfile::default()
        },
        "ast-agent-0003" => DemoProfile {
            endpoint: "http://code-review.example.internal:9200",
            protocol: Some(Protocol::A2a),
            vendor: "autogen",
            version: "0.3.0",
            flavor: "autogen",
            tool_count: 5,
            active_sessions: 1,
            heartbeat_secs: 120,
            ..DemoProfile::default()
        },
        "ast-model-0001" => DemoProfile {
            endpoint: "http://10.20.30.40:8000/v1",
            protocol: Some(Protocol::OpenAiCompat),
            vendor: "vllm",
            version: "v3",
            model: "credit-score-v3",
            price_in: 0.001,
            price_out: 0.002,
            local_deployment: true,
            health: "healthy",
            ..DemoProfile::default()
        },
        "ast-mcp-0001" => DemoProfile {
            endpoint: "http://ops-mcp.example.internal:8081/sse",
            protocol: Some(Protocol::McpSse),
            version: "0.9.7",
            tool_count: 9,
            ..DemoProfile::default()
        },
        "ast-skill-0001" => DemoProfile {
            vendor: "internal-finance",
            version: "1.2.0",
            capabilities: &["read", "write"],
            domains: &["*.example.internal"],
            paths: &["/srv/expense"],
            attached_agents: 2,
            ..DemoProfile::default()
        },
        "ast-cred-0001" | "ast-ds-0001" => DemoProfile { version: "n/a", ..DemoProfile::default() },
        _ => DemoProfile::default(),
    }
}

/// 业务键 → 演示 MCP 工具清单（**合成，仅为演示**）。
///
/// 写入 `Asset.attributes.tools`，是 `GET /api/v1/mcp-servers/{id}/tools` 的**唯一数据源**：
/// 发现侧（`POST /api/v1/assets/discovery`）在真实链路里也会写同一个字段，本函数只是让
/// 演示环境"一开机就有工具清单"。数组元素为对象（含 `name`/`description`/`invocations_24h`/
/// `sensitive_params`/`datasources`）；`capabilities` 与 `risk_level` **不写死**，由
/// `agf_core::mcp::ToolTraits::infer` 按工具名+描述推断（与策略引擎、红队选型同一套规则）。
fn demo_mcp_tools(business_key: &str) -> Value {
    match business_key {
        // 运维 MCP（`ast-mcp-0001`）：读写文件 + 出网 + 知识库检索，覆盖多种能力画像
        "ast-mcp-0001" => serde_json::json!([
            {
                "name": "read_file",
                "description": "读取本机文件内容（只读）",
                "invocations_24h": 128,
                "sensitive_params": ["path"],
                "datasources": ["local-fs"]
            },
            {
                "name": "http_request",
                "description": "向外部 HTTP 接口发起请求并返回响应体",
                "invocations_24h": 42,
                "sensitive_params": ["url", "headers.authorization"],
                "datasources": ["external-http"]
            },
            {
                "name": "search_kb",
                "description": "在企业知识库中做语义检索",
                "invocations_24h": 311,
                "sensitive_params": ["query"],
                "datasources": ["kb-vector"]
            },
            {
                "name": "write_report",
                "description": "把分析结论写入报表库",
                "invocations_24h": 7,
                "sensitive_params": [],
                "datasources": ["report-store"]
            }
        ]),
        // 其余（未登记的 MCP / MCP 客户端）：不给工具清单，端点如实返回空数组
        _ => Value::Array(Vec::new()),
    }
}

/// 把演示画像叠加到资产上（**合成，仅为演示**；不影响台账的领域字段语义）。
fn enrich_asset(asset: &mut Asset, business_key: &str) {
    let profile = demo_profile(business_key);
    if !profile.endpoint.is_empty() {
        asset.endpoint = Some(profile.endpoint.to_string());
    }
    asset.protocol = profile.protocol;
    if !profile.vendor.is_empty() {
        asset.vendor = Some(profile.vendor.to_string());
    }
    if !profile.version.is_empty() {
        asset.version = Some(profile.version.to_string());
    }
    asset.discovery_source = DiscoverySource::AgentReport;
    asset.runtime = Some("k8s".to_string());
    asset.attributes.insert("synthetic".to_string(), Value::from(true));
    match asset.kind {
        AssetKind::Agent => {
            asset.attributes.insert("flavor".to_string(), Value::from(profile.flavor));
            asset.attributes.insert("host".to_string(), Value::from(profile.endpoint));
            asset.attributes.insert("onboarding_mode".to_string(), Value::from("sidecar"));
            asset.attributes.insert("heartbeat_interval_secs".to_string(), Value::from(profile.heartbeat_secs));
            asset.attributes.insert("active_sessions".to_string(), Value::from(profile.active_sessions));
            asset.attributes.insert("tool_count".to_string(), Value::from(profile.tool_count));
        }
        AssetKind::McpServer | AssetKind::McpClient => {
            let tools = demo_mcp_tools(business_key);
            // `tool_count` 与 `tools` 必须同源：前者是列表页的计数，后者是工具清单，
            // 两处对不上就是"编造"（控制台点进去会看到数量与条目不符）。
            let count = tools.as_array().map_or(0, Vec::len);
            asset.attributes.insert("transport".to_string(), Value::from("sse"));
            asset.attributes.insert("tool_count".to_string(), Value::from(count));
            asset.attributes.insert("has_plaintext_secret".to_string(), Value::from(business_key == "ast-mcp-0001"));
            asset.attributes.insert("tools".to_string(), tools);
        }
        AssetKind::ModelEndpoint => {
            asset.attributes.insert("vendor".to_string(), Value::from(profile.vendor));
            asset.attributes.insert("model".to_string(), Value::from(profile.model));
            asset.attributes.insert("base_url".to_string(), Value::from(profile.endpoint));
            asset.attributes.insert("local_deployment".to_string(), Value::from(profile.local_deployment));
            asset.attributes.insert("health".to_string(), Value::from(profile.health));
            asset.attributes.insert("input_price_per_ktok".to_string(), Value::from(profile.price_in));
            asset.attributes.insert("output_price_per_ktok".to_string(), Value::from(profile.price_out));
            asset.attributes.insert("priority".to_string(), Value::from(1));
            asset.attributes.insert("fallback".to_string(), Value::from(true));
            asset.attributes.insert("latency_p95_ms".to_string(), Value::from(320));
        }
        AssetKind::Skill => {
            asset.attributes.insert(
                "capabilities".to_string(),
                Value::from(profile.capabilities.iter().map(|c| (*c).to_string()).collect::<Vec<_>>()),
            );
            asset.attributes.insert(
                "whitelist".to_string(),
                serde_json::json!({
                    "domains": profile.domains,
                    "paths": profile.paths,
                }),
            );
            asset.attributes.insert("attached_agents".to_string(), Value::from(profile.attached_agents));
        }
        _ => {}
    }
}

/// 映射资产类型：fixtures 用简写（`model` / `mcp` / `datasource`），领域模型用规范名。
pub(super) fn map_asset_kind(raw: &str) -> Result<AssetKind, String> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    let canonical = match normalized.as_str() {
        "model" => "model-endpoint",
        "mcp" => "mcp-server",
        "datasource" | "data-source" | "ds" => "data-source",
        other => other,
    };
    AssetKind::parse(canonical)
}

/// 映射数据分级。
pub(super) fn map_data_class(raw: Option<&str>) -> Result<DataClass, String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("internal") => Ok(DataClass::Internal),
        Some("public") => Ok(DataClass::Public),
        Some("confidential") => Ok(DataClass::Confidential),
        Some("restricted") => Ok(DataClass::Restricted),
        Some(other) => Err(format!("未知数据分级: {other}")),
    }
}

/// 映射生命周期：fixtures 的 `active` → 生产、`onboarding` → 试运行。
pub(super) fn map_lifecycle(raw: Option<&str>) -> Result<LifecycleState, String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("active" | "production") => Ok(LifecycleState::Production),
        Some("onboarding" | "trial") => Ok(LifecycleState::Trial),
        Some("requested") => Ok(LifecycleState::Requested),
        Some("under-review") => Ok(LifecycleState::UnderReview),
        Some("changing") => Ok(LifecycleState::Changing),
        Some("archived") => Ok(LifecycleState::Archived),
        Some("rejected") => Ok(LifecycleState::Rejected),
        Some(other) => Err(format!("未知生命周期: {other}")),
    }
}

/// fixtures 条目 → [`Asset`]（返回业务键 + 资产）。
pub(super) fn asset_from_item(item: &Value, tenant: TenantId) -> Result<(String, Asset), String> {
    let business_key = req_str(item, "id")?;
    let name = req_str(item, "name")?;
    let kind = map_asset_kind(&req_str(item, "kind")?)?;

    let mut asset = Asset::new(tenant, kind, name, format!("seed:{business_key}"));
    asset.id = deterministic_id(NS_ASSET, &business_key);
    asset.owner = opt_str(item, "owner");
    asset.department = opt_str(item, "department");
    asset.data_class = map_data_class(opt_str(item, "classification").as_deref())?;
    asset.lifecycle = map_lifecycle(opt_str(item, "lifecycle").as_deref())?;
    asset.risk_score = opt_u8(item, "risk_score");
    asset.exposure_score = asset.risk_score.unwrap_or(0);
    asset.network_zone = opt_str(item, "exposure").map(|raw| match raw.as_str() {
        "public-internet" | "public" => "public".to_string(),
        "dmz" => "dmz".to_string(),
        _ => "endpoint".to_string(),
    });
    asset.tags = str_list(item, "tags");
    asset.attributes.insert("seed_id".to_string(), Value::from(business_key.clone()));
    asset.attributes.insert("open_findings".to_string(), Value::from(opt_u64(item, "open_findings").unwrap_or(0)));
    enrich_asset(&mut asset, &business_key);
    Ok((business_key, asset))
}

/// 灌资产。
pub(super) fn seed_assets(
    store: &ApiStore,
    root: &Path,
    tenant: TenantId,
    report: &mut SeedReport,
    refs: &mut CrossRefs,
) -> DomainResult<()> {
    let file = "assets.json";
    let items = match load_items(root, file) {
        Ok((items, note)) => {
            if let Some(note) = note {
                report.warnings.push(format!("{DS_ASSETS}：{note}"));
            }
            items
        }
        Err(reason) => {
            mark_dataset_unavailable(report, DS_ASSETS, file, &reason);
            return Ok(());
        }
    };
    for item in &items {
        let (business_key, asset) = match asset_from_item(item, tenant) {
            Ok(pair) => pair,
            Err(error) => {
                warn!(dataset = DS_ASSETS, error = %error, "演示资产字段非法，已跳过该条（降级）");
                report.stat(DS_ASSETS, file).errors += 1;
                continue;
            }
        };
        let stat = report.stat(DS_ASSETS, file);
        if store.asset_get(tenant, asset.id)?.is_some() {
            stat.skipped += 1;
        } else {
            settle(store.asset_upsert(&asset), DS_ASSETS, file, stat)?;
        }
        refs.assets_by_business.insert(business_key, asset.id);
        refs.assets_by_name.insert(asset.name.clone(), asset.id);
    }
    Ok(())
}

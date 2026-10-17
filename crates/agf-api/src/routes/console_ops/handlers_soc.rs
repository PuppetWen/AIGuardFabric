//! SOC 类控制台端点：Skill 状态 / 白名单、告警与发现状态别名、升级路由、SOAR、MCP 工具、红队结果、规则测试。

use super::*;

// ===========================================================================
// B. SOC / 生态动作
// ===========================================================================

/// 发现状态流转的控制台别名请求体（`client.ts::updateFindingStatus` 发 `{status}`）。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct FindingStatusAliasBody {
    /// 目标状态（前端写法）。
    #[serde(default)]
    pub status: Option<String>,
    /// 目标状态（平台既有写法）。
    #[serde(default)]
    pub state: Option<String>,
    /// 复核注记。
    #[serde(default)]
    pub verify_note: Option<String>,
    /// 证据等级。
    #[serde(default)]
    pub evidence_level: Option<String>,
}

/// 发现状态流转（`POST /api/v1/findings/{id}/status`）。
///
/// **别名**：业务逻辑与校验全部委托给既有 [`crate::routes::assets::set_finding_state`]
/// （同一个处理器），这里只做两件事：
/// 1. 请求体键名适配（控制台发 `status`，既有处理器读 `state`）；
/// 2. 响应形状适配——控制台声明 `Finding | undefined`（裸对象），既有处理器包了一层
///    `{"finding": …}`，这里拆包返回内层。
///
/// # Errors
/// 权限不足（`findings:write`）、状态非法或发现不存在（均来自既有处理器）。
pub async fn set_finding_status(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<FindingStatusAliasBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let target = body
        .status
        .or(body.state)
        .ok_or_else(|| ApiError::new(DomainError::Validation("status 不能为空".to_string())))?;
    let response = crate::routes::assets::set_finding_state(
        State(state),
        principal,
        Path(id),
        ApiJson(crate::routes::assets::FindingStateBody {
            state: target,
            verify_note: body.verify_note,
            evidence_level: body.evidence_level,
        }),
    )
    .await?;
    Ok(Json(unwrap_entity(response.0, "finding")))
}

/// 告警状态流转的控制台别名请求体（`client.ts::updateAlertStatus` 发 `{status}`）。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct AlertStatusAliasBody {
    /// 目标状态（前端写法：`open`/`acknowledged`/`in-progress`/`resolved`/`suppressed`）。
    #[serde(default)]
    pub status: Option<String>,
    /// 目标状态（平台既有写法：`open`/`acknowledged`/`suppressed`/`escalated`/`closed`）。
    #[serde(default)]
    pub state: Option<String>,
    /// 指派人。
    #[serde(default)]
    pub assignee: Option<String>,
}

/// 告警状态流转（`POST /api/v1/alerts/{id}/status`）。
///
/// **别名**：业务逻辑与校验全部委托给既有 [`crate::routes::soc::set_alert_state`]（同一个处理器），
/// 这里只做请求/响应形状适配：
/// 1. 请求体键名 `status` → `state`；
/// 2. 前端词表补映射——`AlertStatus`（domain.ts）比后端 `AlertState` 多 `in-progress` 与 `resolved`，
///    按 SOC 语义映射：`in-progress` → `acknowledged`（已受理、处理中；后端无"处理中"态），
///    `resolved` → `closed`（已解决即终态）。映射表见 [`map_console_alert_status`]；
/// 3. 响应拆包（控制台声明 `Alert | undefined`，既有处理器包了 `{"alert": …}`）。
///
/// # Errors
/// 权限不足（`alerts:write`）、状态非法或告警不存在（均来自既有处理器）。
pub async fn set_alert_status(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<AlertStatusAliasBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let raw = body
        .status
        .or(body.state)
        .ok_or_else(|| ApiError::new(DomainError::Validation("status 不能为空".to_string())))?;
    let mapped = map_console_alert_status(&raw);
    let response = crate::routes::soc::set_alert_state(
        State(state),
        principal,
        Path(id),
        ApiJson(crate::routes::soc::AlertStateBody { state: mapped, assignee: body.assignee }),
    )
    .await?;
    Ok(Json(unwrap_entity(response.0, "alert")))
}

/// Compatibility projection of the saved, tenant-scoped escalation configuration.
pub async fn list_escalation_routes(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "read")?;
    let config = crate::alert_escalation::get(&state, principal.tenant).await?;
    let routes: Vec<_> = config
        .policies
        .iter()
        .map(|policy| {
            let route = &policy.route;
            let tiers: Vec<_> = route
                .tiers
                .iter()
                .map(|step| {
                    serde_json::json!({
                        "tier":step.level,"channels":step.channels,"targets":[step.target.as_str()],
                        "afterMinutes":step.overdue_minutes,
                    })
                })
                .collect();
            serde_json::json!({"id":format!("sla-{}",route.severity.as_str()),
            "name":format!("sla-{}",route.severity.as_str()),"minSeverity":route.severity,
            "afterMinutes":route.response_minutes,"tiers":tiers,"enabled":route.enabled})
        })
        .collect();
    Ok(Json(serde_json::json!(routes)))
}

/// 案件剧本执行轨迹（`GET /api/v1/cases/{id}/soar-runs`，控制台裸数组）。
///
/// 合并演示内存记录与当前租户持久化执行轨迹，按运行 id 去重。
/// 真实动作由案件执行端点完成；本端点只读取结果，包含演练产生的轨迹。
///
/// 字段投影（`SoarRun` / `SoarStep`，见 `apps/web/src/types/domain.ts`）：
/// - `status`：`RunOutcome::Completed` 且无失败步骤 → `succeeded`；有失败步骤或
///   `Aborted`/`NotStarted` → `failed`（引擎没有 `queued`/`running` 的中间态：`run` 是一次性
///   同步跑完的确定性执行，因此不谎报"运行中"）；
/// - `steps[].output`：引擎 `StepTrace.note`（失败步骤附错误原因）；
/// - `steps[].duration_ms` 恒 `0`：`StepTrace` 不计量单步耗时（与 `/runtime/events` 的
///   `latency_ms=0` 同口径，不编造耗时）。
///
/// 案件 id 非法 → 400；案件不存在 → 404（父资源语义，与 `/cases/{id}/timeline` 同口径）。
///
/// # Errors
/// 权限不足（`cases:read`）、id 非法或案件不存在。
pub async fn list_soar_runs(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case_id = parse_id(&id, "case")?;
    if state.store.case_get_durable(principal.tenant, case_id).await?.is_none() {
        return Err(ApiError::new(DomainError::NotFound { entity: "case", id }));
    }
    let mut runs = state.store.soar_run_list(principal.tenant, case_id)?;
    for record in state.configurations.list::<crate::store::SoarRunRecord>(principal.tenant, "soar-run").await? {
        if record.case_id == case_id {
            runs.retain(|existing| existing.id != record.id);
            runs.push(record);
        }
    }
    runs.sort_by_key(|record| std::cmp::Reverse(record.started_at));
    Ok(Json(serde_json::Value::Array(runs.iter().map(soar_run_json).collect())))
}

/// MCP Server 工具清单（`GET /api/v1/mcp-servers/{id}/tools`，控制台裸数组）。
///
/// 数据源：台账 `Asset.attributes.tools`（发现侧可写入的工具清单；数组元素可以是字符串，
/// 也可以是含 `name`/`description`/`capabilities`/`risk_level`/`invocations_24h`/
/// `sensitive_params`/`datasources` 的对象）。能力与风险等级优先取显式字段，
/// 缺失时用平台既有的 [`agf_core::mcp::ToolTraits::infer`] 从工具名/描述推断
/// （推断规则与策略引擎、红队选型同一套，不另起一套）。
///
/// 台账没有 `tools` 属性时返回空数组（`toolCount` 之类的计数不是工具清单，不能拿它造条目）。
///
/// # Errors
/// 权限不足（`mcps:read`）、id 非法或该 id 不是 MCP 资产。
pub async fn list_mcp_tools(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "mcps", "read")?;
    crate::mcp_gateway::discovery::refresh(&state, principal.tenant).await?;
    let server_id = parse_id(&id, "mcp-server")?;
    let not_found = || ApiError::new(DomainError::NotFound { entity: "mcp-server", id: id.clone() });
    let Some(asset) = state.store.asset_get_durable(principal.tenant, server_id).await? else {
        return Err(not_found());
    };
    if !matches!(asset.kind, AssetKind::McpServer | AssetKind::McpClient) {
        return Err(not_found());
    }
    Ok(Json(serde_json::Value::Array(mcp_tools_from_asset(&asset))))
}

/// 战役逐用例结果（`GET /api/v1/redteam/campaigns/{id}/results`，控制台裸数组）。
///
/// 数据源：`ApiStore::campaign_results`（`store.rs:984`，由
/// [`crate::routes::ecosystem::launch_campaign`] 写入）。
/// 字段投影见 [`campaign_result_json`]：`severity` 取自红队用例库（用例不存在时退化为关联发现的等级，
/// 都没有则取 `info`——未知时不虚报）；`payload` 取用例首轮内容；`modelResponse` 取 transcript
/// 末条的 `content`/`text`（没有该字段时留空）。
///
/// # Errors
/// 权限不足（`redteam:read`）、id 非法或战役不存在。
pub async fn list_campaign_results(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    let campaign_id = parse_id(&id, "redteam-campaign")?;
    let record = state
        .store
        .campaign_get_durable(principal.tenant, campaign_id)
        .await?
        .ok_or(DomainError::NotFound { entity: "redteam-campaign", id })?;
    let views: Vec<serde_json::Value> =
        record.results.iter().map(|result| campaign_result_json(&record, result)).collect();
    Ok(Json(serde_json::Value::Array(views)))
}

/// 规则回归测试（`POST /api/v1/rules/{id}/test`）。
///
/// 复用既有能力（**不重写检测逻辑**）：[`SampleRegression::run_rule`] 跑规则自带的正负样本。
/// 规则先在已加载的规则包（`AppState::rules`）里按 key 查；查不到再用
/// [`RulePackLoader::lenient`] 从规则目录（`AGF_RULES_DIR`，与启动加载同一解析规则）现读一次，
/// 覆盖"规则文件刚改、进程里的包还没重载"的排障场景。
///
/// **样本不通过也是 200**：返回 `RuleTestResult` 对象（控制台据此渲染 TP/FN/TN/FP 与逐样本表），
/// 只有"规则不存在"（404）或"检测条件本身编译失败"（既有 `DomainError`）才是错误。
/// 逐样本 `latencyMs` 恒 0：`agf-scan` 的 `SampleResult` 不计量单样本耗时，这里不编造耗时。
///
/// # Errors
/// 权限不足（`rules:write`）、规则不存在或检测条件编译失败。
pub async fn test_rule(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "write")?;
    let pack = crate::rule_store::pack(&state, principal.tenant).await?;
    let rule = match pack.rules.iter().find(|r| r.key == id || r.name == id) {
        Some(rule) => rule.clone(),
        None => load_rule_from_dir(&state, &id)?,
    };
    let regression = SampleRegression::new();
    let outcome = regression.run_rule(&rule)?;
    let mut true_positive = 0_u64;
    let mut false_negative = 0_u64;
    let mut true_negative = 0_u64;
    let mut false_positive = 0_u64;
    let mut samples: Vec<serde_json::Value> = Vec::new();
    for (index, sample) in outcome.positives.iter().enumerate() {
        if sample.actual_hit {
            true_positive += 1;
        } else {
            false_negative += 1;
        }
        samples.push(sample_json(&rule.key, "positive", index, &sample.sample, sample.actual_hit, sample.passed));
    }
    for (index, sample) in outcome.negatives.iter().enumerate() {
        if sample.actual_hit {
            false_positive += 1;
        } else {
            true_negative += 1;
        }
        samples.push(sample_json(&rule.key, "negative", index, &sample.sample, sample.actual_hit, sample.passed));
    }
    // 内置负样本基线的误报也计入误报总数（与既有 /rules/{key}/regression 同一口径：基线误报同样算失败）
    for (index, sample) in outcome.baseline_false_positives.iter().enumerate() {
        false_positive += 1;
        samples.push(sample_json(&rule.key, "negative", outcome.negatives.len() + index, sample, true, false));
    }
    Ok(Json(serde_json::json!({
        "ruleId": rule.key,
        "ranAt": Timestamp::now(),
        "truePositive": true_positive,
        "falseNegative": false_negative,
        "trueNegative": true_negative,
        "falsePositive": false_positive,
        "samples": samples,
    })))
}

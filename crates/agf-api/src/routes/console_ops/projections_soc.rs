//! SOC / 生态类端点的 JSON 投影辅助（SOAR 轨迹、红队结果、规则样本、适配器、自检、Agent 团队）。

use super::*;

// ===========================================================================
// 剧本执行轨迹投影
// ===========================================================================

/// [`SoarRunRecord`] → 前端 `SoarRun` JSON（口径见 [`list_soar_runs`]）。
pub(super) fn soar_run_json(record: &SoarRunRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id.to_string(),
        "case_id": record.case_id.to_string(),
        "playbook": record.run.playbook_key,
        "dry_run": record.run.dry_run,
        "status": soar_status(&record.run),
        "started_at": record.started_at.to_rfc3339(),
        "finished_at": record.run.finished_at.to_rfc3339(),
        "steps": record.run.trace.iter().map(soar_step_json).collect::<Vec<_>>(),
    })
}

/// 运行结论 → 前端 `SoarRun.status`（无 `queued`/`running` 中间态，理由见 [`list_soar_runs`]）。
fn soar_status(run: &PlaybookRun) -> &'static str {
    match run.outcome {
        RunOutcome::Completed if !run.has_failure() => "succeeded",
        RunOutcome::Completed | RunOutcome::Aborted | RunOutcome::NotStarted => "failed",
    }
}

/// 引擎 `StepTrace` → 前端 `SoarStep`（`duration_ms` 恒 0：引擎不计量单步耗时）。
fn soar_step_json(trace: &StepTrace) -> serde_json::Value {
    let status = match trace.outcome {
        StepOutcome::Succeeded => "done",
        StepOutcome::Skipped => "skipped",
        StepOutcome::Failed => "failed",
    };
    let output = match &trace.error {
        Some(error) if trace.note.is_empty() => format!("失败：{error}"),
        Some(error) => format!("{}｜失败：{error}", trace.note),
        None => trace.note.clone(),
    };
    serde_json::json!({
        "name": trace.name,
        "status": status,
        "output": output,
        "duration_ms": 0,
    })
}

/// 红队战役结果 → 前端 `CampaignResult`（口径见 [`list_campaign_results`]）。
pub(super) fn campaign_result_json(record: &crate::store::CampaignRecord, result: &RedteamResult) -> serde_json::Value {
    let case = record.cases.iter().find(|c| c.key == result.case_key);
    let severity = case.map(|c| c.severity.as_str()).unwrap_or("info");
    let attack_payload = result
        .transcript
        .first()
        .and_then(|v| v.get("content"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let model_response = result
        .transcript
        .last()
        .and_then(|entry| entry.get("content").or_else(|| entry.get("text")))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let outcome = if result.evaluation == agf_core::redteam::EvaluationStatus::ExecutionError {
        "execution-error"
    } else if !result.is_evaluated() {
        "inconclusive"
    } else if !result.succeeded {
        "blocked"
    } else if result.bypass_path.is_some() {
        "bypassed"
    } else {
        "succeeded"
    };
    serde_json::json!({
        "id": result.id.to_string(),
        "campaignId": result.campaign_id.to_string(),
        "findingId": result.finding_id.map(|id| id.to_string()),
        // 控制台字段名是 caseId：这里映射红队用例键（后端结果记录里没有案件 id）
        "caseId": result.case_key,
        "category": result.category.as_str(),
        "target": if result.mocked {record.target_name.clone()} else {result.target_asset_id.to_string()},
        "mocked":result.mocked,
        "evaluation":result.evaluation,
        "evaluationNote":result.evaluation_note,
        "transcript":result.transcript,
        "matchedSignals":result.matched_signals,
        "severity": severity,
        "outcome": outcome,
        "bypassPath": split_bypass_path(result.bypass_path.as_deref()),
        "payload": attack_payload,
        "modelResponse": model_response,
        "evidenceRef": result.evidence_refs.join(", "),
        "ranAt": result.executed_at,
    })
}

/// 绕过路径字符串 → 控制台的分步数组（按常见分隔符切分，去空）。
fn split_bypass_path(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(['→', ';', '；', ',', '，', '、'])
        .flat_map(|part| part.split("->"))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// 从规则目录现读一条规则（内存包中没有时用，与启动加载同一解析规则）。
///
/// # Errors
/// 规则目录不可读、加载失败或规则不存在。
pub(super) fn load_rule_from_dir(state: &AppState, key: &str) -> Result<agf_core::rule::RuleDefinition, ApiError> {
    let dir = crate::state::resolve_dir("AGF_RULES_DIR", &state.config.project_root, &["rules"]);
    if dir.is_dir() {
        if let Ok(pack) = RulePackLoader::lenient().load_dir(&RulesDir::new(&dir)) {
            if let Some(rule) = pack.rules.iter().find(|r| r.key == key || r.name == key) {
                return Ok(rule.clone());
            }
        }
    }
    Err(ApiError::new(DomainError::NotFound { entity: "rule", id: key.to_string() }))
}

/// 单条样本 → 前端 `RuleSample`（`latencyMs` 恒 0：`agf-scan` 不计量单样本耗时）。
pub(super) fn sample_json(
    rule_key: &str,
    label: &str,
    index: usize,
    payload: &str,
    matched: bool,
    passed: bool,
) -> serde_json::Value {
    let note = if passed {
        String::new()
    } else if label == "positive" {
        "正样本未命中".to_string()
    } else {
        "负样本被误命中".to_string()
    };
    serde_json::json!({
        "id": format!("{rule_key}-{label}-{}", index + 1),
        "ruleId": rule_key,
        "label": label,
        "payload": payload,
        "matched": matched,
        "latencyMs": 0,
        "note": note,
    })
}

/// 适配器注册表快照（元信息 + 健康记录），两个适配器端点共用。
///
/// `mock_only` 注册表零配置可用且**零网络**（Mock 模式不触达任何外部系统），因此可以在请求内
/// 现场装配；健康记录来自各适配器自身的 `health_check()`（Mock 态恒为 `degraded`）。
///
/// # Errors
/// 内置注册表装配失败。
pub(super) async fn adapter_registry_snapshot(
    state: &AppState,
    principal: &Principal,
) -> Result<(Vec<AdapterMetadata>, std::collections::BTreeMap<String, AdapterHealthRecord>), ApiError> {
    Ok(crate::integration_store::snapshot(state, principal.tenant).await?)
}

/// 适配器元信息 + 健康记录 → 前端 `Adapter`（口径见 [`list_adapters`]）。
pub(super) fn adapter_json(meta: &AdapterMetadata, health: Option<&AdapterHealthRecord>) -> serde_json::Value {
    let capabilities: Vec<String> =
        meta.capabilities.iter().map(|c| agf_core::adapter::AdapterCapability::as_str(c).to_string()).collect();
    serde_json::json!({
        "id": meta.name,
        "name": meta.display_name,
        "category": frontend_adapter_category(meta),
        "vendor": meta.vendor,
        "health": health.map_or("unknown", |record| match record.status {
            agf_adapters::health::HealthStatus::Available => "healthy",
            agf_adapters::health::HealthStatus::Degraded => "degraded",
            agf_adapters::health::HealthStatus::Unavailable => "unhealthy",
        }),
        "mock": health.is_some_and(|record| record.mocked),
        "configured": health.is_some_and(|record| record.configured),
        "health_note": health.and_then(|record| record.message.as_ref()),
        "capabilities": capabilities,
        "version": meta.version,
        // 注册表不保存同步时间与配置值：如实留空（前端据此渲染"未配置"提示）
        "lastSyncAt": serde_json::Value::Null,
        "latencyMs": health.and_then(|record| record.latency_ms),
        "config": serde_json::Map::<String, serde_json::Value>::new(),
        "degradedBehavior": meta.degradation,
    })
}

/// 后端适配器分类 → 前端 `AdapterCategory`。
///
/// 后端词表是 `message`/`itsm`/`siem`，前端是
/// `llm-provider|edr|siem|soar|iam|cloud|dlp|notify|storage`，语义对应关系：
/// 通知渠道 → `notify`；工单/ITSM → `soar`；安全设备/平台 → 按厂商细分
/// （`syslog-forwarder` → `siem`、`edr-isolation` → `edr`、`iam-scim` → `iam`）。
pub(super) fn frontend_adapter_category(meta: &AdapterMetadata) -> &'static str {
    match meta.name.as_str() {
        // 注册名见 `agf_adapters::vendors::BUILTIN_NAMES`
        "syslog-forwarder" | "syslog" => "siem",
        "edr-isolation" | "edr" => "edr",
        "iam-scim" => "iam",
        _ => match meta.category {
            AdapterCategory::Notification => "notify",
            AdapterCategory::Itsm => "soar",
            AdapterCategory::SecurityPlatform => "siem",
        },
    }
}

/// 云团队 → 前端 `AgentTeam`（口径见 [`list_agent_teams`]）。
pub(super) fn agent_team_json(
    team: &agf_core::cloud::AgentTeam,
    calls: &[agf_core::cloud::CrossTeamCall],
) -> serde_json::Value {
    let members: Vec<serde_json::Value> = team
        .agents
        .iter()
        .map(|agent| {
            serde_json::json!({
                "id": agent.cloud_agent_id,
                "name": agent.name,
                "role": member_role(&agent.role_names),
                "model": agent.models.first().cloned().unwrap_or_default(),
                "status": member_status(&agent.status),
                // 云侧 fixtures 不含调用计数：如实为 0（不编造）
                "invocations24h": 0,
            })
        })
        .collect();
    let dag: Vec<serde_json::Value> = team
        .orchestration
        .iter()
        .map(|node| {
            let role = node
                .agent_ids
                .first()
                .and_then(|id| team.agents.iter().find(|agent| &agent.cloud_agent_id == id))
                .map_or("worker", |agent| member_role(&agent.role_names));
            serde_json::json!({
                "id": node.node_id,
                "label": node.name,
                "role": role,
                "dependsOn": node.depends_on,
            })
        })
        .collect();
    let calls_24h = calls
        .iter()
        .filter(|call| call.from_team_id == team.cloud_team_id || call.to_team_id == team.cloud_team_id)
        .count();
    serde_json::json!({
        "id": team.id.to_string(),
        // AgentTeams 的 team id 即控制台的 workspace 标识
        "workspaceId": team.cloud_team_id,
        "name": team.name,
        "region": agf_alicloud::mock::FIXTURE_REGION,
        "memberCount": team.agents.len(),
        "members": members,
        "dag": dag,
        "crossTeamCalls24h": calls_24h,
        // 风险分：未纳管 Agent 占比（0-100），与 agentteams::managed_summary 同口径
        "riskScore": team_risk_score(team),
        "createdAt": team.created_at,
    })
}

/// 未纳管 Agent 占比作为团队风险分（0-100）。
fn team_risk_score(team: &agf_core::cloud::AgentTeam) -> u8 {
    let total = team.agents.len();
    if total == 0 {
        return 0;
    }
    let unmanaged = team.agents.iter().filter(|agent| agent.asset_id.is_none()).count();
    u8::try_from(unmanaged * 100 / total).unwrap_or(0)
}

/// 云侧角色名 → 前端 `AgentTeamMember.role`（关键词规则，可解释）。
fn member_role(role_names: &[String]) -> &'static str {
    let hay = role_names.join(" ").to_lowercase();
    let has = |keys: &[&str]| keys.iter().any(|k| hay.contains(k));
    if has(&["orchestr", "编排", "主控", "调度", "coordinator"]) {
        "orchestrator"
    } else if has(&["critic", "评审", "研判", "分析", "审计", "audit", "review"]) {
        "critic"
    } else if has(&["retriev", "检索", "查询", "搜索", "search", "rag"]) {
        "retriever"
    } else if has(&["tool", "工具", "执行器", "executor"]) {
        "tool-agent"
    } else {
        "worker"
    }
}

/// 云侧运行状态 → 前端 `AgentTeamMember.status`。
fn member_status(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "running" | "active" | "online" | "healthy" => "active",
        "stopped" | "offline" | "failed" | "unhealthy" => "offline",
        // `idle`/`pending`/未知：按"空闲"处理（既不是活跃也不是离线）
        _ => "idle",
    }
}

/// 读对象字段（非对象/缺字段返回 `None`）。
pub(super) fn object_str(item: &serde_json::Value, key: &str) -> Option<String> {
    item.get(key).and_then(serde_json::Value::as_str).map(ToString::to_string)
}

/// 读对象里的无符号整数字段。
pub(super) fn object_u64(item: &serde_json::Value, key: &str) -> Option<u64> {
    item.get(key).and_then(serde_json::Value::as_u64)
}

/// 读对象里的字符串数组字段（也接受逗号分隔的单个字符串）。
pub(super) fn object_list(item: &serde_json::Value, key: &str) -> Vec<String> {
    match item.get(key) {
        Some(serde_json::Value::Array(items)) => {
            items.iter().filter_map(serde_json::Value::as_str).map(ToString::to_string).collect()
        }
        Some(serde_json::Value::String(raw)) => {
            raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string).collect()
        }
        _ => Vec::new(),
    }
}

/// 读字符串数组值。
pub(super) fn value_string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
        .unwrap_or_default()
}

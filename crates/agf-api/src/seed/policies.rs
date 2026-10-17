//! 策略（policies）映射与灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 策略
// ===========================================================================

/// 映射策略动作（兼容 fixtures 的 `require-approval` 写法）。
pub(super) fn map_policy_action(raw: &str) -> Result<PolicyAction, String> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    if normalized == "require-approval" {
        return Ok(PolicyAction::Approval);
    }
    PolicyAction::parse(&normalized)
}

/// 业务键 → 策略优先级（与 fixtures 的声明顺序一致，数值小者先匹配）。
fn policy_priority(business_key: &str) -> u32 {
    match business_key {
        "pol-0001" => 10,
        "pol-0002" => 20,
        _ => 30,
    }
}

/// 业务键 → 拦截点。
fn policy_intercept_points(business_key: &str) -> Vec<InterceptPoint> {
    match business_key {
        "pol-0002" => vec![InterceptPoint::McpProxy, InterceptPoint::ProcessHook],
        "pol-0003" => vec![InterceptPoint::AiGateway],
        _ => vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway],
    }
}

/// 业务键 → 结构化条件（把 fixtures 的 rule DSL **等价**映射为可求值的结构化条件）。
///
/// fixtures 的 `rule` 是演示用 DSL 字符串（`input matches /…/i`、`tool.name == "shell_exec"`），
/// 不是 Rego/CEL 语法，直接塞进 `source` 编译会失败；因此原 DSL 保留在 `Policy::source`
/// 供控制台展示，求值走这里的等价结构化条件（`PolicyEngine::validate_source` 对
/// `Structured` 直接通过，热重载不会因演示策略报错）。
fn policy_structured(business_key: &str) -> StructuredCondition {
    match business_key {
        "pol-0001" => StructuredCondition {
            domains: vec![RiskDomain::PromptAttack],
            min_severity: Some(Severity::High),
            ..StructuredCondition::default()
        },
        "pol-0002" => StructuredCondition {
            tool_denylist: vec!["shell_exec".to_string()],
            require_approval: true,
            ..StructuredCondition::default()
        },
        "pol-0003" => StructuredCondition {
            domains: vec![RiskDomain::ModelData],
            min_severity: Some(Severity::Medium),
            ..StructuredCondition::default()
        },
        _ => StructuredCondition::default(),
    }
}

/// fixtures 条目 → [`Policy`]。
pub(super) fn policy_from_item(item: &Value, tenant: TenantId) -> Result<(String, Policy), String> {
    let business_key = req_str(item, "id")?;
    let name = req_str(item, "name")?;
    let effect = req_str(item, "effect")?;
    let rule = opt_str(item, "rule").unwrap_or_default();
    let target = opt_str(item, "target").unwrap_or_default();
    let enforcement = opt_str(item, "enforcement").unwrap_or_default();
    let at = opt_timestamp(item, "created_at").unwrap_or_else(Timestamp::now);

    let mut policy = Policy {
        id: deterministic_id(NS_POLICY, &business_key),
        tenant_id: tenant,
        name,
        description: format!("演示策略（合成）：target={target} / enforcement={enforcement} / DSL={rule}"),
        language: PolicyLanguage::Structured,
        source: rule,
        structured: policy_structured(&business_key),
        action: map_policy_action(&effect)?,
        priority: policy_priority(&business_key),
        intercept_points: policy_intercept_points(&business_key),
        scope_agent_ids: Vec::new(),
        scope_departments: Vec::new(),
        enabled: true,
        dry_run: false,
        quota_id: None,
        degrade_endpoint_id: None,
        content_hash: String::new(),
        signature: String::new(),
        version: opt_u64(item, "version").and_then(|v| u32::try_from(v).ok()).unwrap_or(1),
        created_at: at,
        updated_at: at,
        deleted_at: None,
    };
    policy.content_hash = policy.compute_hash();
    Ok((business_key, policy))
}

/// 灌策略（按名称判重，与 [`ApiStore::policy_upsert`] 的语义一致）。
pub(super) fn seed_policies(
    store: &ApiStore,
    root: &Path,
    tenant: TenantId,
    report: &mut SeedReport,
    refs: &mut CrossRefs,
) -> DomainResult<()> {
    let file = "policies.json";
    let items = match load_items(root, file) {
        Ok((items, note)) => {
            if let Some(note) = note {
                report.warnings.push(format!("{DS_POLICIES}：{note}"));
            }
            items
        }
        Err(reason) => {
            mark_dataset_unavailable(report, DS_POLICIES, file, &reason);
            return Ok(());
        }
    };
    let existing: BTreeMap<String, Id> = store.policy_list(tenant)?.into_iter().map(|p| (p.name, p.id)).collect();
    for item in &items {
        let (business_key, policy) = match policy_from_item(item, tenant) {
            Ok(pair) => pair,
            Err(error) => {
                warn!(dataset = DS_POLICIES, error = %error, "演示策略字段非法，已跳过该条（降级）");
                report.stat(DS_POLICIES, file).errors += 1;
                continue;
            }
        };
        if let Some(existing_id) = existing.get(&policy.name).copied() {
            report.stat(DS_POLICIES, file).skipped += 1;
            refs.policies.insert(business_key, existing_id);
            continue;
        }
        let name = policy.name.clone();
        let stat = report.stat(DS_POLICIES, file);
        match store.policy_upsert(tenant, policy) {
            Ok(stored) => {
                stat.inserted += 1;
                refs.policies.insert(business_key, stored.id);
            }
            Err(error) if !is_fatal_backend_error(&error) => {
                warn!(dataset = DS_POLICIES, policy = %name, error = %error, "演示策略写入失败，已跳过");
                stat.errors += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

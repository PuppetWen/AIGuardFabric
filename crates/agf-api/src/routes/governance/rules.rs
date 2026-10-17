//! 规则库路由：列表、概览、详情与正负样本回归。

use super::*;

// ===========================================================================
// 规则
// ===========================================================================

/// 规则库列表（`GET /api/v1/rules`）。
///
/// # Errors
/// 过滤参数非法。
pub async fn list_rules(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    let pack = crate::rule_store::pack(&state, principal.tenant).await?;
    let domain = match query.filter("domain") {
        Some(raw) => Some(RiskDomain::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?),
        None => None,
    };
    let severity = match query.filter("severity") {
        Some(raw) => Some(Severity::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?),
        None => None,
    };
    let enabled = query.filter_bool("enabled")?;
    let rules: Vec<RuleDefinition> = pack
        .rules
        .iter()
        .filter(|r| domain.is_none_or(|d| r.domain == d))
        .filter(|r| severity.is_none_or(|s| r.severity == s))
        .filter(|r| enabled.is_none_or(|e| r.enabled == e))
        .cloned()
        .collect();
    let page = query.paginate_vec(&rules, |r| format!("{} {} {}", r.key, r.name, r.description), |r| r.key.clone());
    let mut value = query.render_page(&page)?;
    let can_write = principal.require(&state, "rules", "write").is_ok();
    value["can_write"] = serde_json::json!(can_write);
    if let Some(items) = value.get_mut("items").and_then(serde_json::Value::as_array_mut) {
        for item in items {
            item["read_only"] = serde_json::json!(!can_write);
            item["lifecycle"] = serde_json::json!(if item["enabled"] == false {
                "disabled"
            } else if item["rollout_percent"].as_u64().unwrap_or(100) < 100 {
                "gray"
            } else {
                "ga"
            });
        }
    }
    Ok(Json(value))
}

/// 规则库概览（`GET /api/v1/rules/summary`）。
///
/// # Errors
/// 权限不足。
pub async fn rules_summary(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    let pack = crate::rule_store::pack(&state, principal.tenant).await?;
    let mut by_domain: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_severity: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for rule in &pack.rules {
        *by_domain.entry(rule.domain.as_str().to_string()).or_insert(0) += 1;
        *by_severity.entry(rule.severity.as_str().to_string()).or_insert(0) += 1;
        *by_kind.entry(rule.kind.as_str().to_string()).or_insert(0) += 1;
    }
    let coverage: std::collections::BTreeMap<String, usize> = RiskDomain::all()
        .into_iter()
        .map(|d| (d.as_str().to_string(), by_domain.get(d.as_str()).copied().unwrap_or(0)))
        .collect();
    let missing_samples: Vec<String> =
        pack.rules.iter().filter(|r| !r.samples.is_complete()).map(|r| r.key.clone()).collect();
    Ok(Json(serde_json::json!({
        "total": pack.len(),
        "by_domain": by_domain,
        "by_severity": by_severity,
        "by_kind": by_kind,
        "coverage": coverage,
        "min_rules_per_domain": agf_scan::MIN_RULES_PER_CORE_DOMAIN,
        "missing_samples": missing_samples,
        "load_report": serde_json::to_value(&pack.report)?,
        "pack_fingerprint": pack.report.pack_fingerprint,
    })))
}

/// 规则详情（`GET /api/v1/rules/{key}`）。
///
/// # Errors
/// 规则不存在。
pub async fn get_rule(
    State(state): State<AppState>,
    principal: Principal,
    Path(key): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    let rule = crate::rule_store::get(&state, principal.tenant, &key).await?;
    Ok(Json(serde_json::json!({
        "rule": rule,
        "yaml": serde_yaml::to_string(&rule).map_err(|e|DomainError::Internal(e.to_string()))?,
        "content_hash": rule.content_hash(),
        "validation": rule.validate().err(),
        "samples_complete": rule.samples.is_complete(),
        "can_write": principal.require(&state, "rules", "write").is_ok(),
    })))
}

/// 正负样本回归 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct RegressionBody {
    /// 回归范围：`rule`（默认）或 `pack`。
    #[serde(default)]
    pub scope: Option<String>,
}

/// 正负样本回归（`POST /api/v1/rules/{key}/regression`）。
///
/// # Errors
/// 规则不存在或回归执行失败。
pub async fn run_regression(
    State(state): State<AppState>,
    principal: Principal,
    Path(key): Path<String>,
    ApiJson(body): ApiJson<RegressionBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "write")?;
    let regression = SampleRegression::new();
    let scope = body.scope.unwrap_or_else(|| "rule".to_string());
    if scope == "pack" {
        let pack = crate::rule_store::pack(&state, principal.tenant).await?;
        let report = regression.run_pack(&pack)?;
        return Ok(Json(serde_json::json!({
            "scope": "pack",
            "report": serde_json::to_value(&report)?,
            "green": report.is_green(),
            "failing_rules": report.failing_rules(),
            "summary": report.summary_line(),
        })));
    }
    let rule = crate::rule_store::get(&state, principal.tenant, &key).await?;
    let outcome = regression.run_rule(&rule)?;
    Ok(Json(serde_json::json!({
        "scope": "rule",
        "outcome": serde_json::to_value(&outcome)?,
        "passed": outcome.passed,
        "failures": outcome.failure_count(),
        "notes": outcome.failure_notes(),
    })))
}

//! 风险发现（findings）映射与灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 风险发现
// ===========================================================================

/// 映射安全域：fixtures 的 `category` 优先，其次 `domain`，最后尝试领域枚举的别名。
pub(super) fn map_risk_domain(domain: &str, category: &str) -> Result<RiskDomain, String> {
    let by_category = match category.trim().to_ascii_lowercase().as_str() {
        "prompt-injection" | "jailbreak" | "direct-injection" | "indirect-injection" => RiskDomain::PromptAttack,
        "credential-leak" | "credential-theft" => RiskDomain::CredentialLeak,
        "rag-poison" | "rag-poisoning" => RiskDomain::RagPoison,
        // `exposure`（端点未鉴权暴露）归"工具与权限滥用"：本质是越权可达
        "tool-abuse" | "exposure" | "privilege-escalation" | "lateral-movement" => RiskDomain::ToolAbuse,
        "model-data" | "data-exfiltration" | "supply-chain" | "resource-exhaustion" => RiskDomain::ModelData,
        _ => return resolve_domain_by_name(domain, category),
    };
    Ok(by_category)
}

/// 按 `domain` 字段/枚举别名兜底解析安全域。
fn resolve_domain_by_name(domain: &str, category: &str) -> Result<RiskDomain, String> {
    let by_domain = match domain.trim().to_ascii_lowercase().as_str() {
        "runtime" => Some(RiskDomain::PromptAttack),
        "identity" => Some(RiskDomain::CredentialLeak),
        "data" => Some(RiskDomain::ModelData),
        "asset" | "network" => Some(RiskDomain::ToolAbuse),
        _ => None,
    };
    by_domain
        .or_else(|| RiskDomain::parse(domain).ok())
        .ok_or_else(|| format!("无法映射安全域：domain={domain} category={category}"))
}

/// 映射发现状态。
fn map_finding_state(raw: Option<&str>) -> Result<FindingState, String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        // fixtures 的 `open` 对应领域模型的"待复核"
        None | Some("open" | "pending") => Ok(FindingState::Pending),
        Some("code-reviewed") => Ok(FindingState::CodeReviewed),
        Some("verified") => Ok(FindingState::Verified),
        Some("false-positive") => Ok(FindingState::FalsePositive),
        Some("fixed") => Ok(FindingState::Fixed),
        Some(other) => Err(format!("未知发现状态: {other}")),
    }
}

/// 演示置信度（由等级派生，保证可复现）。
fn demo_confidence(severity: Severity) -> f32 {
    match severity {
        Severity::Critical => 0.9,
        Severity::High => 0.75,
        Severity::Medium => 0.6,
        Severity::Low => 0.4,
        Severity::Info => 0.2,
    }
}

/// fixtures 条目 → [`Finding`]（引用不可解析时 `warn` 并计入 `errors`，条目仍写入但引用置空）。
pub(super) fn finding_from_item(
    item: &Value,
    tenant: TenantId,
    refs: &CrossRefs,
    stat: &mut DatasetReport,
) -> Result<(String, Finding), String> {
    let business_key = req_str(item, "id")?;
    let severity = Severity::parse(&req_str(item, "severity")?).map_err(|e| format!("{business_key}: {e}"))?;
    let category = opt_str(item, "category").unwrap_or_default();
    let domain = map_risk_domain(&opt_str(item, "domain").unwrap_or_default(), &category)?;

    let asset_key = opt_str(item, "asset_id");
    let asset_name = opt_str(item, "asset");
    let asset_id = asset_key
        .as_deref()
        .and_then(|key| refs.asset(key))
        .or_else(|| asset_name.as_deref().and_then(|name| refs.asset_by_name(name)));
    if asset_id.is_none() && (asset_key.is_some() || asset_name.is_some()) {
        warn!(
            dataset = DS_FINDINGS,
            finding = %business_key,
            asset_key = asset_key.as_deref().unwrap_or("-"),
            "发现引用的资产未解析到（该引用置空，条目仍写入）"
        );
        stat.errors += 1;
    }

    let title = req_str(item, "title")?;
    let rule_key = opt_str(item, "rule_id").unwrap_or_default();
    let evidence_ref = opt_str(item, "evidence");
    let at = opt_timestamp(item, "detected_at").unwrap_or_else(Timestamp::now);
    let summary = opt_str(item, "description").unwrap_or_else(|| title.clone());

    let mut finding = Finding::new(
        tenant,
        domain,
        severity,
        asset_name.clone().unwrap_or_else(|| asset_key.clone().unwrap_or_else(|| title.clone())),
        title.clone(),
        summary.clone(),
        opt_str(item, "fix").unwrap_or_else(|| format!("按规则 {rule_key} 的指引加固并复测（演示数据）")),
    );
    finding.id = deterministic_id(NS_FINDING, &business_key);
    finding.category = category.clone();
    finding.asset_id = asset_id;
    finding.description = summary;
    finding.state = map_finding_state(opt_str(item, "status").as_deref())?;
    // 有证据引用 → "部分证据"（合成数据不宣称已复现）；无引用保持 unknown
    finding.evidence_level = if evidence_ref.is_some() { EvidenceLevel::Partial } else { EvidenceLevel::Unknown };
    finding.confidence = demo_confidence(severity);
    finding.source_origin = if opt_str(item, "source").unwrap_or_default().contains("scan") {
        "scan-confirmed".to_string()
    } else {
        "manual".to_string()
    };
    if !rule_key.is_empty() {
        finding.rule_keys.push(rule_key.clone());
    }
    if let Some(reference) = &evidence_ref {
        let hash = agf_core::secret::content_hash(&format!("{business_key}|{title}"));
        finding.evidence_refs.push(reference.clone());
        finding.evidence.push(Evidence::new(
            format!("EV-{business_key}"),
            opt_str(item, "source").unwrap_or_else(|| "tool-output".to_string()),
            format!("演示证据（合成）：{reference}"),
            hash,
        ));
    }
    finding.first_seen_at = at;
    finding.last_seen_at = at;
    finding.created_at = at;
    finding.updated_at = at;
    Ok((business_key, finding))
}

/// 灌风险发现。
pub(super) fn seed_findings(
    store: &ApiStore,
    root: &Path,
    tenant: TenantId,
    report: &mut SeedReport,
    refs: &mut CrossRefs,
) -> DomainResult<()> {
    let file = "findings.json";
    let items = match load_items(root, file) {
        Ok((items, note)) => {
            if let Some(note) = note {
                report.warnings.push(format!("{DS_FINDINGS}：{note}"));
            }
            items
        }
        Err(reason) => {
            mark_dataset_unavailable(report, DS_FINDINGS, file, &reason);
            return Ok(());
        }
    };
    for item in &items {
        let mapped = {
            let stat = report.stat(DS_FINDINGS, file);
            finding_from_item(item, tenant, refs, stat)
        };
        let (business_key, finding) = match mapped {
            Ok(pair) => pair,
            Err(error) => {
                warn!(dataset = DS_FINDINGS, error = %error, "演示发现字段非法，已跳过该条（降级）");
                report.stat(DS_FINDINGS, file).errors += 1;
                continue;
            }
        };
        let stat = report.stat(DS_FINDINGS, file);
        if store.finding_get(tenant, finding.id)?.is_some() {
            stat.skipped += 1;
        } else {
            settle(store.finding_insert(&finding), DS_FINDINGS, file, stat)?;
        }
        refs.findings.insert(business_key, finding.id);
    }
    Ok(())
}

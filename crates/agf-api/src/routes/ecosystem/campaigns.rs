//! Campaign execution, cancellation, evidence and explicit retests.
use super::campaign_requests::{CampaignBody, prepare};
use super::*;
use crate::store::CampaignRecord;

pub async fn launch_campaign(
    State(state): State<AppState>,
    principal: Principal,
    headers: axum::http::HeaderMap,
    ApiJson(body): ApiJson<CampaignBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "redteam", "execute")?;
    let submission = super::campaign_submission::identity(&principal, &headers, &body)?;
    if let Some((id, fingerprint)) = &submission {
        if let Some(existing) = state.store.campaign_get_durable(principal.tenant, *id).await? {
            super::campaign_submission::matches(&existing, fingerprint)?;
            return response(&existing);
        }
    }
    let Some(mut record) = prepare(&state, &principal, body)? else {
        return Ok((
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"skipped":true,"reason":"No cases in this scheduled partition"})),
        ));
    };
    if record.execution_mode.as_deref() == Some("agent-http") {
        principal.require(&state, "agents", "read")?;
        let profile_id =
            record.target_profile_id.ok_or_else(|| DomainError::Validation("Agent target is required".into()))?;
        let profile = super::agent_targets::load(&state, principal.tenant, profile_id).await?;
        if !profile.enabled || Some(profile.version) != record.target_profile_version {
            return Err(
                DomainError::Conflict("Agent target changed or was disabled; refresh before launching".into()).into()
            );
        }
        let asset = state.store.asset_get_durable(principal.tenant, profile.asset_id).await?;
        if !asset.is_some_and(|row| row.kind == agf_core::enums::AssetKind::Agent && row.is_live()) {
            return Err(DomainError::NotFound { entity: "agent-asset", id: profile.asset_id.to_string() }.into());
        }
        record.campaign.target_agent_ids = vec![profile.asset_id];
        record.target_name = profile.name;
    } else if record.execution_mode.as_deref() == Some("mcp-http") {
        principal.require(&state, "mcps", "read")?;
        let profile_id =
            record.target_profile_id.ok_or_else(|| DomainError::Validation("MCP target is required".into()))?;
        let profile = super::mcp_targets::load(&state, principal.tenant, profile_id).await?;
        if !profile.enabled || Some(profile.version) != record.target_profile_version {
            return Err(
                DomainError::Conflict("MCP target changed or was disabled; refresh before launching".into()).into()
            );
        }
        if record.cases.iter().any(|case| case.key == "RT-MCP-003")
            && (profile.detail_tool_name.is_none() || profile.detail_argument_name.is_none())
        {
            return Err(
                DomainError::Validation("RT-MCP-003 requires a second read-only MCP tool and argument".into()).into()
            );
        }
        let asset = state.store.asset_get_durable(principal.tenant, profile.asset_id).await?;
        if !asset.is_some_and(|row| row.kind == agf_core::enums::AssetKind::McpServer && row.is_live()) {
            return Err(DomainError::NotFound { entity: "mcp-asset", id: profile.asset_id.to_string() }.into());
        }
        record.campaign.target_mcp_ids = vec![profile.asset_id];
        record.target_name = profile.name;
    }
    if let Some((id, fingerprint)) = submission {
        record.campaign.id = id;
        record.request_fingerprint = Some(fingerprint);
    }
    accepted(state, record, principal).await
}

fn response(record: &CampaignRecord) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(serde_json::json!({"task_id":record.campaign.id,"campaign":record.view()?})),
    ))
}

async fn accepted(
    state: AppState,
    record: CampaignRecord,
    principal: Principal,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    let (record, inserted) = state.store.campaign_submit_durable(&record).await?;
    if !inserted {
        return response(&record);
    }
    let id = record.campaign.id;
    let tenant = record.campaign.tenant_id;
    if let Err(error) = state
        .audit(
            tenant,
            AuditAction::Execute,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "redteam-campaign"),
            AuditTarget::new("redteam-campaign", Some(id.to_string()), Some(record.campaign.name.clone())),
            "Campaign accepted with immutable inputs",
        )
        .await
    {
        tracing::warn!(task_id=%id,error=%error,"Campaign audit failed after task commit");
    }
    let response = serde_json::json!({"task_id":id,"campaign":record.view()?});
    tokio::spawn(async move {
        match super::campaign_execution::execute(&state, tenant, id).await {
            Ok(done) => state.publish(crate::state::WsEvent {
                kind: "redteam".into(),
                tenant_id: tenant,
                at: Timestamp::now(),
                payload: serde_json::json!({"campaign_id":id,"state":done.campaign.state}),
            }),
            Err(error) => tracing::error!(task_id=%id,error=%error,"Cannot persist campaign terminal state"),
        }
    });
    Ok((axum::http::StatusCode::ACCEPTED, Json(response)))
}

pub async fn list_campaigns(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    let page = state.store.campaign_page_durable(principal.tenant, &query).await?;
    let mut value = query.render_page(&page)?;
    value["can_execute"] = principal.require(&state, "redteam", "execute").is_ok().into();
    Ok(Json(value))
}

pub(super) async fn load(state: &AppState, principal: &Principal, id: &str) -> ApiResult<CampaignRecord> {
    principal.require(state, "redteam", "read")?;
    state
        .store
        .campaign_get_durable(principal.tenant, parse_id(id, "redteam-campaign")?)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "redteam-campaign", id: id.into() }.into())
}

pub async fn get_campaign(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let record = load(&state, &principal, &id).await?;
    Ok(Json(serde_json::json!({"campaign":record.view()?,"results":record.results})))
}

pub async fn campaign_report(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let record = load(&state, &principal, &id).await?;
    Ok(Json(
        serde_json::json!({"report":record.report,"state":record.campaign.state,"execution_mode":record.execution_mode,
        "ci_gate":record.campaign.ci_gate,"ci_passed":record.report.as_ref().filter(|_|record.campaign.ci_gate).map(|r|r.ci_passed),
        "markdown":record.report.as_ref().map(|r|&r.markdown),"comparison":record.comparison}),
    ))
}

pub async fn campaign_evidence(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let record = load(&state, &principal, &id).await?;
    Ok(Json(serde_json::json!({"format":"agf-redteam-evidence-v1","record":record})))
}

pub async fn cancel_campaign(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "execute")?;
    let campaign_id = parse_id(&id, "redteam-campaign")?;
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "redteam-campaign"),
        AuditTarget::new("redteam-campaign", Some(campaign_id.to_string()), None),
        "Red-team campaign cancelled",
    );
    let record = state.store.campaign_cancel_audited(principal.tenant, campaign_id, audit).await?;
    Ok(Json(record.view()?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetestBody {
    pub name: String,
    #[serde(default)]
    pub guard_strength: Option<u8>,
    #[serde(default)]
    pub target_profile_version: Option<u64>,
}

pub async fn retest_campaign(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RetestBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "redteam", "execute")?;
    let old = load(&state, &principal, &id).await?;
    if !old.terminal()
        || old.cases.is_empty()
        || !matches!(old.execution_mode.as_deref(), Some("simulator" | "agent-http" | "mcp-http"))
    {
        return Err(DomainError::Conflict("Retest requires a terminal run with saved supported inputs".into()).into());
    }
    let real = matches!(old.execution_mode.as_deref(), Some("agent-http" | "mcp-http"));
    if (real && (body.guard_strength.is_some() || body.target_profile_version.is_none_or(|version| version == 0)))
        || (!real && body.target_profile_version.is_some())
    {
        return Err(DomainError::Validation(
            "Simulator retest accepts guard_strength only; real target retest requires the current target_profile_version".into(),
        ).into());
    }
    let input = CampaignBody {
        name: body.name,
        scheduled: false,
        partition: None,
        case_keys: if real { old.cases.iter().map(|case| case.key.clone()).collect() } else { vec![] },
        categories: vec![],
        tags: if real { vec![] } else { old.campaign.tags.clone() },
        target_name: if real { None } else { Some(old.target_name.clone()) },
        target_profile_id: if real { old.target_profile_id } else { None },
        target_profile_version: body.target_profile_version,
        guard_strength: if real { None } else { body.guard_strength.or(Some(old.guard_strength)) },
        max_cases: Some(old.cases.len()),
        ci_gate: old.campaign.ci_gate,
        severity_threshold: old.severity_threshold,
        execution_mode: old.execution_mode.clone().unwrap_or_default(),
    };
    let (target_asset, target_name) = if real {
        let mcp = old.execution_mode.as_deref() == Some("mcp-http");
        principal.require(&state, if mcp { "mcps" } else { "agents" }, "read")?;
        if old.cases.iter().any(|case| {
            if mcp {
                !agf_scan::redteam::McpHttpTarget::supports_case(case)
            } else {
                !agf_scan::redteam::AgentHttpTarget::supports_case(case)
            }
        }) {
            return Err(
                DomainError::Conflict("Saved cases are not supported by the current target adapter".into()).into()
            );
        }
        let profile_id =
            old.target_profile_id.ok_or_else(|| DomainError::Conflict("Saved Agent target is missing".into()))?;
        if mcp {
            let profile = super::mcp_targets::load(&state, principal.tenant, profile_id).await?;
            if !profile.enabled
                || Some(profile.version) != body.target_profile_version
                || old.campaign.target_mcp_ids.as_slice() != [profile.asset_id]
            {
                return Err(DomainError::Conflict("MCP target changed, moved, or was disabled".into()).into());
            }
            if old.cases.iter().any(|case| case.key == "RT-MCP-003")
                && (profile.detail_tool_name.is_none() || profile.detail_argument_name.is_none())
            {
                return Err(DomainError::Validation(
                    "RT-MCP-003 requires a second read-only MCP tool and argument".into(),
                )
                .into());
            }
            let asset = state.store.asset_get_durable(principal.tenant, profile.asset_id).await?;
            if !asset.is_some_and(|row| row.kind == agf_core::enums::AssetKind::McpServer && row.is_live()) {
                return Err(DomainError::NotFound { entity: "mcp-asset", id: profile.asset_id.to_string() }.into());
            }
            (Some(profile.asset_id), Some(profile.name))
        } else {
            let profile = super::agent_targets::load(&state, principal.tenant, profile_id).await?;
            if !profile.enabled
                || Some(profile.version) != body.target_profile_version
                || old.campaign.target_agent_ids.as_slice() != [profile.asset_id]
            {
                return Err(DomainError::Conflict("Agent target changed, moved, or was disabled".into()).into());
            }
            let asset = state.store.asset_get_durable(principal.tenant, profile.asset_id).await?;
            if !asset.is_some_and(|row| row.kind == agf_core::enums::AssetKind::Agent && row.is_live()) {
                return Err(DomainError::NotFound { entity: "agent-asset", id: profile.asset_id.to_string() }.into());
            }
            (Some(profile.asset_id), Some(profile.name))
        }
    } else {
        (None, None)
    };
    super::campaign_requests::validate(&input)?;
    let mut record = super::campaign_requests::record(&principal, input, old.cases);
    if let Some(asset_id) = target_asset {
        if old.execution_mode.as_deref() == Some("mcp-http") {
            record.campaign.target_mcp_ids = vec![asset_id];
        } else {
            record.campaign.target_agent_ids = vec![asset_id];
        }
    }
    if let Some(name) = target_name {
        record.target_name = name;
    }
    record.retest_of = Some(old.campaign.id);
    accepted(state, record, principal).await
}

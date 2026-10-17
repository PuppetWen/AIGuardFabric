//! A current observation or different configuration never rewrites the original write's causality.
use super::{
    completion,
    contract::Scope,
    dependencies, operations,
    records::{DetailRecord, Fact, Main, PublicationStatus, Status, WriteStatus},
    util, views,
};
use crate::{Principal, state::AppState};
use agf_core::{error::DomainResult, time::Timestamp};
use serde_json::{Value, json};

pub(super) struct Context<'a> {
    pub principal: &'a Principal,
    pub main: &'a Main,
    pub current: Option<&'a Scope>,
    pub configured: bool,
    pub enabled: bool,
    pub check_sources: bool,
}
pub(super) async fn operation(state: &AppState, context: Context<'_>, fact: &Fact) -> DomainResult<Value> {
    let Context { principal, main, current, configured, enabled, check_sources } = context;
    let original = operations::receipt(fact)?;
    let pending = completion::pending(state, fact).await?;
    let mut receipt = pending.as_ref().map_or_else(|| original.clone(), |pending| pending.receipt.clone());
    let detail = operations::detail_record(state, fact.tenant, fact.request_id).await?;
    let marker = match detail {
        Some(DetailRecord::Archived { marker }) => Some(marker),
        _ => None,
    };
    if marker.as_ref().is_some_and(|marker| {
        marker.original_status != original.status
            || original.finished_at.is_none()
            || marker.archived_at < original.finished_at.unwrap_or_default()
    }) {
        return Err(util::corrupt());
    }
    let expired = original.status == Status::Started && original.lease_expires_at <= Timestamp::now();
    let complete = original.local_publication == PublicationStatus::Published;
    let same_scope = current.is_some_and(|scope| scope.target.target_scope_id == fact.scope.target.target_scope_id);
    let mut original_status = receipt.original_status;
    if marker.is_some() {
        original_status = Some(original.status);
        receipt.status = Status::Archived;
    } else if pending.is_some() {
        receipt.local_publication = PublicationStatus::PendingAudit;
        if receipt.status == Status::Verified {
            receipt.status = Status::Uncertain;
        }
        receipt.finished_at = None;
        receipt.safe_reason = Some("已保存可信云阶段，但本地终态与成功审计尚未原子发布；请只恢复本地记录".into());
    } else if expired {
        receipt.status = Status::Uncertain;
        if receipt.cloud_write == WriteStatus::Attempting {
            receipt.cloud_write = WriteStatus::Unknown;
        }
        receipt.safe_reason = Some("过期started没有可信终态；先显式recover_local固定未知事实，再新观察和新意图".into());
    } else if complete && current.is_some() && !same_scope {
        original_status = Some(original.status);
        receipt.status = Status::Superseded;
    }
    let archivable = complete
        && marker.is_none()
        && original.finished_at.is_some()
        && main.active.as_ref().is_none_or(|active| active.request_id != fact.request_id);
    let can_write = principal.require(state, "alicloud", "write").is_ok();
    let mut allowed = vec!["read_receipt"];
    if enabled && same_scope && main.active.as_ref().is_none_or(|active| active.expires_at <= Timestamp::now()) {
        allowed.push("observe");
    }
    if can_write && !complete && (pending.is_some() || expired) {
        allowed.push("recover_local");
    }
    if can_write && archivable {
        allowed.push("archive");
    }
    let mut current_versions = None;
    let known_inactive = configured && !enabled;
    let known_different = current.is_some() && !same_scope;
    let mut source_current = if known_inactive || known_different { Some(false) } else { None };
    if check_sources {
        current_versions =
            dependencies::current_versions(state, fact.tenant, &original.source_policy_versions).await.ok();
        if same_scope && enabled {
            if let Some(versions) = &current_versions {
                if *versions != original.source_policy_versions {
                    source_current = Some(false);
                } else if let Some(detail) = operations::detail(state, fact.tenant, fact.request_id).await? {
                    let content = super::preview::validate_content(state, fact.tenant, &detail.prepared)?;
                    if let Some(current) = current {
                        source_current = dependencies::prepare(
                            state,
                            current,
                            &detail.prepared.fence.policies,
                            &content.source_policies,
                        )
                        .await
                        .ok()
                        .map(|(_, fence)| fence.dependencies == detail.prepared.fence.dependencies);
                    }
                }
            }
        }
    }
    Ok(json!({
        "requestId":fact.request_id,"previewId":receipt.preview_id,"target":fact.scope.target,
        "action":receipt.action,"sourcePublicationId":receipt.source_publication_id,"startedAt":receipt.started_at,
        "submittedAt":receipt.submitted_at,"finishedAt":receipt.finished_at,"leaseExpiresAt":receipt.lease_expires_at,
        "status":receipt.status,"originalStatus":original_status,"archived":marker.is_some(),"archivedAt":marker.as_ref().map(|marker|marker.archived_at),
        "archivable":archivable,"cloudWrite":{"status":receipt.cloud_write,"providerRequestId":receipt.provider_request_id},
        "readback":{"status":receipt.readback,"observedAt":receipt.readback_observed_at,"currentHash":receipt.readback_hash},
        "localPublication":{"status":receipt.local_publication},"completionState":if complete{"complete"}else if pending.is_some(){"pending_audit"}else{"running"},
        "safeReason":receipt.safe_reason,"consumerApplied":Value::Null,"supersededBy":receipt.superseded_by,
        "sourceCurrent":source_current,"sourcePolicyVersions":views::revisions(&original.source_policy_versions),
        "currentPolicyVersions":current_versions.as_ref().map(|rows|views::revisions(rows)),
        "recoveryScopeId":current.filter(|_|enabled && same_scope).map(|scope|scope.target.target_scope_id),
        "recoveryConfigurationVersion":current.filter(|_|enabled && same_scope).map(|scope|scope.target.configuration_version),"allowedActions":allowed
    }))
}

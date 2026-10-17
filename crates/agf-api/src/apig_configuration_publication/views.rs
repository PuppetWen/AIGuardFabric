//! All GETs are local pure views. Complete encrypted provider content is never a DTO.
use super::{
    authority::Submission,
    context,
    contract::Scope,
    observation, operations, preview, projection,
    records::{Fact, Main, Observation, Prepared, PublicationStatus, Status},
    risk, store, util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) async fn list(state: &AppState, submission: &Submission) -> DomainResult<Value> {
    let principal = submission.authorize(state).await?;
    let configured = context::configured(state, principal.tenant).await?;
    let scope = configured.as_ref().and_then(|row| super::scope::from_row(state, principal.tenant, row).ok());
    let enabled = configured.as_ref().is_some_and(|row| row.enabled);
    let main = store::load(state, principal.tenant).await?;
    let busy = main.active.as_ref().is_some_and(|active| active.expires_at > Timestamp::now());
    let write = principal.require(state, "alicloud", "write").is_ok();
    let observed = match main.latest_observation {
        Some(id) => observation::load(state, principal.tenant, id).await?,
        None => None,
    };
    let observation =
        observed.as_ref().map(|row| observation_dto(state, row, &main, scope.as_ref(), enabled)).transpose()?;
    let mut facts = Vec::new();
    for id in &main.operations {
        if let Some(fact) = operations::load(state, principal.tenant, *id).await? {
            facts.push(fact);
        }
    }
    facts.sort_by_key(|fact| std::cmp::Reverse((fact.created_at, fact.request_id)));
    let mut rows = Vec::new();
    let mut history = Vec::new();
    for fact in facts {
        if rows.len() < 50 {
            rows.push(
                projection::operation(
                    state,
                    projection::Context {
                        principal: &principal,
                        main: &main,
                        current: scope.as_ref(),
                        configured: configured.is_some(),
                        enabled,
                    },
                    &fact,
                )
                .await?,
            );
        }
        let receipt = operations::receipt(&fact)?;
        if history.len() < 50
            && receipt.status == Status::Verified
            && receipt.local_publication == PublicationStatus::Published
        {
            if let Some(detail) = operations::detail(state, principal.tenant, fact.request_id).await? {
                let content = preview::validate_content(state, principal.tenant, &detail.prepared)?;
                let available = write
                    && enabled
                    && scope
                        .as_ref()
                        .is_some_and(|scope| scope.target.target_scope_id == fact.scope.target.target_scope_id)
                    && observed.as_ref().is_some_and(|observed| {
                        scope.as_ref().is_some_and(|scope| {
                            observed.scope == *scope
                                && observed.observed_at.age_secs() <= 300
                                && observation::restore(state, observed).is_ok_and(|baseline| {
                                    super::content::rollback(scope, &baseline, &content)
                                        .and_then(|change| super::content::prepare(&baseline, &change))
                                        .is_ok()
                                })
                        })
                    });
                history.push(
                    json!({"publicationId":fact.request_id,"target":fact.scope.target,"verifiedAt":receipt.finished_at,
                    "contentHash":receipt.desired_hash,"diff":content.update.safe_diff(),"rollbackAvailable":available,
                    "reason":if available{None}else{Some("需同目标的新可信观察、可支持的当前服务槽与写权限；历史事实仍可读")} }),
                );
            }
        }
    }
    let marker = match &scope {
        Some(scope) => risk::load(state, principal.tenant, scope.target.write_resource_id).await?,
        None => None,
    };
    let usable = observation.as_ref().is_some_and(|row| row["usable"] == true);
    Ok(json!({"configured":configured.is_some(),"enabled":configured.as_ref().map(|row|row.enabled),
        "binding":scope.as_ref().map(|scope|&scope.target),"bindingReason":if scope.is_none(){Some("请填写既有资源的确切ID并显式确认受管配置；没有自动示例")}
            else if !enabled{Some("来源已停用；旧回执/本地恢复/归档仍可用")}else{None},
        "stateVersion":main.version,"generation":main.generation,"busy":busy,"leaseExpiresAt":main.active.as_ref().map(|active|active.expires_at),
        "canObserve":scope.is_some()&&enabled&&!busy,"canInitializeMockFixture":write&&scope.as_ref().is_some_and(|scope|scope.target.mocked)&&enabled&&!busy,
        "canPrepare":write&&usable&&main.active.is_none(),"canApply":write&&scope.is_some()&&enabled&&main.active.is_none(),
        "unresolvedOperationId":marker.as_ref().map(|risk|risk.latest_unknown),"observation":observation,"operations":rows,"history":history,
        "detailedRunCount":main.operations.len(),"archivedCount":main.archived_count,"storedContentBytes":main.stored_content_bytes,
        "limits":limits(),"configurationObserved":observation.is_some(),"deploymentVerified":Value::Null,"consumerApplied":Value::Null,"noCloudCas":true }))
}
pub(super) fn observation_dto(
    state: &AppState,
    row: &Observation,
    main: &Main,
    current: Option<&Scope>,
    enabled: bool,
) -> DomainResult<Value> {
    let usable = enabled
        && main.latest_observation == Some(row.request_id)
        && current == Some(&row.scope)
        && row.started_at <= row.observed_at
        && row.observed_at <= Timestamp::now()
        && row.observed_at.age_secs() <= 300;
    let baseline = observation::restore(state, row)?;
    Ok(
        json!({"id":row.request_id,"requestId":row.request_id,"target":row.scope.target,"startedAt":row.started_at,"observedAt":row.observed_at,
        "fingerprint":row.fingerprint,"view":baseline.safe_view(),"contentHash":row.content_hash,"contentBytes":row.content_bytes,
        "usable":usable,"reason":if usable{None}else{Some("此基线已过期/不是当前启用来源；请明确新观察")},
        "deploymentVerified":Value::Null,"consumerApplied":Value::Null }),
    )
}
pub(super) async fn observed(state: &AppState, submission: &Submission, row: &Observation) -> DomainResult<Value> {
    let main = store::load(state, submission.principal.tenant).await?;
    let current = context::current(state, submission.principal.tenant, None).await.ok();
    observation_dto(state, row, &main, current.as_ref(), current.is_some())
}
pub(super) async fn prepared(state: &AppState, submission: &Submission, row: &Prepared) -> DomainResult<Value> {
    let tenant = submission.principal.tenant;
    let main = store::load(state, tenant).await?;
    let current = context::current(state, tenant, None).await.ok();
    let fact =
        state.configurations.get::<Fact>(tenant, super::records::FACT, util::fact_id(tenant, row.request_id)).await?;
    let consumed = match fact.as_ref().map(|fact| &fact.outcome) {
        Some(super::records::FactOutcome::Prepared { consumed_by }) => *consumed_by,
        _ => None,
    };
    let content = preview::validate_content(state, tenant, row)?;
    let usable = submission.principal.require(state, "alicloud", "write").is_ok()
        && current.as_ref() == Some(&row.scope)
        && row.expires_at > Timestamp::now()
        && row.state_version == main.version
        && consumed.is_none()
        && main.previews.contains(&row.request_id)
        && main.active.is_none();
    Ok(
        json!({"id":row.request_id,"requestId":row.request_id,"target":row.scope.target,"stateVersion":row.state_version,
        "action":row.action,"sourcePublicationId":row.source_publication_id,"observationId":row.observation_id,
        "baselineObservedAt":row.baseline_observed_at,"baselineFingerprint":row.baseline_fingerprint,
        "desiredHash":row.desired_hash,"desiredBytes":row.desired_bytes,"diff":content.update.safe_diff(),
        "expiresAt":row.expires_at,"previewUsable":usable,"consumedBy":consumed,
        "reason":if usable{None}else{Some("预览过期/消费或来源已改版；保留草稿并明确新观察/新预览")},
        "acknowledgeUnknownOperationId":row.acknowledge_unknown_operation_id,"unknownOverlapWarning":row.acknowledge_unknown_operation_id.is_some(),
        "allowedActions":if usable{vec!["apply","read_receipt"]}else{vec!["read_receipt"]},
        "noCloudCas":true,"deploymentVerified":Value::Null,"consumerApplied":Value::Null }),
    )
}
pub(super) async fn operation(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    let principal = submission.authorize(state).await?;
    let fact = operations::load(state, principal.tenant, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "apig-configuration-operation", id: id.to_string() })?;
    let main = store::load(state, principal.tenant).await?;
    let configured = context::configured(state, principal.tenant).await?;
    let current = configured.as_ref().and_then(|row| super::scope::from_row(state, principal.tenant, row).ok());
    let enabled = configured.as_ref().is_some_and(|row| row.enabled);
    projection::operation(
        state,
        projection::Context {
            principal: &principal,
            main: &main,
            current: current.as_ref(),
            configured: configured.is_some(),
            enabled,
        },
        &fact,
    )
    .await
}
fn limits() -> Value {
    json!({"maxDetailedRuns":128,"maxPreviews":32,"maxObservations":8,"maxArchive":100,
    "maxContentBytes":655_360,"maxRecordBytes":1_048_576,"maxStoredContentBytes":67_108_864,"maxServices":32,
    "maxDriverSeconds":30,"maxOperationSeconds":110,"leaseSeconds":120,"previewSeconds":120,"observationSeconds":300})
}

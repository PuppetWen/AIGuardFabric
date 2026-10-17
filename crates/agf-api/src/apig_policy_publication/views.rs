//! Safe views read local records only. Unknown binding or observation never falls back to a fixture.
use super::{
    authority::Submission,
    context,
    contract::Scope,
    dependencies,
    input::PolicyRevision,
    observation, operations, preview, projection,
    records::{Fact, FactOutcome, Main, Observation, Prepared, PublicationStatus, Status},
    risk, store, util,
};
use crate::state::AppState;
use agf_core::{error::DomainResult, ids::Id, time::Timestamp};
use serde_json::{Value, json};

pub(super) async fn list(
    state: &AppState,
    submission: &Submission,
    query: &super::eligibility::Query,
) -> DomainResult<Value> {
    let principal = submission.authorize(state).await?;
    let tenant = principal.tenant;
    let configured = context::configured(state, tenant).await?;
    let scope = configured.as_ref().and_then(|row| super::scope::from_row(state, tenant, row).ok());
    let enabled = configured.as_ref().is_some_and(|row| row.enabled);
    let main = store::load(state, tenant).await?;
    let busy = main.active.as_ref().is_some_and(|active| active.expires_at > Timestamp::now());
    let can_write = principal.require(state, "alicloud", "write").is_ok();
    let observed = match main.latest_observation {
        Some(id) => observation::load(state, tenant, id).await?,
        None => None,
    };
    let observation =
        observed.as_ref().map(|row| observation_dto(state, row, &main, scope.as_ref(), enabled)).transpose()?;
    let mut facts = Vec::new();
    for id in &main.operations {
        if let Some(fact) = operations::load(state, tenant, *id).await? {
            facts.push(fact);
        }
    }
    facts.sort_by_key(|fact| std::cmp::Reverse((fact.created_at, fact.request_id)));
    let mut operation_rows = Vec::new();
    let mut history = Vec::new();
    for fact in facts {
        if operation_rows.len() < 50 {
            operation_rows.push(
                projection::operation(
                    state,
                    projection::Context {
                        principal: &principal,
                        main: &main,
                        current: scope.as_ref(),
                        configured: configured.is_some(),
                        enabled,
                        check_sources: false,
                    },
                    &fact,
                )
                .await?,
            );
        }
        if history.len() < 50
            && enabled
            && scope.as_ref().is_some_and(|current| current.target.target_scope_id == fact.scope.target.target_scope_id)
        {
            let receipt = operations::receipt(&fact)?;
            if receipt.status == Status::Verified && receipt.local_publication == PublicationStatus::Published {
                if let Some(detail) = operations::detail(state, tenant, fact.request_id).await? {
                    let reason = if !can_write {
                        Some("缺少云配置写入权限".to_owned())
                    } else if let Some(current) = scope.as_ref() {
                        preview::rollback_source(
                            state,
                            current,
                            &receipt.source_policy_versions,
                            detail.prepared.managed_limit,
                        )
                        .await
                        .err()
                        .map(|_| "当前来源策略或配额不再支持原限流维度；请先保存有效来源".to_owned())
                    } else {
                        Some("当前来源绑定不可用".to_owned())
                    };
                    history.push(json!({"publicationId":fact.request_id,"target":fact.scope.target,
                        "verifiedAt":receipt.finished_at,"contentHash":receipt.desired_hash,"contentBytes":receipt.desired_bytes,
                        "sourcePolicyVersions":revisions(&receipt.source_policy_versions),"rollbackAvailable":reason.is_none(),"reason":reason}));
                }
            }
        }
    }
    let marker = match scope.as_ref() {
        Some(scope) => risk::load(state, tenant, scope.target.write_resource_id).await?,
        None => None,
    };
    let observed_usable = observation.as_ref().is_some_and(|row| row["usable"] == true);
    let binding_usable = scope.is_some() && enabled;
    let sources = super::eligibility::list(state, tenant, query).await?;
    Ok(json!({
        "sources":sources,"canInitializeMockFixture":can_write && binding_usable && !busy && scope.as_ref().is_some_and(|scope|scope.target.mocked),
        "configured":configured.is_some(),"enabled":configured.as_ref().map(|row|row.enabled),
        "binding":scope.as_ref().map(|scope|&scope.target),"stateVersion":main.version,"generation":main.generation,
        "canObserve":binding_usable && !busy,"canPrepare":can_write && binding_usable && main.active.is_none() && observed_usable,
        "canApply":can_write && binding_usable && main.active.is_none(),
        "bindingReason":if scope.is_none(){Some("请保存明确的既有APIG五ID独立限流绑定，未使用默认示例替代")}
            else if !enabled{Some("当前绑定已停用；仅可读取或恢复/归档原本地事实")}else{None},
        "busy":busy,"leaseExpiresAt":main.active.as_ref().map(|active|active.expires_at),
        "unresolvedOperationId":marker.as_ref().map(|risk|risk.latest_unknown),"observation":observation,
        "operations":operation_rows,"history":history,"detailedRunCount":main.operations.len(),
        "archivedCount":main.archived_count,"storedContentBytes":main.stored_content_bytes,
        "limits":limits(),"consumerApplied":Value::Null,"sharedPolicyImpact":Value::Null,"noCloudCas":true
    }))
}

pub(super) fn observation_dto(
    state: &AppState,
    row: &Observation,
    main: &Main,
    scope: Option<&Scope>,
    enabled: bool,
) -> DomainResult<Value> {
    let usable = enabled
        && main.latest_observation == Some(row.request_id)
        && scope == Some(&row.scope)
        && row.started_at <= row.observed_at
        && row.observed_at <= Timestamp::now()
        && row.observed_at.age_secs() <= 300;
    let baseline = observation::restore(state, row)?;
    let slots = [
        agf_alicloud::apig::policy_driver::ManagedLimit::RequestPerMinute,
        agf_alicloud::apig::policy_driver::ManagedLimit::TokenPerMinute,
    ]
    .into_iter()
    .map(|mode| {
        let (value, reason) = match agf_alicloud::apig::policy_driver::current_limit(&baseline, mode) {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error.to_string())),
        };
        json!({"managedLimit":mode,"currentLimit":value,"supported":value.is_some(),"reason":reason})
    })
    .collect::<Vec<_>>();
    Ok(json!({"id":row.request_id,"requestId":row.request_id,"target":row.scope.target,
        "startedAt":row.started_at,"observedAt":row.observed_at,"fingerprint":row.fingerprint,"configHash":row.config_hash,"slots":slots,
        "contentHash":row.content_hash,"contentBytes":row.content_bytes,
        "usable":usable,"reason":if usable{None}else{Some("此观察不是当前启用来源的新鲜成功基线；请明确重新观察")}}))
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
        Some(FactOutcome::Prepared { consumed_by }) => *consumed_by,
        _ => None,
    };
    let current_versions = dependencies::current_versions(state, tenant, &row.source_policy_versions).await.ok();
    let source = preview::validate_content(state, tenant, row)?;
    let fresh_dependencies = if let Some(scope) = current.as_ref().filter(|scope| **scope == row.scope) {
        dependencies::prepare(state, scope, &row.fence.policies, &source.source_policies)
            .await
            .ok()
            .is_some_and(|(_, fence)| fence.dependencies == row.fence.dependencies)
    } else {
        false
    };
    let write = submission.principal.require(state, "alicloud", "write").is_ok();
    let usable = write
        && current.as_ref() == Some(&row.scope)
        && row.expires_at > Timestamp::now()
        && row.state_version == main.version
        && consumed.is_none()
        && main.previews.contains(&row.request_id)
        && main.active.is_none()
        && fresh_dependencies;
    Ok(json!({
        "id":row.request_id,"requestId":row.request_id,"target":row.scope.target,"stateVersion":row.state_version,
        "action":row.action,"sourcePublicationId":row.source_publication_id,"observationId":row.observation_id,
        "baselineObservedAt":row.baseline_observed_at,"baselineFingerprint":row.baseline_fingerprint,"baselineConfigHash":row.baseline_config_hash,
        "managedLimit":row.managed_limit,"previousLimit":row.previous_limit,"desiredLimit":row.desired_limit,"desiredHash":row.desired_hash,"desiredBytes":row.desired_bytes,
        "sourcePolicyVersions":revisions(&row.source_policy_versions),"currentPolicyVersions":current_versions.as_ref().map(|rows|revisions(rows)).unwrap_or_else(||json!([])),
        "expiresAt":row.expires_at,"previewUsable":usable,"reason":if usable{None}else{Some("预览已过期、消费或当前来源/策略/依赖改变；请保留选择并明确新观察和新预览")},
        "consumedBy":consumed,"casSemantics":"none","noCloudCas":true,"sharedPolicyImpact":Value::Null,"consumerApplied":Value::Null,
        "acknowledgeUnknownOperationId":row.acknowledge_unknown_operation_id,"unknownOverlapWarning":row.acknowledge_unknown_operation_id.is_some(),
        "allowedActions":if usable{vec!["apply","read_receipt"]}else{vec!["read_receipt"]}
    }))
}

pub(super) async fn operation(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    let principal = submission.authorize(state).await?;
    let fact = operations::load(state, principal.tenant, id).await?.ok_or_else(|| {
        agf_core::error::DomainError::NotFound { entity: "apig-publication-operation", id: id.to_string() }
    })?;
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
            check_sources: true,
        },
        &fact,
    )
    .await
}

pub(super) fn revisions(rows: &[PolicyRevision]) -> Value {
    json!(rows.iter().map(|row| json!({"policyId":row.policy_id,"version":row.version})).collect::<Vec<_>>())
}
fn limits() -> Value {
    json!({"maxPolicies":1,"maxContentBytes":655_360,"maxProviderConfigBytes":65_536,"maxRecordBytes":1_048_576,"maxMainBytes":4_194_304,
        "maxAggregateAgentIds":500,"maxStoredContentBytes":67_108_864,"maxDetailedRuns":128,"maxPreviews":32,"maxObservations":8,
        "maxArchive":100,"maxDriverSeconds":30,"maxOperationSeconds":110,"leaseSeconds":120,"previewSeconds":120,"observationSeconds":300})
}

//! Bounded, guarded public reads never publish a partial service listing.
use super::{
    EXECUTION_SECS, NAME, archive,
    contract::{Run, Snapshot, SyncInput},
    guard::{self, Guard},
    parse, publication, scope, store,
};
use crate::{
    Principal,
    cloud_runtime::{self, Request, WritePrecondition},
    state::AppState,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::deterministic_id,
    time::Timestamp,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

pub(super) async fn sync(state: &AppState, principal: &Principal, input: SyncInput) -> DomainResult<Run> {
    let submitted_at = Timestamp::now();
    if input.request_id.is_nil() {
        return Err(DomainError::Validation("request_id 不能是空 UUID".into()));
    }
    guard::authorize(state, principal, submitted_at).await?;
    if let Some(run) = archive::replay(state, principal, &input).await? {
        return Ok(run);
    }
    let (_, scope) = scope::load(state, principal.tenant).await?;
    if input.configuration_version != scope.configuration_version {
        return Err(scope::stale());
    }
    if !scope.mocked && !input.confirm_live {
        return Err(DomainError::PreconditionFailed("真实 MSE 盘点需显式确认只读云调用".into()));
    }
    let (run, created) = store::claim(state, principal, &scope, &input, submitted_at).await?;
    if !created {
        return Ok(run);
    }
    let result =
        tokio::time::timeout(Duration::from_secs(EXECUTION_SECS), execute(state, principal, &run, input.confirm_live))
            .await;
    let error = match result {
        Ok(Ok(())) => return store::get(state, principal.tenant, run.request_id).await,
        Ok(Err(error)) => error,
        Err(_) => DomainError::Timeout("MSE 完整盘点超过110秒；原台账保持不变".into()),
    };
    let (status, note) = match &error {
        DomainError::Conflict(_) => ("superseded", "配置、范围、租约或取消状态已改变；旧结果未发布"),
        DomainError::Timeout(_) => ("interrupted", "只读盘点超时；旧请求不会再次派发，原台账保持不变"),
        _ => ("failed", "完整盘点或原子发布失败；原台账保持不变，请检查权限、分页或服务状态"),
    };
    store::failed(state, principal, &run, status, note).await?;
    Err(error)
}

async fn execute(state: &AppState, principal: &Principal, run: &Run, live: bool) -> DomainResult<()> {
    let guard = Guard { state, principal, run };
    let mut services = Vec::new();
    let mut keys = BTreeSet::new();
    let mut total = None;
    for number in 1..=20_u64 {
        guard.validate().await?;
        let value = read_page(state, principal, run, &guard, number, live).await?;
        guard.validate().await?;
        let page = parse::page(&value, &run.scope, number)?;
        if total.is_some_and(|expected| expected != page.total) {
            return Err(incomplete());
        }
        total = Some(page.total);
        let remaining = page.total.checked_sub(services.len() as u64).ok_or_else(incomplete)?;
        if page.services.len() as u64 != remaining.min(100) {
            return Err(incomplete());
        }
        for service in page.services {
            if !keys.insert(service.key.clone()) {
                return Err(incomplete());
            }
            services.push(service);
        }
        store::progress(state, principal.tenant, run, number, services.len() as u64).await?;
        if services.len() as u64 == page.total {
            let snapshot = Snapshot {
                scope: run.scope.clone(),
                started_at: run.started_at,
                checked_at: Timestamp::now(),
                pages_read: number,
                services,
            };
            guard.validate().await?;
            return publication::publish(state, principal, run, snapshot).await;
        }
    }
    Err(incomplete())
}

async fn read_page(
    state: &AppState,
    principal: &Principal,
    run: &Run,
    guard: &Guard<'_>,
    number: u64,
    live: bool,
) -> DomainResult<Value> {
    let parameters = json!({"InstanceId":run.scope.instance_id,"NamespaceId":run.scope.namespace_id,
        "RegionId":run.scope.region,"PageNum":number,"PageSize":100,"HasIpCount":"true"});
    let request_id =
        deterministic_id("agf.mse.inventory.page", &serde_json::to_string(&(run.request_id, number, &parameters))?);
    let response = Box::pin(cloud_runtime::execute_guarded_authorized(
        state,
        principal,
        NAME,
        Request {
            request_id,
            configuration_version: run.scope.configuration_version,
            action: "ListAnsServices".into(),
            parameters,
            confirm_live: live,
        },
        guard,
    ))
    .await?;
    if response["status"] != "succeeded" || response["completion_state"] == "pending_audit" {
        return Err(DomainError::DependencyUnavailable {
            dependency: "MSE".into(),
            cause: "只读云回执尚未成功发布；原台账保持不变".into(),
        });
    }
    Ok(response["receipt"]["response"].clone())
}

fn incomplete() -> DomainError {
    DomainError::Parse("MSE 分页总数变化、重叠、缺页或超过2000项；未发布部分清单".into())
}

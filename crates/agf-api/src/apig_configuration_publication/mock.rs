//! Explicit owned fixture only. GET never seeds and SQL Mock state survives restart.
use super::{
    audit, content,
    contract::{Binding, Scope},
    provider::Guard,
    records::Values,
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_alicloud::{
    apig::config_driver::{self as driver, CurrentGuard, Observation, Prepared, WriteOutcome},
    http::RpcResponse,
};
use agf_core::{
    audit::AuditAction,
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
const KIND: &str = "apig-configuration-driver-mock";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    tenant: TenantId,
    id: Id,
    resource: Id,
    hash: String,
    secret: SecretMaterial,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    tenant: TenantId,
    resource: Id,
    binding: Binding,
    evidence: Value,
    writes: u64,
}
fn id(scope: &Scope) -> Id {
    util::content_id(scope.tenant, scope.target.write_resource_id, "mock")
}
fn record(state: &AppState, scope: &Scope, data: &Data) -> DomainResult<Record> {
    util::bound(data, 512 * 1024)?;
    let text = serde_json::to_string(data)?;
    Ok(Record {
        tenant: scope.tenant,
        id: id(scope),
        resource: scope.target.write_resource_id,
        hash: util::hash(text.as_bytes()),
        secret: util::encrypt_content(state, scope.tenant, id(scope), &text)?,
    })
}
fn checked(state: &AppState, scope: &Scope, row: &Record) -> DomainResult<Data> {
    if (row.tenant, row.id, row.resource) != (scope.tenant, id(scope), scope.target.write_resource_id) {
        return Err(util::corrupt());
    }
    let text = util::decrypt_content(state, scope.tenant, id(scope), &row.secret, &row.hash)?;
    let data: Data = serde_json::from_str(&text)?;
    util::bound(&data, 512 * 1024)?;
    if (data.tenant, data.resource, &data.binding)
        != (scope.tenant, scope.target.write_resource_id, &scope.target.binding)
    {
        return Err(util::corrupt());
    }
    content::restore_evidence(scope, &data.evidence)?;
    Ok(data)
}
fn fixture(scope: &Scope) -> DomainResult<Data> {
    let fixture: Value = serde_json::from_str(include_str!("mock_fixture.json"))?;
    let (expected, action) = match &scope.target.binding {
        Binding::Content(_) => (&fixture["contentBinding"], "GetPluginAttachment"),
        Binding::Models(_) => (&fixture["modelBinding"], "GetHttpApi"),
    };
    let actual = match &scope.target.binding {
        Binding::Content(value) => serde_json::to_value(value)?,
        Binding::Models(value) => serde_json::to_value(value)?,
    };
    if !scope.target.mocked || scope.target.region != "cn-hangzhou" || actual != *expected {
        return Err(DomainError::PreconditionFailed("Mock只支持指南中明确列出的所属示例目标；不代表云资源".into()));
    }
    let response = fixture["responses"][action].clone();
    let response = RpcResponse { status: 200, raw: response.to_string(), body: response };
    let observed = match &scope.target.binding {
        Binding::Content(value) => driver::parse_content(value, &response)?,
        Binding::Models(value) => driver::parse_models(value, &response)?,
    };
    Ok(Data {
        tenant: scope.tenant,
        resource: scope.target.write_resource_id,
        binding: scope.target.binding.clone(),
        evidence: observed.exported_evidence(),
        writes: 0,
    })
}
pub(super) async fn observe(guard: &Guard, initialize: bool) -> DomainResult<Observation> {
    tokio::time::timeout_at(guard.submission.deadline, async {
        guard.validate().await?;
        if initialize {
            let data = fixture(&guard.scope)?;
            let related = [key(KIND, id(&guard.scope))];
            store::mutate(
                &guard.state,
                Mutation { submission: &guard.submission, scope: Some(&guard.scope), related: &related },
                |main, snapshot| {
                    guard.submission.check_budget()?;
                    if let Some(row) = util::read::<Record>(&snapshot.related, KIND, id(&guard.scope))? {
                        checked(&guard.state, &guard.scope, &row)?;
                        return Ok(Decision::Unchanged);
                    }
                    let mut writes = Values::new();
                    util::put(&mut writes, KIND, id(&guard.scope), &record(&guard.state, &guard.scope, &data)?)?;
                    util::bump(main)?;
                    Ok(Decision::Write {
                        related: writes,
                        audit: Box::new(audit::entry(
                            &guard.submission,
                            Id::new(),
                            "apig-configuration-mock-initialize",
                            AuditAction::Configure,
                            json!({"mocked":true,"resource":guard.scope.target.write_resource_id}),
                        )),
                    })
                },
            )
            .await?;
        }
        let row = guard
            .state
            .configurations
            .get::<Record>(guard.scope.tenant, KIND, id(&guard.scope))
            .await?
            .ok_or_else(|| DomainError::PreconditionFailed("请明确初始化隔离Mock示例；读取不自动创建".into()))?;
        let data = checked(&guard.state, &guard.scope, &row)?;
        guard.validate().await?;
        content::restore_evidence(&guard.scope, &data.evidence)
    })
    .await
    .map_err(|_| DomainError::Timeout("原Mock观察预算已结束".into()))?
}
pub(super) async fn publish(guard: &Guard, update: &Prepared) -> DomainResult<WriteOutcome> {
    guard.validate().await?;
    let operation = guard.operation.ok_or_else(util::corrupt)?;
    let related = [key(KIND, id(&guard.scope))];
    let mut request_id = None;
    let result = tokio::time::timeout_at(
        guard.submission.deadline,
        store::mutate(
            &guard.state,
            Mutation { submission: &guard.submission, scope: Some(&guard.scope), related: &related },
            |main, snapshot| {
                guard.submission.check_budget()?;
                let row = util::read::<Record>(&snapshot.related, KIND, id(&guard.scope))?.ok_or_else(util::stale)?;
                let mut data = checked(&guard.state, &guard.scope, &row)?;
                let current = content::restore_evidence(&guard.scope, &data.evidence)?;
                let before = content::restore_evidence(&guard.scope, &update.baseline_evidence())?;
                if current.fingerprint() != before.fingerprint() {
                    return Err(util::stale());
                }
                data.evidence = update.desired_evidence();
                content::restore_evidence(&guard.scope, &data.evidence)?;
                data.writes = data.writes.checked_add(1).ok_or_else(util::capacity)?;
                let mut writes = Values::new();
                util::put(&mut writes, KIND, id(&guard.scope), &record(&guard.state, &guard.scope, &data)?)?;
                util::bump(main)?;
                request_id = Some(format!("mock-configuration-update-{}", data.writes));
                Ok(Decision::Write {
                    related: writes,
                    audit: Box::new(audit::entry(
                        &guard.submission,
                        operation,
                        "apig-configuration-mock-write",
                        AuditAction::Configure,
                        json!({"mocked":true,"resource":guard.scope.target.write_resource_id,"writes":data.writes}),
                    )),
                })
            },
        ),
    )
    .await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Ok(WriteOutcome::Unknown),
    }
    if guard.validate().await.is_err() {
        return Ok(WriteOutcome::Unknown);
    }
    Ok(WriteOutcome::Accepted { request_id: request_id.ok_or_else(util::corrupt)? })
}

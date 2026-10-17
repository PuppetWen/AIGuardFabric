//! A detail observation and two complete child lists precede any topology publication.
use super::{
    EXECUTION_SECS, NAME, archive,
    contract::{Progress, Run, SecurityGroup, Snapshot, SyncInput, Zone},
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
        return Err(DomainError::Validation("request_id不能是空UUID".into()));
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
        return Err(DomainError::PreconditionFailed("真实PrivateLink盘点需明确确认只读调用".into()));
    }
    let (run, created) = store::claim(state, principal, &scope, &input, submitted_at).await?;
    if !created {
        return Ok(run);
    }
    let collector = Collector {
        guard: Guard { state, principal, run: &run },
        live: input.confirm_live,
        progress: Progress::default(),
        zones: Vec::new(),
        groups: Vec::new(),
    };
    let result = tokio::time::timeout(Duration::from_secs(EXECUTION_SECS), collector.execute()).await;
    let error = match result {
        Ok(Ok(())) => return store::get(state, principal.tenant, run.request_id).await,
        Ok(Err(error)) => error,
        Err(_) => DomainError::Timeout("PrivateLink完整盘点超过110秒；原观察保持不变".into()),
    };
    let (status, note) = match &error {
        DomainError::Conflict(_) => ("superseded", "范围、租约或取消状态改变，未发布旧结果"),
        DomainError::Timeout(_) => ("interrupted", "只读盘点超时；旧编号不重派，原观察保持不变"),
        _ => ("failed", "PrivateLink完整盘点或原子发布失败；请核对权限、配置和分页"),
    };
    store::failed(state, principal, &run, status, note).await?;
    Err(error)
}

struct Collector<'a> {
    guard: Guard<'a>,
    live: bool,
    progress: Progress,
    zones: Vec<Zone>,
    groups: Vec<SecurityGroup>,
}

impl Collector<'_> {
    async fn execute(mut self) -> DomainResult<()> {
        let detail = self.read("GetVpcEndpointAttribute", 0, None).await?;
        let endpoint = parse::endpoint(&detail, &self.guard.run.scope, Timestamp::now())?;
        self.progress.endpoints_observed = 1;
        self.save_progress().await?;
        self.list("ListVpcEndpointZones", "Zones").await?;
        self.list("ListVpcEndpointSecurityGroups", "SecurityGroups").await?;
        self.guard.validate().await?;
        let run = self.guard.run;
        publication::publish(
            self.guard.state,
            self.guard.principal,
            run,
            Snapshot {
                scope: run.scope.clone(),
                started_at: run.started_at,
                checked_at: Timestamp::now(),
                pages_read: self.progress.pages_read,
                asset_id: None,
                endpoint,
                zones: self.zones,
                security_groups: self.groups,
            },
        )
        .await
    }

    async fn list(&mut self, action: &str, key: &str) -> DomainResult<()> {
        let mut token = None;
        let mut tokens = BTreeSet::new();
        let mut total = None;
        let mut ids = BTreeSet::new();
        for number in 1..=20 {
            let value = self.read(action, number, token.as_deref()).await?;
            let page = parse::page(&value, key)?;
            if total.is_some_and(|expected| expected != page.total) {
                return Err(incomplete());
            }
            total = Some(page.total);
            for item in page.items {
                let id = self.push(key, &item)?;
                if !ids.insert(id) {
                    return Err(incomplete());
                }
            }
            if ids.len() as u64 > page.total {
                return Err(incomplete());
            }
            self.progress.pages_read += 1;
            self.progress.zones_observed = self.zones.len() as u64;
            self.progress.security_groups_observed = self.groups.len() as u64;
            self.save_progress().await?;
            token = page.next_token;
            if let Some(next) = &token {
                if !tokens.insert(next.clone()) {
                    return Err(incomplete());
                }
            } else {
                return if ids.len() as u64 == page.total { Ok(()) } else { Err(incomplete()) };
            }
        }
        Err(incomplete())
    }

    fn push(&mut self, key: &str, item: &Value) -> DomainResult<String> {
        let at = Timestamp::now();
        if key == "Zones" {
            let zone = parse::zone(item, &self.guard.run.scope, at)?;
            let id = zone.id.clone();
            self.zones.push(zone);
            Ok(id)
        } else {
            let group = parse::security_group(item, at)?;
            let id = group.id.clone();
            self.groups.push(group);
            Ok(id)
        }
    }

    async fn save_progress(&self) -> DomainResult<()> {
        store::progress(self.guard.state, self.guard.principal.tenant, self.guard.run, &self.progress).await
    }

    async fn read(&self, action: &str, number: u64, token: Option<&str>) -> DomainResult<Value> {
        self.guard.validate().await?;
        let run = self.guard.run;
        let principal = self.guard.principal;
        let mut parameters = json!({"RegionId":run.scope.region,"EndpointId":run.scope.endpoint_id});
        if number > 0 {
            parameters["MaxResults"] = json!(50);
            if let Some(token) = token {
                parameters["NextToken"] = json!(token);
            }
        }
        let request_id = deterministic_id(
            "agf.privatelink.inventory.read",
            &format!("{}:{action}:{number}:{}", run.request_id, scope::hash(&parameters)?),
        );
        let receipt = Box::pin(cloud_runtime::execute_guarded_authorized(
            self.guard.state,
            principal,
            NAME,
            Request {
                request_id,
                configuration_version: run.scope.configuration_version,
                confirm_live: self.live,
                action: action.into(),
                parameters,
            },
            &self.guard,
        ))
        .await?;
        self.guard.validate().await?;
        if receipt["status"] != "succeeded" || receipt["completion_state"] != "complete" {
            return Err(DomainError::DependencyUnavailable {
                dependency: "PrivateLink".into(),
                cause: "只读调用未得到已提交成功回执；原台账保持不变".into(),
            });
        }
        receipt.pointer("/receipt/response").cloned().ok_or_else(incomplete)
    }
}

fn incomplete() -> DomainError {
    DomainError::Parse("PrivateLink子列表不完整、重复或总数矛盾；整批保留原观察".into())
}

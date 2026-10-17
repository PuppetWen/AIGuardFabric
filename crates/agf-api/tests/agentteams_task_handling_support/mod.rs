//! Real normal handlers create the source, scope, binding and original collector records.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_ingest::pipeline::AgentTeamsFailureQuery;
pub(crate) const ROOT: &str = "/api/v1/alicloud/agentteams/task-handling";
pub(crate) const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
pub(crate) const KINDS: [&str; 3] =
    ["agentteams-task-handling-state", "agentteams-task-handling-record", "agentteams-task-handling-request"];
pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) source: Id,
    pub(crate) binding: Value,
}
impl Fixture {
    pub(crate) async fn new() -> DomainResult<Self> {
        Self::from_harness(setup().await).await
    }
    pub(crate) async fn from_harness(mut h: Harness) -> DomainResult<Self> {
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        let tenant = h.tenant;
        let tenant_header: axum::http::HeaderValue = tenant.to_string().parse().map_err(|_| invalid())?;
        h.app =
            build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
                request.headers_mut().insert("x-agf-tenant", tenant_header.clone());
                async move { request }
            }));
        let saved = h
            .request(
                "PUT",
                CLOUD,
                Some(&h.admin),
                Some(json!({"expected_version":0,
            "enabled":true,"mock":true,"settings":{"instance_id":"inst-audit"}})),
            )
            .await;
        ok(&saved, StatusCode::OK);
        ok(
            &h.post(
                "/api/v1/alicloud/agentteams/sync",
                json!({"request_id":Id::new(),"configuration_version":1,
            "confirm_live":false}),
            )
            .await,
            StatusCode::OK,
        );
        let created =
            h.post("/api/v1/ingest/sources", json!({"name":"handling-owned-source","protocol":"http-webhook"})).await;
        ok(&created, StatusCode::CREATED);
        let source = id(&created.json()["id"])?;
        let bound = h
            .request(
                "PUT",
                &format!("/api/v1/alicloud/agentteams/audit-sources/{source}"),
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true})),
            )
            .await;
        ok(&bound, StatusCode::OK);
        Ok(Self { h, source, binding: bound.json() })
    }
    pub(crate) async fn push(&self, name: &str, status: &str) -> DomainResult<Id> {
        let response = self
            .h
            .post(
                &format!("/api/v1/alicloud/agentteams/audit-sources/{}/events", self.source),
                json!({"binding_id":self.binding["bindingId"],"events":[{"event_id":name,"event_time":Timestamp::now(),
                "kind":"task","from_team":"my-team","from_worker":"worker-demo","task_id":name,
                "trace_id":format!("trace-{name}"),"status":status,
                "message":"Collector cannot reach downstream; password=synthetic-private-password"}]}),
            )
            .await;
        ok(&response, StatusCode::OK);
        let scope = id(&self.binding["scopeId"])?;
        Ok(agf_core::ids::deterministic_id("agf.agentteams.event", &format!("{}:{scope}:{name}", self.h.tenant)))
    }
    pub(crate) async fn detail(&self, event: Id) -> Value {
        let response = self.h.get(&format!("{ROOT}/events/{event}")).await;
        ok(&response, StatusCode::OK);
        response.json()
    }
    pub(crate) async fn resolution(&self, event: Id, request: Id, version: u64, decision: &str) -> Value {
        let detail = self.detail(event).await;
        json!({"request_id":request,"expected_version":version,
            "expected_cloud_configuration_version":detail["currentSource"]["cloudConfigurationVersion"],
            "expected_source_fingerprint":detail["currentSource"]["fingerprint"],"decision":decision})
    }
    pub(crate) async fn resolve(&self, event: Id, input: Value) -> Resp {
        self.h.request("PUT", &format!("{ROOT}/events/{event}/resolution"), Some(&self.h.admin), Some(input)).await
    }
    pub(crate) async fn archive_input(&self, event: Id, request: Id) -> Value {
        let state = self.h.get(ROOT).await.json();
        let detail = self.detail(event).await;
        let current = &detail["currentSource"];
        json!({"request_id":request,"expected_generation":state["generation"],"event_ids":[event],
            "expected_cloud_configuration_version":if current["sourceGone"]==true {Value::Null}else{current["cloudConfigurationVersion"].clone()},
            "sources":[{"source_id":self.source,"fingerprint":current["fingerprint"]}]})
    }
    pub(crate) async fn snapshot(&self) -> DomainResult<Value> {
        let mut records = BTreeMap::new();
        for kind in KINDS {
            let mut rows: Vec<Value> = self.h.state.configurations.list(self.h.tenant, kind).await?;
            rows.sort_by_key(Value::to_string);
            records.insert(kind, rows);
        }
        let audit = self.h.state.store.audit_stats_durable(self.h.tenant).await?;
        Ok(json!({"records":records,"audit":audit}))
    }
    pub(crate) async fn original(&self, event: Id) -> DomainResult<Value> {
        let row =
            self.h.state.ingest_sink.agentteams_failure_record(self.h.tenant, event).await?.ok_or_else(invalid)?;
        Ok(serde_json::to_value(row)?)
    }
    pub(crate) async fn failure_query(&self) -> DomainResult<agf_ingest::pipeline::AgentTeamsFailureSnapshot> {
        let now = Timestamp::now();
        self.h
            .state
            .ingest_sink
            .agentteams_failure_snapshot(&AgentTeamsFailureQuery {
                tenant_id: self.h.tenant,
                source_id: Some(self.source),
                scope_id: None,
                from: now.offset_secs(-60),
                until: now.offset_secs(60),
                received_until: now,
            })
            .await
    }
}
pub(crate) fn id(value: &Value) -> DomainResult<Id> {
    Id::parse(value.as_str().ok_or_else(invalid)?).map_err(|_| invalid())
}
pub(crate) fn invalid() -> DomainError {
    DomainError::Validation("Owned task handling fixture is incomplete".into())
}
pub(crate) fn ok(response: &Resp, status: StatusCode) {
    assert_eq!(response.status, status, "{}", response.text);
}

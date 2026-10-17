//! Only new callback helpers; the previously accepted native SQL ownership/provider helpers stay untouched.
use crate::common::*;
pub(crate) use crate::scheduler_native_observation_database_support as native;
pub(crate) use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use native::{
    provider::{self, Engine},
    wire::fixture_error,
};
use sha2::{Digest, Sha256};

pub(crate) mod authority;
pub(crate) mod crypto;
pub(crate) mod gate;
pub(crate) mod identity;
mod negative;
pub(crate) mod progress;
pub(crate) mod publication;

pub(crate) const ROOT: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions";
pub(crate) const EXECUTION: &str = "scheduler-native-callback-execution";
pub(crate) const BATCH: &str = "scheduler-native-callback-batch";
pub(crate) const PROGRESS: &str = "scheduler-native-callback-progress";
pub(crate) const PENDING: &str = "scheduler-native-callback-pending";
pub(crate) const REQUEST: &str = "scheduler-native-callback-request";
pub(crate) const KINDS: [&str; 6] =
    ["asset-inventory", "log-pull", "redteam-cruise", "rule-hot-reload", "report", "archive"];
const SCOPES: [&str; 8] = [
    "alicloud:read",
    "assets:read",
    "sources:read",
    "sources:write",
    "redteam:read",
    "redteam:execute",
    "policies:write",
    "reports:write",
];

pub(crate) struct Fixture {
    pub(crate) case: native::SqlCase,
    pub(crate) engine: Engine,
    pub(crate) h: Harness,
    pub(crate) token: String,
    pub(crate) key: Id,
    pub(crate) observation: Id,
    pub(crate) binding: Value,
    pub(crate) target: Value,
}
impl Fixture {
    pub(crate) async fn new(label: &str) -> DomainResult<Self> {
        let case = native::SqlCase::open(label).await?;
        let engine = Engine::new(6, false).await?;
        let h = provider::attach(case.h.clone(), &engine)?;
        provider::configure(&h, &engine, 0, true).await?;
        let observation = Id::new();
        let observed =
            native::post(&h, &format!("{}/observe", native::BASE), native::observe(observation, false)).await?;
        assert_eq!(observed["status"], "observed");
        assert_eq!(observed["total"], 6);
        assert_eq!(observed["originalTarget"]["transportMode"], "loopback_test");
        assert_eq!(observed["appId"], "9007199254740993");
        let reply = h
            .request(
                "PUT",
                &format!("{}/bindings", native::BASE),
                Some(&h.admin),
                Some(replace(Id::new(), 0, observation, 1)),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "real six-job association status");
        let binding = reply.json();
        assert_eq!(binding["items"].as_array().map(Vec::len), Some(6));
        assert!(
            binding["items"].as_array().is_some_and(|items| items.iter().all(|item| item["eligibility"] == "eligible"))
        );
        assert_eq!(binding["callbackBindingEnforced"], false);
        let issued = h
            .post("/api/v1/settings/api-keys", json!({"name":format!("owned-callback-{}",Id::new()),"scopes":SCOPES}))
            .await;
        assert_eq!(issued.status, StatusCode::CREATED);
        let issued = issued.json();
        let token =
            issued["plaintext"].as_str().ok_or_else(|| fixture_error("created key credential absent"))?.to_owned();
        let key = native::identifier(&issued["api_key"], "id")?;
        engine.count(2).await?;
        Ok(Self { case, engine, h, token, key, observation, binding, target: observed["originalTarget"].clone() })
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        provider::attach(self.case.second().await?, &self.engine)
    }
    pub(crate) fn input(&self, kind: &str, execution: &str, index: u16, total: u16) -> Value {
        json!({"request_id":Id::new(),"kind":kind,"app_id":"9007199254740993","job_id":job(kind),
            "job_execution_id":execution,"partition_index":index,"partition_total":total,
            "binding_version":self.binding["version"],"configuration_version":self.target["configurationVersion"],
            "source_fingerprint":self.target["fingerprint"]})
    }
    pub(crate) async fn admit(&self, input: Value) -> DomainResult<Value> {
        call(&self.h, &self.token, "POST", ROOT, Some(input)).await
    }
    pub(crate) async fn get(&self, fact: &Value) -> DomainResult<Value> {
        call(&self.h, &self.token, "GET", &fact_path(fact)?, None).await
    }
    pub(crate) async fn start(&self, fact: &Value) -> DomainResult<Value> {
        call(&self.h, &self.token, "POST", &format!("{}/validate", fact_path(fact)?), Some(claim(fact))).await
    }
    pub(crate) async fn complete(&self, fact: &Value, outcome: Value) -> DomainResult<Value> {
        call(&self.h, &self.token, "POST", &format!("{}/complete", fact_path(fact)?), Some(complete(fact, outcome)))
            .await
    }
    pub(crate) async fn finish(
        &self,
        kind: &str,
        execution: &str,
        index: u16,
        total: u16,
        outcome: Value,
    ) -> DomainResult<Value> {
        let admitted = self.admit(self.input(kind, execution, index, total)).await?;
        assert_eq!(admitted["mayConfirmStart"], true);
        assert_eq!(admitted["mayExecute"], false);
        let started = self.start(&admitted).await?;
        assert_eq!(started["mayExecute"], true);
        let done = self.complete(&started, outcome).await?;
        assert_eq!(done["completionState"], "complete");
        passive(&done);
        Ok(done)
    }
    pub(crate) async fn clean(&self) -> DomainResult<()> {
        native::chain(&self.h).await?;
        self.case.owner.pool.close().await;
        Ok(())
    }
}
pub(crate) fn job(kind: &str) -> String {
    KINDS
        .iter()
        .position(|candidate| *candidate == kind)
        .map_or_else(String::new, |index| (9_007_199_254_741_001_i64 + index as i64).to_string())
}
pub(crate) fn replace(id: Id, version: u64, observation: Id, configuration: u64) -> Value {
    json!({"action":"replace","request_id":id,"expected_version":version,"configuration_version":configuration,
        "observation_id":observation,"bindings":KINDS.map(|kind|json!({"kind":kind,"job_id":job(kind)})),"confirm_local_only":true})
}
pub(crate) fn good() -> Value {
    // Actual in-memory synthetic observation bytes, not a file path, provider attestation or an executed handler.
    let bytes = b"owned callback API reported-outcome fixture; no business handler";
    json!({"ok":true,"skipped":false,"degraded":false,"artifacts":[{"sha256":hex::encode(Sha256::digest(bytes)),"bytes":bytes.len()}]})
}
pub(crate) fn claim(fact: &Value) -> Value {
    json!({"claim_id":fact["claimId"]})
}
pub(crate) fn complete(fact: &Value, outcome: Value) -> Value {
    json!({"claim_id":fact["claimId"],"outcome":outcome})
}
pub(crate) fn fact_path(fact: &Value) -> DomainResult<String> {
    Ok(format!("{ROOT}/{}", native::identifier(fact, "factId")?))
}
pub(crate) fn passive(value: &Value) {
    assert_eq!(value["mayConfirmStart"], false);
    assert_eq!(value["mayExecute"], false);
}
pub(crate) async fn call(
    h: &Harness,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> DomainResult<Value> {
    let reply = h.request(method, path, Some(token), body).await;
    assert_eq!(reply.status, StatusCode::OK, "owned callback API status");
    let result = reply.json();
    let safe = serde_json::to_string(&result)?;
    assert!(!safe.contains(token), "service key must never be returned");
    for carrier in ["SYNTHETIC-CALLBACK-TOKEN", "SYNTHETIC-APP-TOKEN", "access_key_secret", "JobHandler"] {
        assert!(!safe.contains(carrier), "callback DTO cannot contain a carrier");
    }
    Ok(result)
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut base = native::snapshot(h).await?;
    let mut records = BTreeMap::new();
    for kind in [EXECUTION, BATCH, PROGRESS, PENDING, REQUEST] {
        records.insert(kind, native::rows(h, kind).await?);
    }
    base["callback"] = serde_json::to_value(records)?;
    Ok(base)
}
pub(crate) async fn audit_count(h: &Harness, fact: &Value, kind: &str) -> DomainResult<usize> {
    Ok(native::audits(h, native::identifier(fact, "factId")?, kind).await?.len())
}
pub(crate) fn pending_id(fact: &Value) -> DomainResult<Id> {
    Ok(deterministic_id("agf.scheduler.callback.pending.v1", &native::identifier(fact, "factId")?.to_string()))
}

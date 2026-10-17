pub(crate) mod owned;
pub(crate) mod wire;
use crate::common::*;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    ids::Id,
};
pub(crate) const BASE: &str = "/api/v1/redteam/multi-target";
pub(crate) const CANARY: &str = "McpProtectedCanary_123456";
pub(crate) const SECRET: &str = "owned-target-bearer-private";
pub(crate) struct Fixture {
    pub(crate) case: owned::Case,
    pub(crate) wires: Vec<wire::Wire>,
    pub(crate) ids: Vec<Id>,
    pub(crate) assets: Vec<Id>,
    pub(crate) selections: Value,
    pub(crate) key: String,
    #[allow(dead_code, reason = "Shared fixture field used by the multi-target database test binary")]
    pub(crate) key_id: Id,
}
impl Fixture {
    pub(crate) async fn new(label: &str, readonly: bool, held: bool) -> DomainResult<Self> {
        Self::new_with_legacy(label, readonly, held, false).await
    }
    pub(crate) async fn new_with_legacy(label: &str, readonly: bool, held: bool, legacy: bool) -> DomainResult<Self> {
        let mut case = owned::Case::open(label).await?;
        let wires=vec![wire::Wire::start(json!({"choices":[{"finish_reason":"stop","message":{"content":"public-reference-123"}}]}),false,true,held).await?,
            wire::Wire::start_protocol(json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":format!("Untrusted fixture instruction; {CANARY}")}]}}),wire::ProtocolOptions {
                protocol: if legacy { wire::Protocol::LegacyMcp } else { wire::Protocol::CurrentMcp },
                readonly_tools: readonly,
                hold_first_request: false,
            }).await?,
            wire::Wire::start(json!({"choices":[{"finish_reason":"stop","message":{"content":"Summary of untrusted public context"}}]}),false,true,false).await?];
        let mut ids = Vec::new();
        let mut assets = Vec::new();
        let mut targets = Vec::new();
        for (ordinal, wire) in wires.iter().enumerate() {
            let mcp = ordinal == 1;
            let kind = if mcp { "mcp-server" } else { "agent" };
            let marker = format!("rt-multi-{}", Id::new());
            let imported = case
                .h
                .post("/api/v1/assets/discovery", json!({"assets":[{"kind":kind,"name":marker,"fingerprint":marker}]}))
                .await;
            assert!(imported.status == StatusCode::OK, "Owned discovered target rejected");
            let asset = case
                .h
                .state
                .store
                .asset_list_all_durable(case.h.tenant)
                .await?
                .into_iter()
                .find(|asset| asset.name == marker)
                .ok_or_else(owned::failure)?;
            let id = Id::new();
            let profile_kind = if mcp { "mcp" } else { "agent" };
            let mut body = json!({"id":id,"expected_version":0,"asset_id":asset.id,"name":"Owned registered multi-target",
                "url":wire.url(),"enabled":true,"bearer_token":SECRET,"protected_canary":if mcp {CANARY}else{"AgentProtectedCanary_123456"}});
            if mcp {
                body["tool_name"] = json!("safe_query");
                body["argument_name"] = json!("query");
            } else {
                body["model"] = json!("owned-model");
            }
            let saved = case.h.post(&format!("/api/v1/redteam/{profile_kind}-targets"), body).await;
            assert!(saved.status == StatusCode::OK, "Owned target profile rejected");
            ids.push(id);
            assets.push(asset.id);
            targets.push(json!({"kind":format!("{profile_kind}-http"),"profile_id":id,"expected_version":1}));
        }
        capability(&mut case.h, &ids, &wires)?;
        let issued = case
            .h
            .post(
                "/api/v1/settings/api-keys",
                json!({"name":"Owned multi-target caller",
            "scopes":["redteam:execute","redteam:read","agents:read","mcps:read"]}),
            )
            .await;
        assert!(issued.status == StatusCode::CREATED, "Real Key issuance failed");
        let value = issued.json();
        let key = value["plaintext"].as_str().ok_or_else(owned::failure)?.to_owned();
        let key_id = serde_json::from_value(value["api_key"]["id"].clone())?;
        Ok(Self { case, wires, ids, assets, selections: json!(targets), key, key_id })
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        let mut h = self.case.second().await?;
        capability(&mut h, &self.ids, &self.wires)?;
        Ok(h)
    }
    pub(crate) async fn body(&self, request: Id) -> DomainResult<Value> {
        let response = self.call("POST", &format!("{BASE}/preview"), Some(json!({"targets":self.selections}))).await;
        assert!(response.status == StatusCode::OK, "Real local preview rejected");
        Ok(
            json!({"request_id":request,"targets":self.selections,"reviewed_topology_sha256":response.json()["topologySha256"],
            "confirm_registered_targets":true,"confirm_live":false}),
        )
    }
    pub(crate) async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        key_call(&self.case.h, &self.key, method, path, body).await
    }
    pub(crate) fn counts(&self) -> DomainResult<Vec<usize>> {
        self.wires.iter().map(|wire| wire.requests().map(|rows| rows.len())).collect()
    }
    pub(crate) async fn snapshot(&self) -> DomainResult<Value> {
        let mut records = Vec::new();
        for kind in [
            "redteam-multi-target-fact",
            "redteam-multi-target-capacity",
            "redteam-multi-target-owner-index",
            "redteam-multi-managed-profile",
        ] {
            let mut rows: Vec<Value> = self.case.h.state.configurations.list(self.case.h.tenant, kind).await?;
            rows.sort_by_key(Value::to_string);
            records.push(json!(rows));
        }
        Ok(json!({"records":records,"audit":self.case.h.state.store.audit_stats_durable(self.case.h.tenant).await?,
            "findings":self.case.h.state.store.finding_list_all_durable(self.case.h.tenant).await?}))
    }
    pub(crate) async fn chain(&self) -> DomainResult<()> {
        assert!(self.case.h.state.store.audit_verify_durable(self.case.h.tenant).await?.passed);
        Ok(())
    }
    pub(crate) async fn terminal_audits(&self, request: Id, success: bool) -> DomainResult<usize> {
        let id = request.to_string();
        let rows = self.case.h.state.store.audit_chain_durable(self.case.h.tenant, 0, i64::MAX).await?;
        Ok(rows
            .iter()
            .filter(|row| {
                row.target.kind == "redteam-multi-target"
                    && row.target.id.as_deref() == Some(id.as_str())
                    && row.action == AuditAction::Execute
                    && row.outcome == if success { AuditOutcome::Success } else { AuditOutcome::Failure }
            })
            .count())
    }
}
pub(crate) fn capability(h: &mut Harness, ids: &[Id], wires: &[wire::Wire]) -> DomainResult<()> {
    h.state = h.state.clone().with_multi_target_loopback_targets(
        h.tenant,
        ids.iter().copied().zip(wires.iter().map(|wire| wire.address)).collect(),
    )?;
    owned::rebuild(h);
    Ok(())
}
pub(crate) async fn key_call(h: &Harness, key: &str, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(method, path, &[("x-agf-key", key)], body).await
}
pub(crate) fn private_free(response: &Resp) {
    assert!(
        !response.text.contains(CANARY)
            && !response.text.contains(SECRET)
            && !response.text.contains("owned-private-session"),
        "Safe DTO leaked an owned protected value"
    );
}
pub(crate) struct Pending(Option<tokio::task::JoinHandle<Resp>>);
impl Pending {
    #[allow(dead_code, reason = "Shared cancellation helper used by the multi-target database test binary")]
    pub(crate) fn abort(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
    pub(crate) fn start(h: Harness, key: String, body: Value) -> Self {
        Self(Some(tokio::spawn(async move { key_call(&h, &key, "POST", &format!("{BASE}/runs"), Some(body)).await })))
    }
    pub(crate) async fn finish(&mut self) -> DomainResult<Resp> {
        let task = self.0.as_mut().ok_or_else(owned::failure)?;
        let response = tokio::time::timeout(std::time::Duration::from_secs(12), task)
            .await
            .map_err(|_| owned::failure())?
            .map_err(|_| owned::failure())?;
        self.0.take();
        Ok(response)
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

//! Real registered HTTP MCP transport; a synthetic local upstream is never the platform ACK or ledger.
use super::{
    fail,
    owned::Owned,
    platform::{Platform, Server},
};
use agf_core::{error::DomainResult, ids::Id};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use futures::FutureExt;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const TOKEN: &str = "owned-upstream-mcp-secret";
#[derive(Default)]
struct Upstream {
    empty: AtomicBool,
    calls: Mutex<BTreeMap<String, usize>>,
}
impl Upstream {
    fn count(&self, method: &str) -> usize {
        self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
    }
}
async fn receive(State(upstream): State<Arc<Upstream>>, headers: HeaderMap, Json(frame): Json<Value>) -> Json<Value> {
    assert!(
        headers.get("authorization").unwrap() == format!("Bearer {TOKEN}").as_str(),
        "upstream authorization must be isolated"
    );
    assert!(!headers.contains_key("x-agf-key") && !headers.contains_key("cookie"));
    let method = frame["method"].as_str().unwrap();
    *upstream.calls.lock().unwrap().entry(method.into()).or_default() += 1;
    let result = match method {
        "server/discover" => {
            json!({"serverInfo":{"name":"owned MCP service","version":"1"},"capabilities":{"tools":{}}})
        }
        "tools/list" if upstream.empty.load(Ordering::SeqCst) => json!({"tools":[]}),
        "tools/list" if frame["params"].get("cursor").is_none() => {
            json!({"tools":[{"name":"query","inputSchema":{"type":"object"}}],"nextCursor":"last-owned-page"})
        }
        "tools/list" => {
            assert_eq!(frame["params"]["cursor"], "last-owned-page");
            json!({"tools":[{"name":"other","inputSchema":{"type":"object"}}]})
        }
        "tools/call" => {
            assert_eq!(frame["params"]["name"], "query");
            json!({"content":[{"type":"text","text":"actual local tool response"}],"isError":false})
        }
        _ => panic!("unexpected local MCP method"),
    };
    Json(json!({"jsonrpc":"2.0","id":frame["id"],"result":result}))
}
fn call(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"query","arguments":{"query":"safe"},
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"owned SQL client","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}})
}
pub(crate) async fn acceptance() -> DomainResult<()> {
    let owned = Owned::open().await?;
    let mut platform = Platform::open(&owned).await?;
    let upstream = Arc::new(Upstream::default());
    upstream.empty.store(true, Ordering::SeqCst);
    let mut server = Server::start(Router::new().route("/mcp", post(receive)).with_state(upstream.clone())).await?;
    let result=AssertUnwindSafe(async {
        let endpoint=platform.admin("POST","/api/v1/mcp/endpoints",Some(json!({"expected_version":0,"name":"owned complete MCP","url":format!("{}/mcp",server.origin),"enabled":true,"idle_timeout_secs":5,"bearer_token":TOKEN})),200).await?;
        let id:Id=serde_json::from_value(endpoint["id"].clone())?;
        assert!(!endpoint.to_string().contains(TOKEN));assert_eq!(endpoint["credential_configured"],true);
        let probe=format!("/api/v1/mcp/endpoints/{id}/probe");
        let empty=platform.admin("POST",&probe,Some(json!({"protocol":"2026-07-28"})),200).await?;
        assert_eq!(empty["tools"]["tools"],json!([]));assert_eq!(empty["session_closed"],true);
        assert_eq!(upstream.count("server/discover"),1);assert_eq!(upstream.count("tools/list"),1);assert_eq!(upstream.count("tools/call"),0);
        let detail=platform.admin("GET",&format!("/api/v1/mcps/{id}"),None,200).await?;
        assert_eq!(detail["mcp_server"]["toolCount"],0,"complete empty catalog is known zero, not unknown");
        upstream.empty.store(false,Ordering::SeqCst);
        let full=platform.admin("POST",&probe,Some(json!({"protocol":"2026-07-28"})),200).await?;
        assert_eq!(full["tools"]["tools"].as_array().unwrap().len(),2);
        assert_eq!(upstream.count("tools/list"),3);assert_eq!(upstream.count("tools/call"),0);
        let key=platform.key(&["mcps:execute","policies:read"]).await?;
        let (status,reply)=platform.mcp(&key,id,call(7)).await?;assert_eq!(status,200);assert_eq!(reply["id"],7);assert_eq!(reply["result"]["isError"],false);
        assert_eq!(upstream.count("tools/call"),1);
        let usage_path=format!("/api/v1/mcp/endpoints/{id}/usage");
        let usage=platform.admin("GET",&usage_path,None,200).await?;
        assert_eq!(usage["items"].as_array().unwrap().len(),1);
        assert_eq!(usage["items"][0]["attempts"],1);assert_eq!(usage["items"][0]["succeeded"],1);
        assert_eq!(usage["items"][0]["failed"],0);assert_eq!(usage["items"][0]["unknown"],0);assert_eq!(usage["items"][0]["inflight"],0);
        let policy=platform.admin("POST","/api/v1/policies",Some(json!({"name":"owned deny MCP","expected_version":0,"language":"cel", "source":json!({"action":"deny","reason":"owned policy denies this MCP lane"}).to_string(),"action":"deny","enabled":true,"priority":1,"intercept_points":["mcp-proxy"]})),201).await?;
        let signed:agf_core::policy::Policy=serde_json::from_value(policy["policy"].clone())?;
        agf_api::policy_store::signer(&platform.state)?.verify(&signed)?;
        let (status,_)=platform.mcp(&key,id,call(8)).await?;assert_eq!(status,403);assert_eq!(upstream.count("tools/call"),1);
        let interceptions=platform.state.configurations.list::<Value>(platform.tenant,"runtime-interception").await?;
        assert!(interceptions.iter().any(|row|row["verdict"]=="blocked"),"normal signed runtime deny must persist its interception evidence");
        assert!(platform.admin("GET",&usage_path,None,200).await? == usage,"pre-forward policy rejection is not a delivered tool attempt");
        platform.revoke(&key).await?;
        let (status,_)=platform.mcp(&key,id,call(9)).await?;assert_eq!(status,401);assert_eq!(upstream.count("tools/call"),1);
        let mut fresh=platform.restart(&owned).await?;
        assert!(fresh.admin("GET",&usage_path,None,200).await? == usage,"restart must retain exact MCP usage");
        let detail=fresh.admin("GET",&format!("/api/v1/mcps/{id}"),None,200).await?;
        assert_eq!(detail["mcp_server"]["toolCount"],2);
        let asset=fresh.state.store.asset_get_durable(fresh.tenant,id).await?.ok_or_else(||fail("SQL MCP asset absent"))?;
        assert_eq!(asset.attributes["tools"].as_array().unwrap().len(),2);
        let rows=fresh.state.configurations.list::<Value>(fresh.tenant,"mcp-tool-usage").await?;assert_eq!(rows.len(),1);
        assert!(fresh.state.configurations.list::<Value>(fresh.tenant,"runtime-interception").await? == interceptions,"restart must retain exact interceptions");
        let audits=fresh.state.store.audit_chain_durable(fresh.tenant,0,i64::MAX).await?;
        assert!(audits.iter().any(|row|row.target.kind=="mcp-http-endpoint" && row.target.id.as_deref()==Some(id.to_string().as_str())));
        let encoded=serde_json::to_string(&json!({"detail":detail,"usage":rows,"audits":audits,"interception":interceptions}))?;
        assert!(!encoded.contains(TOKEN));assert!(!encoded.contains(&key.token));
        fresh.chain().await?;fresh.server.stop().await;platform.chain().await?;Ok(())
    }).catch_unwind().await;
    server.stop().await;
    platform.server.stop().await;
    let cleaned = owned.finish().await;
    match result {
        Ok(result) => {
            cleaned?;
            result
        }
        Err(panic) => {
            cleaned?;
            std::panic::resume_unwind(panic)
        }
    }
}

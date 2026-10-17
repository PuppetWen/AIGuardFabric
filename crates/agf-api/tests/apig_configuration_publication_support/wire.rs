//! A real literal-loopback HTTP provider, containing only synthetic evidence and bounded effects.
use crate::{apig_configuration_publication_support::*, common::*};
use agf_core::error::{DomainError, DomainResult};
use axum::{Json, body::Bytes, extract::State, http::Method, routing::get};
use std::sync::Mutex;
use tokio::task::JoinHandle;

struct Data {
    raw: Value,
    reads: u64,
    writes: u64,
    bad_ack: bool,
}
pub(crate) struct Engine {
    pub(crate) address: std::net::SocketAddr,
    data: Arc<Mutex<Data>>,
    task: JoinHandle<std::io::Result<()>>,
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Engine {
    pub(crate) async fn new(kind: &str) -> DomainResult<Self> {
        let fixture: Value =
            serde_json::from_str(include_str!("../../src/apig_configuration_publication/mock_fixture.json"))?;
        let action = if kind == "content" { "GetPluginAttachment" } else { "GetHttpApi" };
        let data = Arc::new(Mutex::new(Data {
            raw: fixture["responses"][action]["data"].clone(),
            reads: 0,
            writes: 0,
            bad_ack: false,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let app = Router::new()
            .route("/v1/plugin-attachments/pa-owned", get(respond).put(respond))
            .route("/v1/http-apis/api-owned", get(respond).put(respond))
            .with_state(data.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { address, data, task })
    }
    pub(crate) fn counts(&self) -> DomainResult<(u64, u64)> {
        let d = self.data.lock().map_err(|_| DomainError::Internal("owned wire lock".into()))?;
        Ok((d.reads, d.writes))
    }
    pub(crate) fn bad_ack(&self) -> DomainResult<()> {
        self.data.lock().map_err(|_| DomainError::Internal("owned wire lock".into()))?.bad_ack = true;
        Ok(())
    }
    pub(crate) fn raw(&self) -> DomainResult<Value> {
        Ok(self.data.lock().map_err(|_| DomainError::Internal("owned wire lock".into()))?.raw.clone())
    }
}
async fn respond(
    State(data): State<Arc<Mutex<Data>>>,
    method: Method,
    headers: HeaderMap,
    bytes: Bytes,
) -> (StatusCode, Json<Value>) {
    assert!(headers.get("authorization").is_some());
    let Ok(mut d) = data.lock() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":"failed"})));
    };
    if method == Method::GET {
        d.reads += 1;
        return (StatusCode::OK, Json(json!({"code":"Ok","requestId":format!("owned-read-{}",d.reads),"data":d.raw})));
    }
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"code":"failed"})));
    };
    d.writes += 1;
    if body.get("pluginConfig").is_some() {
        d.raw["pluginConfig"] = body["pluginConfig"].clone();
        d.raw["enable"] = body["enable"].clone();
    } else {
        assert_eq!(body["onlyChangeConfig"], true);
        for (k, v) in body.as_object().into_iter().flatten() {
            if k != "onlyChangeConfig" {
                d.raw[k] = v.clone();
            }
        }
    }
    if d.bad_ack {
        (StatusCode::OK, Json(json!({"code":"bad-provider-ack"})))
    } else {
        (StatusCode::OK, Json(json!({"code":"Ok","requestId":format!("owned-update-{}",d.writes)})))
    }
}
pub(crate) async fn live(kind: &str, engine: &Engine) -> DomainResult<Harness> {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.apig_configuration_publication = Arc::new(
        agf_api::apig_configuration_publication::Registry::literal_loopback_for_test(h.tenant, engine.address)?,
    );
    h.app = build_router(h.state.clone());
    save(&h, 0, kind, engine, "owned-wire-account").await?;
    Ok(h)
}
pub(crate) async fn save(h: &Harness, version: u64, kind: &str, engine: &Engine, account: &str) -> DomainResult<()> {
    let mut s = settings(kind);
    s["endpoint"] = json!(format!("http://{}", engine.address));
    s["account_id"] = json!(account);
    let r = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":true,"mock":false,"settings":s,
        "secrets":{"access_key_id":"owned-wire-id","access_key_secret":"owned-wire-secret"}})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    Ok(())
}

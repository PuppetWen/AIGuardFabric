//! Authenticated HTTP MCP gateway. Upstreams are explicitly registered by tenant administrators.
pub mod config;
mod cursor;
pub(crate) mod discovery;
pub(crate) mod forward;
pub(crate) mod legacy_sse;
pub(crate) mod oauth;
pub(crate) mod probe;
mod protocol;
mod sessions;
mod stream;
pub(crate) mod usage;

use agf_core::error::DomainError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

const MAX_FRAME: usize = 1024 * 1024;

pub(crate) fn invalid(message: &str) -> DomainError {
    DomainError::Validation(message.into())
}

pub(crate) fn probe_rejection(error: &Value, legacy_sse: bool) -> DomainError {
    let transport = if legacy_sse { "MCP SSE" } else { "MCP" };
    let code = error["code"].as_i64().map_or_else(String::new, |value| format!(" (JSON-RPC code {value})"));
    invalid(&format!(
        "{transport} discovery rejected by upstream{code}; check protocol, endpoint permissions and server logs"
    ))
}

pub(crate) fn safe_upstream_frame(frame: Value) -> Value {
    if frame.get("method").is_some() || frame.get("error").is_none() {
        return frame;
    }
    let code = frame["error"]["code"].as_i64().unwrap_or(-32000);
    json!({"jsonrpc":"2.0","id":frame["id"],"error":{
        "code":code,"message":"MCP upstream returned a JSON-RPC error; check its server logs"
    }})
}

pub(crate) fn rpc_error(status: StatusCode, id: &Value, code: i32, message: &str) -> Response {
    (status, Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}))).into_response()
}

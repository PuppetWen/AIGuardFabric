//! Callable model gateway and model onboarding; every write is acknowledged after persistence.
use crate::model_gateway::{ENDPOINT_KIND, StoredEndpoint};
use crate::{
    error::ApiResult,
    middleware::Principal,
    routes::{ApiJson, parse_id},
    state::AppState,
};
use agf_core::{
    enums::{DataClass, LlmProvider},
    error::DomainError,
    ids::Id,
    time::Timestamp,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
mod anthropic;
mod anthropic_stream;
mod atomic_stream;
mod chat;
pub(crate) mod credentials;
mod endpoints;
mod policy;
pub(crate) mod prepared;
mod protocol;
mod wire;

/// Internal authoring tools use the same authenticated gateway as SDK callers.
pub(crate) async fn parser_completion(
    state: AppState,
    principal: Principal,
    body: Value,
    data_class: &str,
) -> ApiResult<(Value, bool)> {
    let class: DataClass =
        serde_json::from_value(json!(data_class)).map_err(|_| DomainError::Validation("无效的数据分级".into()))?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-agf-data-class",
        axum::http::HeaderValue::from_str(class.as_str())
            .map_err(|_| DomainError::Validation("无效的数据分级".into()))?,
    );
    let response = chat::execute(state, principal, headers, wire::request(body)?, protocol::Protocol::OpenAi).await?;
    let mocked = response.headers().get("x-agf-mocked").is_some_and(|value| value == "true");
    let bytes = axum::body::to_bytes(response.into_body(), 262_144)
        .await
        .map_err(|_| DomainError::Validation("模型响应超出解析器草案长度限制".into()))?;
    Ok((serde_json::from_slice(&bytes)?, mocked))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/gateway/providers", get(endpoints::catalog))
        .route("/gateway/endpoints", get(endpoints::list).post(endpoints::create))
        .route("/gateway/endpoints/{id}", put(endpoints::update).delete(endpoints::remove))
        .route("/chat/completions", post(chat::complete))
        .route("/messages", post(anthropic::messages))
}
pub fn compat_router() -> Router<AppState> {
    Router::new()
        .route("/v1/chat/completions", post(chat::complete))
        .route("/v1/models", get(chat::models))
        .route("/v1/messages", post(anthropic::messages))
        .route("/v1/messages/count_tokens", post(anthropic::count_tokens))
}

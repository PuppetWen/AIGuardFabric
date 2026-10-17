use super::{ProfileInput, Submission, load, save};
use crate::{AppState, Principal, error::ApiError, routes::ApiJson};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::HeaderMap,
    routing::get,
};
use tokio::time::{Duration, Instant};

/// Parent registration is separate; management endpoints never call an embedding provider.
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/models/semantic-cache/profile", get(show).put(update)).layer(DefaultBodyLimit::max(16 * 1024))
}
async fn show(State(state): State<AppState>, principal: Principal) -> Result<Json<super::ProfileView>, ApiError> {
    Ok(Json(load(&state, &principal).await?))
}
async fn update(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ProfileInput>,
) -> Result<Json<super::ProfileView>, ApiError> {
    let submission = Submission::capture(&state, &principal, &headers, Instant::now() + Duration::from_secs(110))?;
    Ok(Json(Box::pin(save(&state, &submission, &input)).await?))
}

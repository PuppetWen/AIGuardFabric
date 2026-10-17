//! 只公开明确发布的采集器制品；禁止从 URL 读取任意文件路径。
use crate::{error::ApiResult, state::AppState};
use agf_core::error::DomainError;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const PLATFORMS: &[(&str, &str)] = &[
    ("windows-amd64", "dist/windows/agf-agent.exe"),
    ("linux-amd64", "dist/linux/agf-agent"),
    ("macos-arm64", "dist/macos-arm64/agf-agent"),
];

pub fn router() -> Router<AppState> {
    Router::new().route("/downloads/agents", get(manifest)).route("/downloads/agents/{platform}", get(download))
}

fn artifact(state: &AppState, platform: &str) -> ApiResult<PathBuf> {
    let relative = PLATFORMS
        .iter()
        .find(|(name, _)| *name == platform)
        .map(|(_, path)| path)
        .ok_or_else(|| DomainError::NotFound { entity: "agent-artifact", id: platform.into() })?;
    Ok(PathBuf::from(&state.config.project_root).join(relative))
}

async fn read(state: &AppState, platform: &str) -> ApiResult<Vec<u8>> {
    let path = artifact(state, platform)?;
    let metadata = tokio::fs::metadata(&path).await.map_err(|_| DomainError::NotFound {
        entity: "agent-artifact",
        id: format!("{platform} 尚未发布；请按接入指南从源码构建"),
    })?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err(DomainError::Config("采集器制品大小异常".into()).into());
    }
    tokio::fs::read(path).await.map_err(|_| DomainError::Internal("读取采集器制品失败".into()).into())
}

async fn manifest(State(state): State<AppState>) -> Json<Value> {
    let mut items = Vec::new();
    for (platform, _) in PLATFORMS {
        if let Ok(bytes) = read(&state, platform).await {
            items.push(json!({"platform":platform,"url":format!("/downloads/agents/{platform}"),
                "sha256":hex::encode(Sha256::digest(&bytes)),"size_bytes":bytes.len()}));
        }
    }
    Json(json!({"version":crate::VERSION,"items":items}))
}

async fn download(State(state): State<AppState>, Path(platform): Path<String>) -> ApiResult<Response> {
    let bytes = read(&state, &platform).await?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let name = if platform == "windows-amd64" { "agf-agent.exe" } else { "agf-agent" };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            (header::ETAG, format!("\"{digest}\"")),
            (header::CACHE_CONTROL, "no-cache".into()),
        ],
        Body::from(bytes),
    )
        .into_response())
}

/// Only advertise a currently readable, bounded artifact, using the same path as downloads.
pub(crate) async fn published_digest(state: &AppState, platform: &str) -> Option<String> {
    read(state, platform).await.ok().map(|bytes| hex::encode(Sha256::digest(&bytes)))
}

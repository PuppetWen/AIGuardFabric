//! Parser samples and dry runs use the same engine as live ingestion; no event is written.
use super::*;
use crate::routes::ApiJson;
use agf_core::parser::ParserEngine;
use serde_json::json;

pub(super) async fn preview(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "parsers", "read")?;
    let parser = crate::parser_store::find(&state, principal.tenant, &id).await?;
    let custom = state
        .configurations
        .get::<crate::parser_store::Record>(principal.tenant, crate::parser_store::KIND, parser.id)
        .await?;
    let sample = match custom.and_then(|row| row.current) {
        Some(revision) => Some(revision.sample),
        None => fixture(&state, &parser.definition.sample_fixture).await,
    };
    let outcome = sample
        .as_ref()
        .filter(|_| parser.definition.engine != ParserEngine::Plugin)
        .map(|raw| agf_ingest::engine::parse_with(&parser.definition, raw));
    Ok(Json(json!({
        "key":parser.definition.key,
        "editable":state.parsers.find_id(parser.id).is_none(),
        "enabled":parser.enabled, "priority":parser.priority, "version":parser.definition.version,
        "definition_json":serde_json::to_string_pretty(&parser.definition)?,
        "sample_raw":sample,
        "outcome":outcome,
        "note":if sample.is_none() {"当前安装包没有此模板的测试样本，请粘贴脱敏日志进行试解析。"} else {"仅预览，不写入日志和事件仓储。"},
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SampleInput {
    sample: String,
}

pub(super) async fn test_sample(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<SampleInput>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "parsers", "read")?;
    if input.sample.is_empty() || input.sample.len() > 65_536 {
        return Err(DomainError::Validation("样本须为 1–65536 字节 UTF-8 文本".into()).into());
    }
    let parser = crate::parser_store::find(&state, principal.tenant, &id).await?;
    if parser.definition.engine == ParserEngine::Plugin {
        return Err(DomainError::PreconditionFailed("原生插件请通过隔离的采集器验证".into()).into());
    }
    let definition = parser.definition.clone();
    let outcome = tokio::task::spawn_blocking(move || agf_ingest::engine::parse_with(&definition, &input.sample))
        .await
        .map_err(|_| DomainError::Internal("解析任务未完成".into()))?;
    Ok(Json(serde_json::to_value(outcome)?))
}

async fn fixture(state: &AppState, name: &str) -> Option<String> {
    use std::path::{Component, Path};
    let (file, anchor) = name.split_once('#').unwrap_or((name, ""));
    if file.is_empty() || Path::new(file).components().any(|part| !matches!(part, Component::Normal(_))) {
        return None;
    }
    let root = Path::new(&state.config.project_root);
    let (base, relative) = if let Some(relative) = file.strip_prefix("tests/fixtures/logs/") {
        (root.join("tests/fixtures/logs"), relative)
    } else if let Some(relative) = file.strip_prefix("parsers/") {
        (root.join("parsers"), relative)
    } else if Path::new(file).components().count() == 1 {
        (root.join("tests/fixtures/logs"), file)
    } else {
        return None;
    };
    let content = read_under(&base, relative).await?;
    let sample = if anchor.is_empty() {
        content
    } else {
        let values: serde_json::Value = serde_json::from_str(&content).ok()?;
        let entry = &values["samples"][anchor];
        if let Some(line) = entry["line"].as_str() {
            line.to_owned()
        } else {
            read_under(&root.join("tests/fixtures/logs"), entry["fixture"].as_str()?).await?
        }
    };
    (sample.len() <= 65_536).then_some(sample)
}

async fn read_under(base: &std::path::Path, relative: &str) -> Option<String> {
    if relative.is_empty()
        || std::path::Path::new(relative).components().any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return None;
    }
    let base = tokio::fs::canonicalize(base).await.ok()?;
    let path = tokio::fs::canonicalize(base.join(relative)).await.ok()?;
    if !path.starts_with(&base) || tokio::fs::metadata(&path).await.ok()?.len() > 1_048_576 {
        return None;
    }
    tokio::fs::read_to_string(path).await.ok()
}

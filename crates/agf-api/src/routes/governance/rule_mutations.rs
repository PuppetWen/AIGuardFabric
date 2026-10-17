//! Rule editing, publication and rollback with sample gates.
use super::*;
use crate::rule_store::publication::{Grant, Submission};
use agf_core::error::DomainResult;
use axum::http::HeaderMap;

#[derive(Debug, Deserialize)]
pub(super) struct RulePatch {
    pub enabled: Option<bool>,
    #[serde(alias = "rolloutPercent")]
    pub rollout_percent: Option<u8>,
    #[serde(alias = "expectedVersion")]
    pub expected_version: Option<u32>,
}
#[derive(Debug, Deserialize)]
pub(super) struct RuleBody {
    pub yaml: String,
    #[serde(alias = "sourceKey")]
    pub source_key: Option<String>,
    #[serde(alias = "expectedVersion")]
    pub expected_version: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct RuleVersionGuard {
    #[serde(alias = "expectedVersion")]
    pub expected_version: Option<u32>,
}

fn check_version(previous: Option<&RuleDefinition>, expected: Option<u32>) -> DomainResult<()> {
    if expected.is_some_and(|version| previous.map_or(0, |rule| rule.version) != version) {
        return Err(DomainError::Conflict(
            "Rule changed since it was loaded; reload and compare before publishing / 规则已被修改，请重新加载并核对"
                .into(),
        ));
    }
    Ok(())
}

pub(super) async fn patch(
    State(state): State<AppState>,
    principal: Principal,
    Path(key): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RulePatch>,
) -> ApiResult<Json<serde_json::Value>> {
    let submission = Submission::capture(&state, &principal, &headers, Grant::Rules)?;
    let rule = crate::rule_store::publication::change(&state, &submission, &key, |previous| {
        check_version(previous.as_ref(), body.expected_version)?;
        let mut rule = previous.ok_or_else(|| DomainError::NotFound { entity: "rule", id: key.clone() })?;
        if let Some(enabled) = body.enabled {
            rule.enabled = enabled;
        }
        if let Some(rollout) = body.rollout_percent {
            rule.rollout_percent = rollout;
        }
        Ok(rule)
    })
    .await?;

    Ok(Json(serde_json::json!({"rule":rule})))
}

pub(super) async fn publish(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RuleBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let submission = Submission::capture(&state, &principal, &headers, Grant::Rules)?;
    if body.yaml.len() > 262_144 {
        return Err(DomainError::Validation("单条规则 YAML 不能超过 256 KiB".into()).into());
    }
    let definition: RuleDefinition =
        serde_yaml::from_str(&body.yaml).map_err(|e| DomainError::Validation(format!("规则 YAML 无效：{e}")))?;
    let key = definition.key.clone();
    if body.source_key.as_ref().is_some_and(|source| source != &key) {
        return Err(DomainError::Validation(
            "Keep the existing rule key unchanged; use New rule to create another / 编辑已有规则时不能修改 key".into(),
        )
        .into());
    }
    let rule = crate::rule_store::publication::change(&state, &submission, &key, |previous| {
        check_version(previous.as_ref(), body.expected_version)?;
        Ok(definition)
    })
    .await?;

    Ok(Json(serde_json::json!({"rule":rule})))
}

pub(super) async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(key): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    let current = crate::rule_store::get(&state, principal.tenant, &key).await?;
    let registry = crate::rule_store::registry(&state, principal.tenant).await?;
    let history = registry.entries.get(&key).cloned().unwrap_or_else(|| {
        vec![crate::rule_store::Revision { definition: current, changed_at: Timestamp::now(), actor: "builtin".into() }]
    });
    let items = history
        .iter()
        .map(|r| {
            Ok(serde_json::json!({"version":r.definition.version,"actor":r.actor,"changed_at":r.changed_at,
        "yaml":serde_yaml::to_string(&r.definition).map_err(|e|DomainError::Internal(e.to_string()))?}))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(serde_json::json!({"items":items})))
}

pub(super) async fn restore(
    State(state): State<AppState>,
    principal: Principal,
    Path((key, version)): Path<(String, u32)>,
    axum::extract::Query(guard): axum::extract::Query<RuleVersionGuard>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let submission = Submission::capture(&state, &principal, &headers, Grant::Rules)?;
    let registry = crate::rule_store::registry(&state, principal.tenant).await?;
    let definition = registry
        .entries
        .get(&key)
        .and_then(|h| h.iter().find(|r| r.definition.version == version))
        .map(|r| r.definition.clone())
        .ok_or_else(|| DomainError::NotFound { entity: "rule-version", id: version.to_string() })?;
    let rule = crate::rule_store::publication::change(&state, &submission, &key, |previous| {
        check_version(previous.as_ref(), guard.expected_version)?;
        Ok(definition)
    })
    .await?;

    Ok(Json(serde_json::json!({"rule":rule})))
}

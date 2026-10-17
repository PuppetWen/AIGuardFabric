//! 模型网关类控制台端点：模型路由策略与用量聚合。

use super::*;
use axum::http::HeaderMap;

// ===========================================================================
// A. 模型网关
// ===========================================================================

pub async fn list_route_policies(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "models", "read")?;
    let policies = crate::model_routes::list(&state, principal.tenant).await?;
    Ok(Json(serde_json::Value::Array(policies.iter().map(route_policy_json).collect())))
}

pub async fn save_route_policy(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let submission = crate::model_routes::publication::Submission::capture(&state, &principal, &headers)?;
    let policy_id = parse_id(&id, "model-route-policy")?;
    if policy_id.is_nil() {
        return Err(DomainError::Validation("模型路由 ID 不能为零 UUID".into()).into());
    }
    let existing = crate::model_routes::publication::current(&state, &submission, policy_id).await?;
    let mut policy = merge_route_policy(existing.clone(), policy_id, principal.tenant, &body)?;
    let requested = body.get("expectedVersion").or_else(|| body.get("expected_version"));
    let expected = match requested {
        Some(value) => {
            value.as_u64().ok_or_else(|| DomainError::Validation("expectedVersion 必须为非负整数".into()))?
        }
        None if existing.is_some() => {
            return Err(DomainError::Validation("编辑模型路由须提供 expectedVersion，请重新加载".into()).into());
        }
        None => 0,
    };
    if existing.as_ref().map_or(0, |row| row.version) != expected {
        return Err(DomainError::Conflict("模型路由已被其他人修改，请重新加载后合并变更".into()).into());
    }
    policy.version = expected.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?;
    Box::pin(crate::model_routes::publication::save(&state, &submission, &policy, expected)).await?;
    Ok(Json(route_policy_json(&policy)))
}

pub async fn list_usage(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "models", "read")?;
    let names = if principal.require(&state, "assets", "read").is_ok() {
        asset_names(&state, principal.tenant).await?
    } else {
        BTreeMap::new()
    };
    let records: Vec<serde_json::Value> = crate::gateway_quota::usage(&state, principal.tenant)
        .await?
        .iter()
        .filter(|record| record.tenant_id == principal.tenant)
        .map(|record| usage_record_json(record, &names))
        .collect();
    let page = query.paginate_vec(&records, |_| String::new(), |_| String::new());
    Ok(Json(query.render_page(&page)?))
}

pub async fn usage_aggregate(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "models", "read")?;
    let mut buckets: BTreeMap<(String, String, bool), UsageBucket> = BTreeMap::new();
    for record in crate::gateway_quota::usage(&state, principal.tenant).await? {
        if record.tenant_id != principal.tenant {
            continue;
        }
        let bucket = buckets
            .entry((record.endpoint_id.to_string(), record.model.clone(), record.mocked))
            .or_insert_with(|| UsageBucket::new(&record));
        bucket.input_tokens = bucket.input_tokens.saturating_add(record.prompt_tokens);
        bucket.output_tokens = bucket.output_tokens.saturating_add(record.completion_tokens);
        bucket.cost_micro = bucket.cost_micro.saturating_add(record.cost_micro);
        bucket.calls = bucket.calls.saturating_add(1);
    }
    Ok(Json(serde_json::Value::Array(buckets.into_values().map(UsageBucket::into_json).collect())))
}

pub async fn create_route_policy(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    save_route_policy(State(state), principal, Path(Id::new().to_string()), headers, ApiJson(body)).await
}

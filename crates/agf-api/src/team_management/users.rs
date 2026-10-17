//! Candidate pages never establish absence or administrator eligibility.
use super::{
    DIRECTORIES, cloud, context,
    contract::{Cursor, DirectoryState, UserDirectory, UserQuery},
    input::UsersInput,
    validation,
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn key(tenant: agf_core::ids::TenantId) -> Id {
    deterministic_id("agf.team-management.directory", &tenant.to_string())
}
pub(super) async fn observe(state: &AppState, principal: &Principal, input: UsersInput) -> DomainResult<Value> {
    let ctx = context::load(state, principal.tenant).await?;
    if ctx.scope.configuration_version != input.configuration_version {
        return Err(super::stale());
    }
    context::confirm(&ctx.scope, input.confirm_live)?;
    if input.request_id.is_nil() {
        return Err(DomainError::Validation("请求编号不能为nil".into()));
    }
    if input.name_like.as_ref().is_some_and(|s| s.len() > 256 || s.chars().any(char::is_control)) {
        return Err(DomainError::Validation("人员筛选文本无效".into()));
    }
    let id = key(principal.tenant);
    let current =
        state.configurations.get::<Option<DirectoryState>>(principal.tenant, DIRECTORIES, id).await?.flatten();
    let hash = validation::hash(&input)?;
    if let Some((prior, page)) = current.as_ref().and_then(|row| row.requests.get(&input.request_id)) {
        if prior != &hash {
            return Err(DomainError::Conflict("同一人员读取请求编号不能用于不同筛选、分页或配置".into()));
        }
        if let Some(page) = page {
            let mut page = page.clone();
            if page.observed_at.age_secs() >= 300
                || current.as_ref().is_none_or(|row| row.latest_request != input.request_id)
            {
                page.selection_usable = false;
                page.unusable_reason = Some("superseded".into());
            }
            return Ok(serde_json::to_value(page)?);
        }
        return Err(DomainError::Conflict("该候选读取请求已开始或失败，请提供新请求编号显式重新读取".into()));
    }
    let query = UserQuery { name_like: input.name_like.clone() };
    let previous = if let Some(cursor) = &input.cursor {
        Some(
            current
                .as_ref()
                .and_then(|directory| directory.cursors.get(cursor))
                .filter(|cursor| {
                    context::same_scope(&cursor.scope, &ctx.scope)
                        && cursor.query.name_like == query.name_like
                        && cursor.expires_at > Timestamp::now()
                })
                .cloned()
                .ok_or_else(|| DomainError::Conflict("候选分页游标失效，请重新读取首页；保留已选人员".into()))?,
        )
    } else {
        None
    };
    state
        .configurations
        .mutate::<Option<DirectoryState>, _>(principal.tenant, DIRECTORIES, id, |slot| {
            let row = slot.get_or_insert_with(|| DirectoryState {
                scope: ctx.scope.clone(),
                latest_request: input.request_id,
                latest: None,
                cursors: BTreeMap::new(),
                requests: BTreeMap::new(),
            });
            if !context::same_scope(&row.scope, &ctx.scope) {
                row.latest = None;
                row.cursors.clear();
                row.scope = ctx.scope.clone();
            }
            row.latest_request = input.request_id;
            if let Some((prior, _)) = row.requests.get(&input.request_id) {
                return Err(DomainError::Conflict(
                    if prior == &hash {
                        "该候选请求正在读取"
                    } else {
                        "同一候选读取编号不能用于不同内容"
                    }
                    .into(),
                ));
            }
            if row.requests.len() >= 2000 {
                return Err(DomainError::PreconditionFailed(
                    "候选读取回执达2000条上限，请联系管理员归档；旧回执保留".into(),
                ));
            }
            row.requests.insert(input.request_id, (hash.clone(), None));
            if let Some(page) = &mut row.latest {
                page.selection_usable = false;
                page.unusable_reason = Some("refresh-pending-or-failed".into());
            }
            bounded(row)
        })
        .await?;
    let mut params = json!({"MaxResults":100});
    if let Some(text) = &query.name_like {
        params["NameLike"] = json!(text);
    }
    if let Some(previous) = &previous {
        params["NextToken"] = json!(previous.next_token);
    }
    let body = cloud::call(
        state,
        principal,
        &ctx.scope,
        input.request_id,
        "directory",
        "ListUsers",
        params,
        input.confirm_live,
    )
    .await?;
    let items = body["Items"]
        .as_array()
        .filter(|items| items.len() <= 100)
        .ok_or_else(|| DomainError::Parse("用户列表Items必须为至多100条的数组".into()))?;
    let mut names = previous.as_ref().map(|row| row.names.clone()).unwrap_or_default();
    let mut users = Vec::new();
    for item in items {
        let user = validation::user(item, &ctx.scope.instance_id, None)?;
        if names.contains(&user.name) {
            return Err(DomainError::Parse("候选分页返回重复用户".into()));
        }
        names.push(user.name.clone());
        users.push(user);
    }
    let total = match body.get("TotalCount").filter(|v| !v.is_null()) {
        None => previous.as_ref().and_then(|row| row.total),
        Some(v) => Some(v.as_u64().ok_or_else(|| DomainError::Parse("用户TotalCount无效".into()))?),
    };
    if previous.as_ref().and_then(|row| row.total).is_some_and(|old| Some(old) != total)
        || total.is_some_and(|count| count < names.len() as u64)
    {
        return Err(DomainError::Parse("候选分页总数改变或错误".into()));
    }
    let next = match body.get("NextToken").filter(|v| !v.is_null()) {
        None => "",
        Some(v) => v.as_str().ok_or_else(|| DomainError::Parse("用户分页令牌无效".into()))?,
    };
    let mut tokens = previous.as_ref().map(|row| row.tokens.clone()).unwrap_or_default();
    if next.len() > 4096 || (!next.is_empty() && tokens.iter().any(|old| old == next)) {
        return Err(DomainError::Parse("用户分页令牌过大或重复".into()));
    }
    let complete = next.is_empty();
    if complete && total.is_some_and(|count| count != names.len() as u64) {
        return Err(DomainError::Parse("用户分页提前结束".into()));
    }
    let pages = previous.as_ref().map_or(1, |row| row.pages + 1);
    let capped = !complete && (pages >= 20 || names.len() >= 2000);
    let cursor = (!complete && !capped).then(|| Id::new().to_string());
    let directory = UserDirectory {
        snapshot_id: deterministic_id(
            "agf.team-management.directory-page",
            &format!("{}:{}", principal.tenant, input.request_id),
        ),
        configuration_version: ctx.scope.configuration_version,
        scope_id: ctx.scope.id,
        mocked: ctx.scope.mocked,
        instance_id: ctx.scope.instance_id.clone(),
        observed_at: Timestamp::now(),
        query: query.clone(),
        page_complete: true,
        complete,
        directory_complete: complete && query.name_like.is_none(),
        next_cursor: cursor.clone(),
        total_count: total,
        selection_usable: true,
        unusable_reason: capped.then(|| "page-limit".into()),
        items: users,
    };
    context::checked(state, principal, &ctx.scope, input.confirm_live).await?;
    state
        .configurations
        .mutate::<Option<DirectoryState>, _>(principal.tenant, DIRECTORIES, id, |slot| {
            let row = slot
                .as_mut()
                .filter(|row| row.latest_request == input.request_id && context::same_scope(&row.scope, &ctx.scope))
                .ok_or_else(super::stale)?;
            row.cursors.retain(|_, cursor| cursor.expires_at > Timestamp::now());
            if row.cursors.len() > 100 {
                return Err(DomainError::PreconditionFailed("候选分页过多，请稍后重新读取".into()));
            }
            if let Some(cursor) = &cursor {
                tokens.push(next.into());
                row.cursors.insert(
                    cursor.clone(),
                    Cursor {
                        scope: ctx.scope.clone(),
                        query: query.clone(),
                        next_token: next.into(),
                        total,
                        pages,
                        names,
                        tokens,
                        expires_at: Timestamp::now().offset_secs(300),
                    },
                );
            }
            row.latest = Some(directory.clone());
            row.requests.insert(input.request_id, (hash.clone(), Some(directory.clone())));
            bounded(row)
        })
        .await?;
    Ok(serde_json::to_value(directory)?)
}
fn bounded(row: &DirectoryState) -> DomainResult<()> {
    if serde_json::to_vec(row)?.len() > 1_900_000 {
        return Err(DomainError::PreconditionFailed("候选目录回执超过容量上限，请联系管理员归档".into()));
    }
    Ok(())
}
pub(super) async fn validate_snapshot(
    state: &AppState,
    principal: &Principal,
    scope: &super::contract::Scope,
    id: Id,
) -> DomainResult<()> {
    let row = state
        .configurations
        .get::<Option<DirectoryState>>(principal.tenant, DIRECTORIES, key(principal.tenant))
        .await?
        .flatten();
    if !row.is_some_and(|row| {
        context::same_scope(&row.scope, scope)
            && row.latest.is_some_and(|page| {
                page.snapshot_id == id
                    && page.snapshot_id
                        == deterministic_id(
                            "agf.team-management.directory-page",
                            &format!("{}:{}", principal.tenant, row.latest_request),
                        )
                    && page.selection_usable
                    && page.observed_at.age_secs() < 300
            })
    }) {
        return Err(DomainError::PreconditionFailed("人员候选快照失效，请重新读取；已选名单仍可保留".into()));
    }
    Ok(())
}

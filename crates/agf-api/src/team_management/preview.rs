use super::{
    cloud, context,
    contract::Preview,
    input::{Change, PreviewInput},
    projection, store, users, validation,
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) async fn create(state: &AppState, principal: &Principal, input: PreviewInput) -> DomainResult<Value> {
    validation::change(&input.change)?;
    if input.request_id.is_nil() {
        return Err(DomainError::Validation("请求编号不能为nil".into()));
    }
    let hash = validation::hash(&input)?;
    let id = deterministic_id("agf.team-management.preview", &format!("{}:{}", principal.tenant, input.request_id));
    match store::preview(state, principal.tenant, id).await {
        Ok(existing) => {
            if existing.request_hash != hash {
                return Err(DomainError::Conflict("同一请求编号不能用于不同预览".into()));
            }
            return get(state, principal, id).await;
        }
        Err(DomainError::NotFound { .. }) => {}
        Err(error) => return Err(error),
    }
    let ctx = context::load(state, principal.tenant).await?;
    if ctx.scope.configuration_version != input.configuration_version {
        return Err(super::stale());
    }
    context::confirm(&ctx.scope, input.confirm_live)?;
    let record_id = context::record_id(principal.tenant, &ctx.scope, input.change.team())?;
    let row = store::get(state, principal.tenant, record_id).await?;
    if row.version != input.expected_state_version {
        return Err(super::stale());
    }
    store::idle(&row)?;
    if row.unresolved_delete.is_some() {
        return Err(DomainError::PreconditionFailed("该团队删除结果待确认，只能观察原回执，不可重新写入".into()));
    }
    let baseline = cloud::team(
        state,
        principal,
        &ctx.scope,
        input.request_id,
        "preview-team",
        input.change.team(),
        input.confirm_live,
    )
    .await?;
    if matches!(input.change, Change::Create { .. }) {
        let teams = cloud::pages(
            state,
            principal,
            &ctx.scope,
            input.request_id,
            "preview-teams",
            "ListTeams",
            json!({}),
            input.confirm_live,
        )
        .await?;
        if teams.iter().any(|team| team["Name"] == input.change.team()) || baseline.is_some() {
            return Err(DomainError::Conflict("团队已存在，不能按新建覆盖".into()));
        }
    } else {
        let observed =
            baseline.as_ref().ok_or_else(|| DomainError::PreconditionFailed("目标团队不存在，请重新盘点".into()))?;
        if observed.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("deleting")) {
            return Err(DomainError::PreconditionFailed("团队正在删除，只能观察".into()));
        }
        if input.change.members().is_some() && observed.member_names.is_none() {
            return Err(DomainError::PreconditionFailed("云端未提供完整TeamMembers，禁止全量替换".into()));
        }
    }
    let mut selected = input.change.members().unwrap_or_default().to_vec();
    if let Some(admin) = input.change.admin() {
        selected.push(admin.into());
    }
    if !selected.is_empty() {
        let snapshot = input
            .user_snapshot_id
            .ok_or_else(|| DomainError::PreconditionFailed("人员变更须先读取候选目录并提供user_snapshot_id".into()))?;
        users::validate_snapshot(state, principal, &ctx.scope, snapshot).await?;
    }
    let verified =
        cloud::users(state, principal, &ctx.scope, input.request_id, "preview-users", &selected, input.confirm_live)
            .await?;
    let task_count = if matches!(input.change, Change::Delete { .. }) {
        let observed = baseline.as_ref().ok_or_else(super::stale)?;
        if observed.member_names.is_none() || observed.worker_names.is_none() || observed.rooms.is_none() {
            return Err(DomainError::PreconditionFailed("删除影响不完整：云端须明确人员、Worker和Rooms名单".into()));
        }
        Some(
            cloud::pages(
                state,
                principal,
                &ctx.scope,
                input.request_id,
                "preview-tasks",
                "ListTeamTasks",
                json!({"Team":input.change.team()}),
                input.confirm_live,
            )
            .await?
            .len(),
        )
    } else {
        None
    };
    context::checked(state, principal, &ctx.scope, input.confirm_live).await?;
    let preview = Preview {
        id,
        record_id,
        request_id: input.request_id,
        request_hash: hash,
        scope: ctx.scope.clone(),
        state_version: row.version,
        change: input.change.clone(),
        baseline_hash: validation::hash(&baseline)?,
        baseline,
        observed_at: Timestamp::now(),
        expires_at: Timestamp::now().offset_secs(300),
        consumed_at: None,
        verified_users: verified,
        task_count,
        actor: principal.display(),
    };
    store::modify(
        state,
        principal,
        &ctx.scope,
        input.change.team(),
        "生成团队变更预览；未发送云写入",
        |row| {
            store::idle(row)?;
            if row.version != input.expected_state_version || row.unresolved_delete.is_some() {
                return Err(super::stale());
            }
            if let Some(existing) = row.previews.get(&id) {
                if existing.request_hash != preview.request_hash {
                    return Err(super::stale());
                }
                return Ok(());
            }
            row.previews.insert(id, preview.clone());
            Ok(())
        },
    )
    .await?;
    get(state, principal, id).await
}
pub(super) async fn get(state: &AppState, principal: &Principal, id: Id) -> DomainResult<Value> {
    let preview = store::preview(state, principal.tenant, id).await?;
    let row = store::get(state, principal.tenant, preview.record_id).await?;
    let current = context::available(state, principal.tenant).await?;
    Ok(projection::preview(&preview, &row, current.as_ref().map(|ctx| &ctx.scope)))
}

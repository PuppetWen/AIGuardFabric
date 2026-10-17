//! 白标与网关配额设置：持久化成功后才响应，租户由认证主体决定。
use super::*;
use crate::{
    gateway_quota::{Limits, QUOTAS},
    model_routes::tenant_record_id,
    routes::ApiJson,
};
use serde::de::DeserializeOwned;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TenantUpdate {
    expected_version: Option<u64>,
    name: String,
    plan: String,
    region: String,
    white_label: BrandingUpdate,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrandingUpdate {
    product_name: String,
    logo_text: String,
    primary_color: String,
}

pub(super) async fn tenant(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<TenantUpdate>,
) -> ApiResult<Json<TenantView>> {
    principal.require(&state, "settings", "write")?;
    if body.name.trim().is_empty()
        || body.name.len() > 128
        || body.white_label.product_name.trim().is_empty()
        || body.white_label.product_name.len() > 128
        || body.white_label.logo_text.chars().count() > 8
        || body.region.len() > 64
        || !["community", "standard", "enterprise"].contains(&body.plan.as_str())
    {
        return Err(DomainError::Validation("租户名称、套餐或品牌配置不合法".into()).into());
    }
    let color = &body.white_label.primary_color;
    if color.len() != 7 || !color.starts_with('#') || !color[1..].bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(DomainError::Validation("主题色必须为 #RRGGBB".into()).into());
    }
    let key = tenant_record_id(principal.tenant);
    let previous: Option<TenantView> = state.configurations.get(principal.tenant, "tenant-profile", key).await?;
    let expected = match (previous.as_ref(), body.expected_version) {
        (Some(_), None) => {
            return Err(DomainError::Validation("编辑企业资料须提供 expectedVersion，请重新加载".into()).into());
        }
        (None, None) => 0,
        (_, Some(version)) => version,
    };
    if previous.as_ref().map_or(0, |profile| profile.version) != expected {
        return Err(DomainError::Conflict("企业资料已被其他人修改，请重新加载后合并变更".into()).into());
    }
    let mut profile = current(&state, principal.tenant).await?;
    profile.version = expected.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?;
    profile.name = body.name.trim().into();
    profile.plan = body.plan;
    profile.region = body.region;
    profile.white_label.product_name = body.white_label.product_name.trim().into();
    profile.white_label.logo_text = body.white_label.logo_text;
    profile.white_label.primary_color = body.white_label.primary_color;
    audited_change::<Option<TenantView>, _>(
        &state,
        &principal,
        "tenant-profile",
        key,
        "保存租户与白标配置",
        |slot| {
            if slot.as_ref().map_or(0, |row| row.version) != expected {
                return Err(DomainError::Conflict("企业资料已被其他人修改，请重新加载后合并变更".into()));
            }
            *slot = Some(profile.clone());
            Ok(())
        },
    )
    .await?;
    Ok(Json(profile))
}

pub(super) async fn current(state: &AppState, tenant: TenantId) -> ApiResult<TenantView> {
    let entry = crate::tenant_directory::get(state, tenant).await?;
    let quotas = state.store.quota_list(tenant)?;
    let mut view =
        state.configurations.get(tenant, "tenant-profile", tenant_record_id(tenant)).await?.unwrap_or_else(|| {
            let mut view = super::identity::tenant_view(state, tenant, &quotas);
            view.name = entry.name.clone();
            view
        });
    view.directory_name = entry.name;
    view.slug = entry.slug;
    view.enabled = entry.enabled;
    view.directory_version = entry.version;
    view.created_at = entry.created_at.to_rfc3339();
    if let Some(limits) = state.configurations.get::<Limits>(tenant, QUOTAS, tenant_record_id(tenant)).await? {
        view.quota_defaults = QuotaDefaultsView {
            version: limits.version,
            tenant_tokens_per_day: i64::try_from(limits.tenant_tokens_per_day).unwrap_or(i64::MAX),
            agent_tokens_per_hour: i64::try_from(limits.agent_tokens_per_hour).unwrap_or(i64::MAX),
            session_tokens_per_turn: i64::try_from(limits.session_tokens_per_turn).unwrap_or(i64::MAX),
            max_concurrent_sessions: i64::try_from(limits.max_concurrent_sessions).unwrap_or(i64::MAX),
        };
    }
    Ok(view)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct QuotaUpdate {
    expected_version: Option<u64>,
    tenant_tokens_per_day: u64,
    agent_tokens_per_hour: u64,
    session_tokens_per_turn: u64,
    max_concurrent_sessions: u64,
}

pub(super) async fn quotas(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<QuotaUpdate>,
) -> ApiResult<Json<Limits>> {
    principal.require(&state, "quotas", "write")?;
    let values = [
        body.tenant_tokens_per_day,
        body.agent_tokens_per_hour,
        body.session_tokens_per_turn,
        body.max_concurrent_sessions,
    ];
    if values.iter().any(|v| *v > 1_000_000_000_000) || body.max_concurrent_sessions == 0 {
        return Err(DomainError::Validation("配额需为有效非负整数，并发上限至少为 1".into()).into());
    }
    let key = tenant_record_id(principal.tenant);
    let previous: Option<Limits> = state.configurations.get(principal.tenant, QUOTAS, key).await?;
    let expected = match (previous.as_ref(), body.expected_version) {
        (Some(_), None) => {
            return Err(DomainError::Validation("编辑网关配额须提供 expectedVersion，请重新加载".into()).into());
        }
        (None, None) => 0,
        (_, Some(version)) => version,
    };
    if previous.as_ref().map_or(0, |limits| limits.version) != expected {
        return Err(DomainError::Conflict("网关配额已被其他人修改，请重新加载后合并变更".into()).into());
    }
    let limits = Limits {
        version: expected.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?,
        tenant_tokens_per_day: body.tenant_tokens_per_day,
        agent_tokens_per_hour: body.agent_tokens_per_hour,
        session_tokens_per_turn: body.session_tokens_per_turn,
        max_concurrent_sessions: body.max_concurrent_sessions,
    };
    audited_change::<Limits, _>(
        &state,
        &principal,
        QUOTAS,
        key,
        "保存网关配额；下一请求按新配额预留，0 token 配额表示不限",
        |current| {
            if current.version != expected {
                return Err(DomainError::Conflict("网关配额已被其他人修改，请重新加载后合并变更".into()));
            }
            *current = limits.clone();
            Ok(())
        },
    )
    .await?;
    Ok(Json(limits))
}

async fn audited_change<T, F>(
    state: &AppState,
    principal: &Principal,
    kind: &str,
    key: Id,
    note: &str,
    apply: F,
) -> ApiResult<T>
where
    T: Serialize + DeserializeOwned + Default,
    F: FnOnce(&mut T) -> agf_core::error::DomainResult<()> + Send,
{
    let entry = AppState::audit_entry(
        principal.tenant,
        agf_core::audit::AuditAction::Configure,
        agf_core::audit::AuditOutcome::Success,
        AppState::audit_actor(principal, "settings"),
        agf_core::audit::AuditTarget::new("tenant-settings", Some(principal.tenant.to_string()), None),
        note,
    );
    let (value, sealed) =
        state.configurations.mutate_audited(principal.tenant, kind, key, entry.clone(), apply).await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的租户设置审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(value)
}

#[derive(Deserialize)]
pub(super) struct PasswordPolicyUpdate {
    #[serde(default)]
    expected_version: Option<u64>,
    #[serde(flatten)]
    view: PasswordPolicyView,
}

pub(super) async fn password(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<PasswordPolicyUpdate>,
) -> ApiResult<Json<PasswordPolicyView>> {
    principal.require(&state, "settings", "write")?;
    let mut view = body.view;
    if !(8..=128).contains(&view.min_length)
        || !(0..=365).contains(&view.max_age_days)
        || !(0..=24).contains(&view.history_size)
        || !(1..=20).contains(&view.lockout_threshold)
    {
        return Err(DomainError::Validation("口令策略参数超出允许范围".into()).into());
    }
    if view.mfa_enforced {
        crate::model_gateway::cipher(&state)?;
        let id =
            principal.subject_id.ok_or_else(|| DomainError::Forbidden("请以已绑定 MFA 的管理员身份操作".into()))?;
        if !state.auth_backend.find_user(principal.tenant, id).await?.is_some_and(|user| user.mfa_enabled) {
            return Err(DomainError::PreconditionFailed(
                "请先在账号安全页面为当前管理员绑定 MFA，再开启租户强制 MFA".into(),
            )
            .into());
        }
    }
    let key = tenant_record_id(principal.tenant);
    let previous: Option<crate::auth_policy::TenantPolicy> =
        state.configurations.get(principal.tenant, crate::auth_policy::KIND, key).await?;
    let expected = match (previous.as_ref(), body.expected_version) {
        (Some(_), None) => {
            return Err(DomainError::Validation("编辑口令策略须提供 expected_version，请重新加载".into()).into());
        }
        (None, None) => 0,
        (_, Some(version)) => version,
    };
    if previous.as_ref().map_or(0, |policy| policy.view.version) != expected {
        return Err(DomainError::Conflict("口令策略已被其他人修改，请重新加载后合并变更".into()).into());
    }
    view.version = expected.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?;
    let record = crate::auth_policy::TenantPolicy { require_classes: view.require_classes, view: view.clone() };
    audited_change::<Option<crate::auth_policy::TenantPolicy>, _>(
        &state,
        &principal,
        crate::auth_policy::KIND,
        key,
        "保存租户口令与 MFA 策略",
        |current| {
            if current.as_ref().map_or(0, |policy| policy.view.version) != expected {
                return Err(DomainError::Conflict("口令策略已被其他人修改，请重新加载后合并变更".into()));
            }
            *current = Some(record.clone());
            Ok(())
        },
    )
    .await?;
    Ok(Json(view))
}

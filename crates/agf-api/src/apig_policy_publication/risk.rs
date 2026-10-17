//! Only an unconfirmed write creates overlap risk. A known acceptance with missing readback does not.
//! Expiring a local lease cannot stop an already delivered request whose result remains unknown.
use super::{
    records::{Main, Observation, Risk, STATE},
    util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};

pub(super) async fn load(state: &AppState, tenant: TenantId, scope: Id) -> DomainResult<Option<Risk>> {
    let risk = state.configurations.get::<Risk>(tenant, STATE, util::risk_id(tenant, scope)).await?;
    if let Some(risk) = &risk {
        if (risk.tenant, risk.scope_id) != (tenant, scope) || risk.latest_unknown.is_nil() || risk.unknown_count == 0 {
            return Err(util::corrupt());
        }
    }
    Ok(risk)
}
pub(super) fn preview(
    main: &Main,
    risk: Option<&Risk>,
    observation: &Observation,
    ack: Option<Id>,
) -> DomainResult<()> {
    if let Some(active) = &main.active {
        return Err(if active.expires_at > Timestamp::now() {
            DomainError::Conflict("目标仍有有效领取；请先等待并读取原操作回执".into())
        } else {
            DomainError::PreconditionFailed(
                "旧started领取已过期但尚无已发布终态；请先显式recover_local记录未知事实，再新观察和新预览".into(),
            )
        });
    }
    if let Some(risk) = risk {
        if Timestamp::now() <= risk.lease_expires_at
            || ack != Some(risk.latest_unknown)
            || observation.started_at <= risk.lease_expires_at
            || observation.observed_at <= risk.lease_expires_at
        {
            return Err(DomainError::PreconditionFailed(
                "旧请求结果永久未知；须在旧租约之后开始并完成新观察，明确承认该原编号，再创建独立新意图".into(),
            ));
        }
    } else if ack.is_some() {
        return Err(DomainError::Validation("此目标没有对应的未知风险编号；不会转用其它范围的确认".into()));
    }
    Ok(())
}

//! A cloud write is explicit and never retried after an uncertain receipt.
use super::{
    cloud, context,
    context::Resolved,
    contract::{Observation, Operation, SyncInput},
    operations,
};
use crate::{Principal, state::AppState};
use agf_core::{error::DomainError, ids::deterministic_id};

pub(super) async fn execute(
    state: &AppState,
    principal: &Principal,
    resolved: &Resolved,
    input: &SyncInput,
    preview: &Observation,
    run: &mut Operation,
) {
    let before = match cloud::read(state, principal, resolved, input.request_id, "before", input.confirm_live).await {
        Ok((limit, _)) => limit,
        Err(_) => {
            fail(run, "failed", "写入前未能核对云限制；没有下发本次配额更新");
            return;
        }
    };
    if !context::same_config(&before, &preview.cloud) {
        fail(run, "failed", "云限制已与确认预览不同；请重新观察并明确确认");
        return;
    }
    let checked = operations::verified(
        state,
        principal,
        resolved.asset,
        input.expected_binding_version,
        input.expected_quota_version,
        input.configuration_version,
    )
    .await;
    match checked {
        Ok((binding, current))
            if binding.active.as_ref().is_some_and(|active| {
                active.run_id == run.id && active.expires_at > agf_core::time::Timestamp::now()
            }) && current.cloud.scope_id == resolved.cloud.scope_id
                && current.worker == resolved.worker => {}
        Ok(_) => {
            fail(run, "superseded", "Worker 身份或当前同步操作已改变；本次未下发更新");
            return;
        }
        Err(error) => {
            fail(run, classification(&error), "写入前无法确认绑定和规则；本次未下发更新");
            return;
        }
    }
    let wanted = resolved.quota.quota.limit;
    let write = before.usage_limit != wanted;
    if write {
        let guard = super::write_guard::WriteGuard { state, principal, asset: resolved.asset, run: run.id, input };
        let receipt = cloud::write(state, principal, resolved, cloud::Write { previous: &before, wanted, guard }).await;
        match receipt {
            Ok(receipt) if receipt["status"] == "succeeded" => run.changed = true,
            Ok(receipt) if receipt["status"] == "failed" => {
                fail(run, "failed", "云写入回执失败；请检查回执并重新观察，不自动重试");
                return;
            }
            Ok(_) | Err(_) => {
                fail(run, "uncertain", "云写入结果未确认；请重新观察实际限制，禁止重放本次写入");
                return;
            }
        }
    }
    let after = match cloud::read(state, principal, resolved, input.request_id, "after", input.confirm_live).await {
        Ok(value) => value,
        Err(_) => {
            fail(run, if write { "uncertain" } else { "failed" }, "最终云回读未完成；不能证明限制已生效，请重新观察");
            return;
        }
    };
    if after.0.usage_limit != wanted || after.0.limit_type != "token" || after.0.period_type != "day" {
        fail(run, if write { "uncertain" } else { "failed" }, "最终云限制与平台期望不符；请重新观察，不自动重试");
        return;
    }
    run.status = "verified".into();
    run.observation = Some(Observation {
        id: deterministic_id("agf.worker-quota.readback", &run.id.to_string()),
        observed_at: after.1,
        quota_version: input.expected_quota_version,
        cloud_version: input.configuration_version,
        binding_version: input.expected_binding_version,
        mocked: resolved.cloud.snapshot.mocked,
        preview_usable: false,
        cloud: after.0,
    });
}

pub(super) fn classification(error: &DomainError) -> &'static str {
    if matches!(
        error,
        DomainError::Conflict(_)
            | DomainError::PreconditionFailed(_)
            | DomainError::NotFound { .. }
            | DomainError::Forbidden(_)
            | DomainError::TenantViolation { .. }
    ) {
        "superseded"
    } else {
        "uncertain"
    }
}

fn fail(run: &mut Operation, status: &str, message: &str) {
    run.status = status.into();
    run.error = Some(message.into());
}

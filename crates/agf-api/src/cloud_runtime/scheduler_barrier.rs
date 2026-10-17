//! Generic receipts cannot authorize Scheduler management or immediate execution.
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};

pub(super) fn validate(service: AliCloudService, action: &str) -> DomainResult<()> {
    if service == AliCloudService::SchedulerX3
        && matches!(
            action,
            "CreateJob" | "UpdateJob" | "OperateEnableJobs" | "OperateDisableJobs" | "DeleteJobs" | "OperateExecuteJob"
        )
    {
        return Err(DomainError::PreconditionFailed(
            "创建、日历修改、启停须使用 Scheduler 受管任务入口的观察、预览和原回执；平台尚未提供受管删除或立即执行，请在云控制台明确操作并重新观察，勿从通用云操作重发".into(),
        ));
    }
    Ok(())
}

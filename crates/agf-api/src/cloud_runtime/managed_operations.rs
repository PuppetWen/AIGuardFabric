//! Generic menus and dispatch cannot expose a managed write bypass.
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
pub(crate) fn generic_operation_visible(service: AliCloudService, action: &str, read_only: bool) -> bool {
    match service {
        AliCloudService::Apig => read_only,
        AliCloudService::SchedulerX3 => !matches!(
            action,
            "GetApp"
                | "CreateJob"
                | "UpdateJob"
                | "OperateEnableJobs"
                | "OperateDisableJobs"
                | "DeleteJobs"
                | "OperateExecuteJob"
        ),
        AliCloudService::Privatelink => !matches!(action, "CreateVpcEndpoint" | "EnableVpcEndpointConnection"),
        _ => true,
    }
}
pub(super) fn validate_privatelink(service: AliCloudService, action: &str) -> DomainResult<()> {
    if service == AliCloudService::Privatelink && matches!(action, "CreateVpcEndpoint" | "EnableVpcEndpointConnection")
    {
        return Err(DomainError::PreconditionFailed(
            "PrivateLink创建与接纳必须使用可信资源选择、预览和原UUID永久领取的专用入口；通用操作不会派发这些写入"
                .into(),
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn menus_exclude_managed_writes_but_preserve_registered_safe_reads() {
        for action in [
            "CreateJob",
            "UpdateJob",
            "OperateEnableJobs",
            "OperateDisableJobs",
            "DeleteJobs",
            "OperateExecuteJob",
            "GetApp",
        ] {
            assert!(!generic_operation_visible(AliCloudService::SchedulerX3, action, false));
        }
        for action in ["CreateVpcEndpoint", "EnableVpcEndpointConnection"] {
            assert!(!generic_operation_visible(AliCloudService::Privatelink, action, false));
            assert!(validate_privatelink(AliCloudService::Privatelink, action).is_err());
        }
        for action in ["GetPolicy", "GetPluginAttachment"] {
            assert!(generic_operation_visible(AliCloudService::Apig, action, true));
            assert!(!generic_operation_visible(AliCloudService::Apig, action, false));
        }
        for action in ["ListJobs", "GetJob", "GetJobExecution"] {
            assert!(generic_operation_visible(AliCloudService::SchedulerX3, action, true));
        }
        assert!(generic_operation_visible(AliCloudService::Privatelink, "ListVpcEndpoints", true));
        assert!(validate_privatelink(AliCloudService::Privatelink, "ListVpcEndpoints").is_ok());
    }
}

//! 主机身份只能分配给部署端显式登记的租户，租户配置不能选择任意主机文件。
use crate::{cloud_store as config, integration_store::Private};
use agf_alicloud::credential::{CloudCredential, sts_async::assume_role, workload};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};

pub fn is_workload(private: &Private) -> bool {
    matches!(config::setting(private, "credential_source", "access-key"), "ecs-role" | "oidc-role")
}
pub fn tenant_allowed(tenant: TenantId, allowlist: &str) -> bool {
    allowlist.split(',').filter_map(|id| TenantId::parse(id.trim()).ok()).any(|id| id == tenant)
}
pub fn validate(tenant: TenantId, private: &Private) -> DomainResult<()> {
    if !is_workload(private) {
        config::source(private)?;
        config::role(private)?;
        return Ok(());
    }
    if !tenant_allowed(tenant, &std::env::var("AGF_CLOUD_WORKLOAD_TENANTS").unwrap_or_default()) {
        return Err(DomainError::Forbidden(
            "此租户未获部署端授权使用主机身份；请登记 AGF_CLOUD_WORKLOAD_TENANTS".into(),
        ));
    }
    if config::setting(private, "credential_source", "") == "oidc-role" {
        config::role(private)?;
        if config::setting(private, "oidc_provider_arn", "").is_empty()
            && std::env::var("ALIBABA_CLOUD_OIDC_PROVIDER_ARN").unwrap_or_default().is_empty()
        {
            return Err(DomainError::Config("请配置 OIDC Provider ARN".into()));
        }
        if std::env::var("ALIBABA_CLOUD_OIDC_TOKEN_FILE").unwrap_or_default().is_empty() {
            return Err(DomainError::Config("部署端未挂载 ALIBABA_CLOUD_OIDC_TOKEN_FILE".into()));
        }
    }
    Ok(())
}
pub async fn resolve(tenant: TenantId, private: &Private) -> DomainResult<CloudCredential> {
    validate(tenant, private)?;
    match config::setting(private, "credential_source", "access-key") {
        "ecs-role" => {
            workload::ecs_role(workload::ECS_METADATA, Some(config::setting(private, "ecs_role_name", "")), false).await
        }
        "oidc-role" => {
            let token_path = std::env::var("ALIBABA_CLOUD_OIDC_TOKEN_FILE")
                .map_err(|_| DomainError::Config("未挂载 OIDC Token".into()))?;
            let token = workload::token_file(std::path::Path::new(&token_path)).await?;
            let provider = std::env::var("ALIBABA_CLOUD_OIDC_PROVIDER_ARN").unwrap_or_default();
            let role = config::role(private)?.ok_or_else(|| DomainError::Config("缺少 OIDC 角色配置".into()))?;
            workload::oidc_role(
                config::setting(private, "sts_endpoint", "https://sts.aliyuncs.com"),
                &role,
                config::setting(private, "oidc_provider_arn", &provider),
                &token,
                false,
            )
            .await
        }
        _ => {
            let source = config::source(private)?;
            if let Some(role) = config::role(private)? {
                Ok(assume_role(
                    config::setting(private, "sts_endpoint", "https://sts.aliyuncs.com"),
                    source,
                    &role,
                    false,
                )
                .await?
                .credential)
            } else {
                Ok(source)
            }
        }
    }
}

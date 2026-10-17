//! Generic writes cannot bypass reviewed APIG intents, source fences or Unknown resource risk.
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};

pub(super) fn validate(service: AliCloudService, read_only: bool) -> DomainResult<()> {
    if service == AliCloudService::Apig && !read_only {
        return Err(DomainError::PreconditionFailed(
            "APIG管理写入必须使用受管配额策略/内容与模型配置入口；安装插件、创建挂载以及发布、删除、执行等未支持操作请在云控制台明确完成后重新观察。通用操作不会派发这些写入".into(),
        ));
    }
    Ok(())
}

//! 由 `settings.rs` 拆分：`validate_endpoint` 函数（纯搬移，逻辑不变）。
use super::*;

/// 校验 endpoint 文本（scheme 白名单 + 必须有 host）。
///
/// # Errors
/// URL 不可解析 / scheme 不在白名单 / 缺 host 时返回 `DomainError::Config`。
pub fn validate_endpoint(endpoint: &str) -> DomainResult<()> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Config("endpoint 不能为空".to_string()));
    }
    let url = Url::parse(trimmed).map_err(|e| DomainError::Config(format!("endpoint URL 非法: {e}")))?;
    if !ALLOWED_SCHEMES.contains(&url.scheme()) {
        return Err(DomainError::Config(format!(
            "endpoint scheme 不受支持: {}（允许 {ALLOWED_SCHEMES:?}）",
            url.scheme()
        )));
    }
    if url.host_str().is_none() {
        return Err(DomainError::Config(format!("endpoint 缺少主机: {trimmed}")));
    }
    Ok(())
}

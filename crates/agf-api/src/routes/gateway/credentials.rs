use agf_aigw::provider::AwsCredentials;
use agf_core::error::{DomainError, DomainResult};

/// Bedrock 凭据由租户单独加密保存，禁止回落到服务器的其它租户凭据。
pub(crate) fn aws(raw: &str) -> DomainResult<AwsCredentials> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| DomainError::Validation("Bedrock 凭据必须是 JSON 对象".into()))?;
    let read = |field: &str| value[field].as_str().filter(|s| !s.trim().is_empty()).map(str::to_string);
    Ok(AwsCredentials {
        access_key_id: read("access_key_id").ok_or_else(|| DomainError::Validation("缺少 access_key_id".into()))?,
        secret_access_key: read("secret_access_key")
            .ok_or_else(|| DomainError::Validation("缺少 secret_access_key".into()))?,
        session_token: read("session_token"),
    })
}

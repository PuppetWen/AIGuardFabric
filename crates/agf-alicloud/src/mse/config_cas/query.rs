use super::client::{Envelope, WireResponse, check_deadline, normal_response, single_header};
use super::*;
use md5::{Digest, Md5};
use reqwest::Method;
use tokio::time::Instant;

impl NacosConfigClient {
    /// Query one exact unencrypted, normal configuration using the fixed v2 protocol.
    /// # Errors
    /// Invalid identity, credentials, guard, timeout, unavailable response or unverified content.
    pub async fn query(&self, key: &ConfigKey, guard: &dyn NacosSendGuard) -> DomainResult<ConfigObservation> {
        key.validate()?;
        let deadline = Instant::now() + self.limits.timeout;
        tokio::time::timeout_at(deadline, Box::pin(self.query_inner(key, guard, deadline)))
            .await
            .map_err(|_| DomainError::Timeout("Nacos query call deadline expired".into()))?
    }
    async fn query_inner(
        &self,
        key: &ConfigKey,
        guard: &dyn NacosSendGuard,
        deadline: Instant,
    ) -> DomainResult<ConfigObservation> {
        let headers = self.prepare(key, guard, deadline).await?;
        let request = self.request(Method::GET, headers).query(&key.pairs());
        check_deadline(deadline)?;
        let response = Box::pin(request.send()).await.map_err(|_| unavailable())?;
        let wire = self.read(response).await.map_err(|_| unavailable())?;
        check_deadline(deadline)?;
        let observed = parse(key, wire, self.limits.max_content_bytes)?;
        check_deadline(deadline)?;
        Ok(observed)
    }
}
fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "mse.nacos.http-v2".into(),
        cause: "Nacos query response unavailable".into(),
    }
}
/// Compute the lowercase Nacos content MD5 of exact UTF-8 bytes, including empty content.
///
/// This digest supports content comparison; it is not an authentication signature.
#[must_use]
pub fn content_md5(content: &str) -> String {
    hex::encode(Md5::digest(content.as_bytes()))
}
pub(super) fn valid_md5(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
pub(super) fn parse(key: &ConfigKey, wire: WireResponse, max_content: usize) -> DomainResult<ConfigObservation> {
    normal_response(&wire.headers)?;
    let body: Envelope = serde_json::from_slice(&wire.body)
        .map_err(|_| DomainError::Parse("Nacos v2 query did not return a valid JSON envelope".into()))?;
    if body.code != 0 && !(body.data.is_null() || body.data.is_string()) {
        return Err(DomainError::Parse("Nacos v2 query returned an invalid error envelope".into()));
    }
    if wire.status == 404 && body.code == 20004 {
        return Err(DomainError::NotFound { entity: "nacos-config", id: key.data_id.clone() });
    }
    if wire.status == 403 && body.code == 10001 {
        return Err(DomainError::Forbidden("Nacos configuration read denied".into()));
    }
    if wire.status != 200 || body.code != 0 {
        return Err(unavailable());
    }
    let content = body.data.as_str().ok_or_else(|| DomainError::Parse("Nacos v2 data must be content text".into()))?;
    if content.len() > max_content {
        return Err(DomainError::Parse("Nacos configuration content exceeds its byte bound".into()));
    }
    let md5 = single_header(&wire.headers, "Content-MD5")?
        .filter(|value| valid_md5(value))
        .ok_or_else(|| DomainError::Parse("Nacos query lacks a valid Content-MD5".into()))?
        .to_ascii_lowercase();
    if md5 != content_md5(content) {
        return Err(DomainError::Parse("Nacos Content-MD5 does not match the exact UTF-8 content".into()));
    }
    Ok(ConfigObservation { key: key.clone(), content: content.into(), md5, observed_at: Timestamp::now() })
}

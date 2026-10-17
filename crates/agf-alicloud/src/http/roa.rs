//! ACS3 signatures for APIs whose resource path/body are part of the request contract.
use super::*;

/// Structured ROA request. The path is already percent-encoded; query values are raw.
#[derive(Debug)]
pub struct RoaCall<'a> {
    pub action: &'a str,
    pub version: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub params: &'a [(String, String)],
    pub body: &'a str,
}
impl RpcClient {
    pub fn build_roa(&self, call: &RoaCall<'_>) -> DomainResult<RpcRequest> {
        if self.credential.is_expired(Timestamp::now()) {
            return Err(DomainError::Forbidden("云临时凭据已过期，请刷新后重试".into()));
        }
        if !call.path.starts_with('/') || call.path.starts_with("//") || call.path.contains(['?', '#', '\\']) {
            return Err(DomainError::Validation("ROA 路径必须是已编码的绝对资源路径，查询参数请单独提供".into()));
        }
        let query = canonicalized_query(call.params);
        let mut headers = BTreeMap::from([
            ("x-acs-action".into(), call.action.into()),
            ("x-acs-version".into(), call.version.into()),
            ("x-acs-date".into(), self.timestamp_string()),
            ("x-acs-signature-nonce".into(), self.nonce()),
        ]);
        if let Some(token) = &self.credential.security_token {
            headers.insert("x-acs-security-token".into(), token.clone());
        }
        let signed = sign_v3(&V3SignInput {
            method: call.method,
            canonical_uri: call.path,
            canonical_query: &query,
            headers,
            host: &self.endpoint.host,
            body: call.body,
            access_key_id: &self.credential.access_key_id,
            access_key_secret: &self.credential.access_key_secret,
        });
        let mut headers = signed.signed_headers;
        headers.insert("Authorization".into(), signed.authorization);
        Ok(RpcRequest {
            method: call.method.to_uppercase(),
            url: self.endpoint.url(call.path),
            style: SignStyle::V3,
            query,
            headers,
            body: call.body.into(),
        })
    }
    pub async fn call_roa(&self, call: &RoaCall<'_>) -> DomainResult<RpcResponse> {
        self.execute_async(&self.build_roa(call)?).await
    }
}
impl std::fmt::Debug for RpcRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("style", &self.style)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for RpcResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcResponse").field("status", &self.status).finish_non_exhaustive()
    }
}

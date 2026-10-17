//! 复用既有 TLS 材料装配，采用有界异步请求，不在失败时改用明文或重试启动。
use crate::client::TlsConfig;
use agf_core::{
    error::{DomainError, DomainResult},
    process_hook::{ProcessMode, ProcessReceipt, ProcessRequest, launch_action_supported},
    time::Timestamp,
};
use secrecy::{ExposeSecret, SecretString};
use std::time::{Duration, Instant};

pub(crate) fn denied(message: &str) -> DomainError {
    DomainError::PreconditionFailed(message.into())
}
/// 只连接一个显式 HTTPS 平台原点；凭据不进入 Debug、审计或子进程。
pub struct ProcessClient {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    key: SecretString,
}
impl std::fmt::Debug for ProcessClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessClient").finish_non_exhaustive()
    }
}
impl ProcessClient {
    /// 独立配置的 Agent Key 必须在平台绑定 Agent；服务端最终核验绑定关系。
    pub fn new(base: &str, key: SecretString, tls: &TlsConfig) -> DomainResult<Self> {
        let mut endpoint = reqwest::Url::parse(base).map_err(|_| denied("Invalid process policy HTTPS origin"))?;
        if endpoint.scheme() != "https"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !["", "/"].contains(&endpoint.path())
            || tls.insecure_skip_verify
            || !key.expose_secret().starts_with("agf_")
            || key.expose_secret().len() > 1024
            || key.expose_secret().contains(['\r', '\n'])
        {
            return Err(denied("Process policy requires verified HTTPS and a bound Agent API Key"));
        }
        tls.validate(Some(base))?;
        let material = tls.load()?;
        let config = material.client_config()?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .use_preconfigured_tls((*config).clone())
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(2))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| denied("Process policy TLS client setup failed"))?;
        endpoint.set_path("/api/v1/runtime/process/check");
        Ok(Self { client, endpoint, key })
    }
    /// 严格核验原始 nonce、请求摘要、Agent、模式、短期限与审计提交回执。
    pub async fn check(&self, request: &ProcessRequest) -> DomainResult<ProcessReceipt> {
        let digest = request.digest()?;
        let start = Instant::now();
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header("X-AGF-Key", self.key.expose_secret())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .json(request)
            .send()
            .await
            .map_err(|_| denied("Process policy request failed; no process authorized"))?;
        if response.status() != reqwest::StatusCode::OK
            || response.headers().contains_key(reqwest::header::CONTENT_ENCODING)
            || response.content_length().is_some_and(|n| n > 16384)
        {
            return Err(denied("Process policy response rejected"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| denied("Process policy response interrupted"))? {
            if bytes.len() + chunk.len() > 16384 {
                return Err(denied("Process policy receipt exceeds budget"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let receipt: ProcessReceipt =
            serde_json::from_slice(&bytes).map_err(|_| denied("Invalid process policy receipt"))?;
        let now = Timestamp::now().unix_millis();
        if start.elapsed() >= Duration::from_secs(3)
            || receipt.request_id != request.request_id
            || receipt.agent_id != request.agent_id
            || receipt.request_sha256 != digest
            || receipt.mode != request.mode
            || receipt.audit_id.is_nil()
            || !receipt.audit_committed
            || receipt.enforced
            || receipt.expires_at_ms <= now
            || receipt.expires_at_ms > now + 5000
            || (receipt.launch_allowed
                && (request.mode != ProcessMode::Launch
                    || !launch_action_supported(receipt.action, receipt.dry_run, false)))
        {
            return Err(denied("Process policy receipt is stale, uncommitted or not bound to original request"));
        }
        Ok(receipt)
    }
}

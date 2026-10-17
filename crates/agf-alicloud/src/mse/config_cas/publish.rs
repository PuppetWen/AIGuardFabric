use super::client::{Envelope, WireResponse, check_deadline, normal_response};
use super::*;
use reqwest::{Method, header::HeaderValue};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Instant;

impl NacosConfigClient {
    /// Send one CAS publication. It is an upsert with content-MD5 comparison, not update-only.
    ///
    /// This driver makes no retry, claim or reload decision. After an uncertain outcome, observe only.
    /// # Errors
    /// Local validation, credentials or guard reject before transport. Later failures are Uncertain.
    pub async fn publish(
        &self,
        key: &ConfigKey,
        expected_md5: &str,
        content: &str,
        guard: &dyn NacosSendGuard,
    ) -> DomainResult<PublishOutcome> {
        key.validate()?;
        if !query::valid_md5(expected_md5) || content.len() > self.limits.max_content_bytes {
            return Err(DomainError::Validation("Nacos CAS requires a valid baseline MD5 and bounded content".into()));
        }
        let started = AtomicBool::new(false);
        let deadline = Instant::now() + self.limits.timeout;
        match tokio::time::timeout_at(
            deadline,
            Box::pin(self.publish_inner(key, expected_md5, content, guard, &started, deadline)),
        )
        .await
        {
            Ok(result) => result,
            Err(_) if started.load(Ordering::Relaxed) => Ok(PublishOutcome::Uncertain(UncertainReason::Deadline)),
            Err(_) => Err(DomainError::Timeout("Nacos call expired before transport started".into())),
        }
    }
    async fn publish_inner(
        &self,
        key: &ConfigKey,
        expected_md5: &str,
        content: &str,
        guard: &dyn NacosSendGuard,
        started: &AtomicBool,
        deadline: Instant,
    ) -> DomainResult<PublishOutcome> {
        let mut headers = self.prepare(key, guard, deadline).await?;
        headers.insert(
            "casmd5",
            HeaderValue::from_str(&expected_md5.to_ascii_lowercase())
                .map_err(|_| DomainError::Validation("Invalid Nacos baseline MD5".into()))?,
        );
        let mut form = key.pairs().to_vec();
        form.extend([("content", content), ("type", "json")]);
        let request = self.request(Method::POST, headers).form(&form);
        check_deadline(deadline)?;
        started.store(true, Ordering::Relaxed);
        let response = match Box::pin(request.send()).await {
            Ok(response) => response,
            Err(_) => return Ok(PublishOutcome::Uncertain(UncertainReason::Transport)),
        };
        let outcome = match self.read(response).await {
            Ok(wire) => classify(&wire),
            Err(reason) => PublishOutcome::Uncertain(reason),
        };
        Ok(if Instant::now() >= deadline { PublishOutcome::Uncertain(UncertainReason::Deadline) } else { outcome })
    }
}
pub(super) fn classify(wire: &WireResponse) -> PublishOutcome {
    if normal_response(&wire.headers).is_err() {
        return PublishOutcome::Uncertain(UncertainReason::Protocol);
    }
    let Ok(body) = serde_json::from_slice::<Envelope>(&wire.body) else {
        return PublishOutcome::Uncertain(UncertainReason::Protocol);
    };
    if body.code != 0 && !(body.data.is_null() || body.data.is_string()) {
        return PublishOutcome::Uncertain(UncertainReason::Protocol);
    }
    match (wire.status, body.code) {
        (200, 0) if body.data.as_bool() == Some(true) => PublishOutcome::Accepted,
        (500, 20005) => PublishOutcome::Conflict,
        (403, code @ (10001 | 20008)) | (400, code @ (10000 | 20001 | 20002 | 20003 | 20009)) => {
            PublishOutcome::Rejected { http_status: wire.status, provider_code: code }
        }
        _ => PublishOutcome::Uncertain(UncertainReason::Protocol),
    }
}

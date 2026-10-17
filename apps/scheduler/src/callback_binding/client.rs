use super::{
    identity::Identity,
    types::{Admission, Context, NativeState, Outcome, Receipt, invalid},
};
use crate::tasks::ApiAuth;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use reqwest::{Method, Url};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::time::Instant;

const NATIVE: &str = "/api/v1/alicloud/schedulerx3/native";
const EXECUTIONS: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions";
const MAX_BODY: usize = 64 * 1024;
// Native state includes a bounded latest observation as well as the binding context.
const MAX_NATIVE: usize = 5 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct Client {
    http: reqwest::Client,
    origin: Url,
    key: String,
    pub(crate) tenant: TenantId,
    test_loopback: bool,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackClient").field("tenant", &self.tenant).finish_non_exhaustive()
    }
}
impl Client {
    pub(crate) fn new(server: &str, auth: &ApiAuth, tenant: TenantId) -> DomainResult<Self> {
        let ApiAuth::ApiKey(key) = auth else {
            return Err(DomainError::Validation("云绑定回调仅支持平台 API Key".into()));
        };
        let mut origin = Url::parse(server).map_err(|_| DomainError::Validation("平台 origin 无效".into()))?;
        if tenant.as_uuid().is_nil()
            || key.is_empty()
            || key.trim() != key
            || key.contains(['\r', '\n'])
            || !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !matches!(origin.path(), "" | "/")
        {
            return Err(DomainError::Validation("请配置显式租户、API Key 和固定平台 origin".into()));
        }
        origin.set_path("/");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(|_| DomainError::Internal("平台回调客户端初始化失败".into()))?;
        Ok(Self { http, origin, key: key.clone(), tenant, test_loopback: false })
    }
    #[cfg(test)]
    pub(crate) fn literal_loopback(server: &str, auth: &ApiAuth, tenant: TenantId) -> DomainResult<Self> {
        let mut client = Self::new(server, auth, tenant)?;
        if client.origin.host_str() != Some("127.0.0.1")
            || client.origin.scheme() != "http"
            || client.origin.port().is_none()
        {
            return Err(invalid());
        }
        client.test_loopback = true;
        Ok(client)
    }
    pub(crate) async fn identity(&self, deadline: Instant) -> DomainResult<()> {
        #[derive(Deserialize)]
        struct Me {
            tenant_id: TenantId,
        }
        let me: Me = self.call(Method::GET, "/api/v1/auth/me", None, MAX_BODY, deadline).await?;
        if me.tenant_id != self.tenant {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) async fn native(&self, deadline: Instant) -> DomainResult<NativeState> {
        let state: NativeState = self.call(Method::GET, NATIVE, None, MAX_NATIVE, deadline).await?;
        if state.tenant_id != self.tenant {
            return Err(invalid());
        }
        Ok(state)
    }
    pub(crate) async fn ready(&self, deadline: Instant) -> DomainResult<()> {
        self.identity(deadline).await?;
        let state = self.native(deadline).await?;
        let source = state.source_target.ok_or_else(invalid)?;
        source.check(self.tenant, self.test_loopback)?;
        if !state.configured
            || !state.enabled
            || !state.bindings.locally_enabled
            || !state.bindings.source_current
            || state.bindings.source_target.as_ref() != Some(&source)
            || state.bindings.version == 0
            || state.bindings.adoption_version == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) async fn context(&self, identity: &Identity, deadline: Instant) -> DomainResult<Context> {
        self.native(deadline).await?.context(self.tenant, identity, self.test_loopback)
    }
    pub(crate) async fn claim(
        &self,
        identity: &Identity,
        context: &Context,
        deadline: Instant,
    ) -> DomainResult<Receipt> {
        let body = Admission {
            request_id: identity.request_id(self.tenant),
            kind: identity.kind,
            app_id: &identity.app,
            job_id: &identity.job,
            job_execution_id: &identity.execution,
            partition_index: identity.partition.index,
            partition_total: identity.partition.total,
            binding_version: context.binding_version,
            configuration_version: context.source.configuration_version,
            source_fingerprint: &context.source.fingerprint,
        };
        let receipt: Receipt =
            self.call(Method::POST, EXECUTIONS, Some(serde_json::to_value(body)?), MAX_BODY, deadline).await?;
        self.check(&receipt, identity, context)?;
        if receipt.may_execute || (receipt.may_confirm_start && receipt.request_id != identity.request_id(self.tenant))
        {
            return Err(invalid());
        }
        Ok(receipt)
    }
    pub(crate) async fn validate(&self, original: &Receipt, deadline: Instant) -> DomainResult<Receipt> {
        let value: Receipt = self
            .call(
                Method::POST,
                &format!("{EXECUTIONS}/{}/validate", original.fact_id),
                Some(json!({"claim_id":original.claim_id})),
                MAX_BODY,
                deadline,
            )
            .await?;
        self.followup(&value, original)?;
        if !value.same_claim(original) || value.may_confirm_start {
            return Err(invalid());
        }
        Ok(value)
    }
    pub(crate) async fn lookup(
        &self,
        identity: &Identity,
        context: &Context,
        deadline: Instant,
    ) -> DomainResult<Receipt> {
        let request = identity.request_id(self.tenant);
        let receipt: Receipt =
            self.call(Method::GET, &format!("{EXECUTIONS}/requests/{request}"), None, MAX_BODY, deadline).await?;
        self.check(&receipt, identity, context)?;
        if receipt.request_id != request || receipt.may_confirm_start || receipt.may_execute {
            return Err(invalid());
        }
        Ok(receipt)
    }
    pub(crate) async fn complete(
        &self,
        original: &Receipt,
        outcome: &Outcome,
        deadline: Instant,
    ) -> DomainResult<Receipt> {
        outcome.check()?;
        let value: Receipt = self
            .call(
                Method::POST,
                &format!("{EXECUTIONS}/{}/complete", original.fact_id),
                Some(json!({"claim_id":original.claim_id,"outcome":outcome})),
                MAX_BODY,
                deadline,
            )
            .await?;
        self.followup(&value, original)?;
        if !value.same_claim(original)
            || value.may_confirm_start
            || value.may_execute
            || value.outcome.as_ref() != Some(outcome)
        {
            return Err(invalid());
        }
        Ok(value)
    }
    pub(crate) async fn status(&self, original: &Receipt, deadline: Instant) -> DomainResult<Receipt> {
        let value: Receipt =
            self.call(Method::GET, &format!("{EXECUTIONS}/{}", original.fact_id), None, MAX_BODY, deadline).await?;
        self.followup(&value, original)?;
        if !value.same_claim(original) || value.may_confirm_start || value.may_execute {
            return Err(invalid());
        }
        Ok(value)
    }
    pub(crate) fn check(&self, receipt: &Receipt, identity: &Identity, context: &Context) -> DomainResult<()> {
        receipt.check(self.tenant, identity, context, self.test_loopback)
    }
    fn followup(&self, value: &Receipt, original: &Receipt) -> DomainResult<()> {
        let identity = Identity {
            kind: original.kind,
            app: original.app_id.clone(),
            job: original.job_id.clone(),
            execution: original.job_execution_id.clone(),
            partition: crate::Partition { index: original.partition_index, total: original.partition_total },
        };
        let context = Context {
            source: original.original_target.clone(),
            binding_version: original.binding_version,
            adoption_version: original.adoption_version,
        };
        self.check(value, &identity, &context)
    }
    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        max: usize,
        deadline: Instant,
    ) -> DomainResult<T> {
        let url = self.origin.join(path).map_err(|_| invalid())?;
        if url.origin() != self.origin.origin() || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }
        tokio::time::timeout_at(deadline, async {
            let mut request = self
                .http
                .request(method, url)
                .header("X-AGF-Key", &self.key)
                .header("X-AGF-Tenant", self.tenant.to_string());
            if let Some(body) = body {
                if serde_json::to_vec(&body)?.len() > MAX_BODY {
                    return Err(invalid());
                }
                request = request.json(&body);
            }
            let mut reply = request.send().await.map_err(|_| unavailable())?;
            if !reply.status().is_success() {
                return Err(status_error(reply.status().as_u16()));
            }
            if reply.content_length().is_some_and(|size| size > max as u64) {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = reply.chunk().await.map_err(|_| unavailable())? {
                if bytes.len().saturating_add(chunk.len()) > max {
                    return Err(invalid());
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_| invalid())
        })
        .await
        .map_err(|_| DomainError::Timeout("平台回调协议请求超时；禁止重跑业务".into()))?
    }
}
fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "platform callback protocol".into(),
        cause: "请求或响应未能完整确认；禁止重跑业务".into(),
    }
}
fn status_error(status: u16) -> DomainError {
    match status {
        401 => DomainError::Unauthenticated("平台服务身份已失效".into()),
        403 => DomainError::Forbidden("平台当前权限拒绝回调操作".into()),
        409 => DomainError::Conflict("原执行身份或来源冲突；禁止重跑业务".into()),
        412 => DomainError::PreconditionFailed("当前绑定、资格或上游批次不满足执行条件".into()),
        _ => unavailable(),
    }
}

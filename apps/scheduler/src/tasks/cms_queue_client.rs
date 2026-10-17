//! Only the authenticated platform can admit CMS intents or settle provider outcomes.
use super::{ApiAuth, TenantId};
use reqwest::{Method, Url};
use serde_json::Value;
use std::time::Duration;

pub(super) const BASE: &str = "/api/v1/alicloud/cms/queue";
pub(super) struct Client {
    http: reqwest::Client,
    origin: Url,
    auth: ApiAuth,
    tenant: TenantId,
}
impl Client {
    pub(super) fn new(server: &str, auth: &ApiAuth, tenant: TenantId) -> anyhow::Result<Self> {
        let mut origin = Url::parse(server).map_err(|_| anyhow::anyhow!("CMS 平台 origin 无效"))?;
        let secret = match auth {
            ApiAuth::ApiKey(key) | ApiAuth::Bearer(key) => key,
        };
        anyhow::ensure!(
            !tenant.as_uuid().is_nil()
                && !secret.is_empty()
                && secret.trim() == secret
                && !secret.contains(['\r', '\n'])
                && matches!(origin.scheme(), "http" | "https")
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && matches!(origin.path(), "" | "/"),
            "CMS 需要固定平台 origin、有效租户和服务身份"
        );
        origin.set_path("/");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| anyhow::anyhow!("CMS 平台客户端初始化失败"))?;
        Ok(Self { http, origin, auth: auth.clone(), tenant })
    }
    pub(super) async fn identity(&self) -> anyhow::Result<()> {
        let value = self.get("/api/v1/auth/me").await?;
        anyhow::ensure!(value["tenant_id"] == self.tenant.to_string(), "CMS 服务身份不属于当前租户");
        Ok(())
    }
    pub(super) async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.call(Method::GET, path, None, false).await?.ok_or_else(|| anyhow::anyhow!("CMS 回执缺失"))
    }
    pub(super) async fn original(&self, id: super::Id) -> anyhow::Result<Option<Value>> {
        self.call(Method::GET, &format!("{BASE}/requests/{id}"), None, true).await
    }
    pub(super) async fn post(&self, path: &str, value: &Value) -> anyhow::Result<Value> {
        self.call(Method::POST, path, Some(value), false).await?.ok_or_else(|| anyhow::anyhow!("CMS 回执缺失"))
    }
    async fn call(
        &self,
        method: Method,
        path: &str,
        value: Option<&Value>,
        absent: bool,
    ) -> anyhow::Result<Option<Value>> {
        anyhow::ensure!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains(['?', '#']),
            "CMS API 路径无效"
        );
        let url = self.origin.join(path).map_err(|_| anyhow::anyhow!("CMS API 路径无效"))?;
        let mut request =
            self.auth.apply(self.http.request(method, url)).header("x-agf-tenant", self.tenant.to_string());
        if let Some(value) = value {
            request = request.json(value);
        }
        let mut response = request.send().await.map_err(|_| anyhow::anyhow!("CMS 平台连接未确认；保留原请求编号"))?;
        if absent && response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        anyhow::ensure!(
            response.status().is_success(),
            "CMS 平台 HTTP {}；保留原 wire，不自动更换身份或配置",
            response.status().as_u16()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) =
            response.chunk().await.map_err(|_| anyhow::anyhow!("CMS 回执读取未确认；保留原请求编号"))?
        {
            anyhow::ensure!(bytes.len() + chunk.len() <= 512 * 1024, "CMS 回执超过 512 KiB");
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map(Some).map_err(|_| anyhow::anyhow!("CMS 回执 JSON 无效；保留原请求编号"))
    }
}

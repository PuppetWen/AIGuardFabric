//! Asynchronous STS AssumeRole exchange. Only explicit calls may contact the configured endpoint.
use super::*;
use crate::{
    AdapterMode,
    endpoint::{EndpointStyle, ResolvedEndpoint},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
};
use agf_core::enums::AliCloudService;
use serde::{Deserialize, Serialize};

/// Scope of one temporary role session; source credentials remain separately in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumeRoleRequest {
    pub role_arn: String,
    pub session_name: String,
    pub duration_seconds: u32,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub policy: Option<String>,
}
impl AssumeRoleRequest {
    pub fn validate(&self) -> DomainResult<()> {
        self.parameters().map(|_| ())
    }
    pub fn from_integration(integration: &CloudIntegration) -> DomainResult<Self> {
        Ok(Self {
            role_arn: AssumeRoleResolver::require_role_arn(integration)?.into(),
            session_name: integration.role_session_name.clone().unwrap_or_else(|| "aiguardfabric".into()),
            duration_seconds: 3600,
            external_id: None,
            policy: None,
        })
    }
    pub(super) fn parameters(&self) -> DomainResult<Vec<(String, String)>> {
        if !self.role_arn.starts_with("acs:ram::") || !self.role_arn.contains(":role/") || self.role_arn.len() > 2048 {
            return Err(DomainError::Validation("STS RoleArn 格式无效".into()));
        }
        if !(2..=64).contains(&self.session_name.len())
            || !self.session_name.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
        {
            return Err(DomainError::Validation("STS 会话名称必须是 2–64 位字母、数字、点、横线或下划线".into()));
        }
        if !(900..=43200).contains(&self.duration_seconds) {
            return Err(DomainError::Validation("STS 有效期必须为 900–43200 秒，并受角色设置上限约束".into()));
        }
        let mut params = vec![
            ("RoleArn".into(), self.role_arn.clone()),
            ("RoleSessionName".into(), self.session_name.clone()),
            ("DurationSeconds".into(), self.duration_seconds.to_string()),
        ];
        if let Some(external) = &self.external_id {
            params.push(("ExternalId".into(), external.clone()));
        }
        if let Some(policy) = &self.policy {
            if policy.len() > 2048 || serde_json::from_str::<serde_json::Value>(policy).is_err() {
                return Err(DomainError::Validation("STS 会话策略须为不超过 2048 字节的 JSON".into()));
            }
            params.push(("Policy".into(), policy.clone()));
        }
        Ok(params)
    }
}
pub(super) fn endpoint(raw: &str) -> DomainResult<ResolvedEndpoint> {
    let raw = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let url = url::Url::parse(&raw).map_err(|_| DomainError::Config("STS 地址格式无效".into()))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(DomainError::Config("STS 地址必须是 HTTPS 服务根地址；本地回环测试允许 HTTP".into()));
    }
    Ok(ResolvedEndpoint {
        service: AliCloudService::Cms,
        region: "cn-hangzhou".into(),
        host: url[url::Position::BeforeHost..url::Position::AfterPort].into(),
        scheme: if url.scheme() == "https" { "https" } else { "http" },
        style: EndpointStyle::Public,
        origin: "override",
    })
}
/// Exchange a RAM principal for a role session. Mock mode returns before constructing a network client.
pub async fn assume_role(
    endpoint_url: &str,
    source: CloudCredential,
    request: &AssumeRoleRequest,
    mock: bool,
) -> DomainResult<CredentialOutcome> {
    if mock {
        return Err(DomainError::DependencyUnavailable {
            dependency: "aliyun.sts".into(),
            cause: "模拟模式禁止真实 STS 凭据交换".into(),
        });
    }
    source.validate()?;
    if source.is_expired(Timestamp::now()) {
        return Err(DomainError::Forbidden("STS 源凭据已过期".into()));
    }
    let params = request.parameters()?;
    let transport = Arc::new(ReqwestTransport::with_tls_options(10, None, false)?);
    let client = RpcClient::live(
        AdapterMode::Live,
        RpcClientConfig {
            adapter: "alicloud-sts".into(),
            region: "cn-hangzhou".into(),
            account_id: String::new(),
            style: SignStyle::Rpc,
            timeout_secs: 10,
        },
        Some(source),
        endpoint(endpoint_url)?,
        transport.clone(),
    )?
    .with_async_transport(transport);
    let response = client.call_async("AssumeRole", "2015-04-01", "POST", &params).await?;
    let fields =
        response.body.get("Credentials").ok_or_else(|| DomainError::Parse("STS 响应缺少 Credentials".into()))?;
    let field = |key| {
        fields
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DomainError::Parse(format!("STS 响应缺少 {key}")))
    };
    let expiry = Timestamp::parse_rfc3339(field("Expiration")?)
        .map_err(|_| DomainError::Parse("STS Expiration 格式无效".into()))?;
    let credential = CloudCredential::sts(
        field("AccessKeyId")?,
        field("AccessKeySecret")?,
        field("SecurityToken")?,
        expiry,
        CloudCredentialKind::AssumeRole,
    );
    credential.validate()?;
    if credential.is_expired(Timestamp::now()) {
        return Err(DomainError::Forbidden("STS 返回了过期凭据".into()));
    }
    Ok(CredentialOutcome::new(credential))
}

/// Decode a tenant-decrypted credential object; never infer a temporary token's expiration.
pub fn from_secret_json(raw: &str) -> DomainResult<CloudCredential> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| DomainError::Config("云凭据必须是 JSON 对象".into()))?;
    let field = |key| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| DomainError::Config(format!("云凭据缺少 {key}")))
    };
    let ak = field("access_key_id")?;
    let sk = field("access_key_secret")?;
    let credential = if let Some(token) =
        value.get("security_token").and_then(serde_json::Value::as_str).filter(|s| !s.is_empty())
    {
        let expiry = Timestamp::parse_rfc3339(field("expires_at")?)
            .map_err(|_| DomainError::Config("临时云凭据 expires_at 必须是 RFC3339 时间".into()))?;
        CloudCredential::sts(ak, sk, token, expiry, CloudCredentialKind::StsToken)
    } else {
        CloudCredential::long_term(ak, sk)
    };
    credential.validate()?;
    if credential.is_expired(Timestamp::now()) {
        return Err(DomainError::Forbidden("云凭据已过期".into()));
    }
    Ok(credential)
}
impl StsResolver {
    /// Load a pre-issued token or exchange the configured source for the declared role.
    pub async fn resolve_async(
        &self,
        integration: &CloudIntegration,
        ctx: &CredentialContext,
    ) -> DomainResult<CredentialOutcome> {
        if ctx.mock || !self.allow_network {
            return self.resolve(integration, ctx);
        }
        let source = if let Some(id) = integration.credential_ref {
            from_secret_json(&ctx.secrets.resolve_secret(id)?)?
        } else {
            EnvResolver::new().resolve(integration, ctx)?.credential
        };
        if integration.assume_role_arn.is_some() {
            assume_role(&self.endpoint, source, &AssumeRoleRequest::from_integration(integration)?, false).await
        } else if source.security_token.is_some() {
            Ok(CredentialOutcome::new(source))
        } else {
            Err(DomainError::Config("STS 配置需包含临时 Token，或提供源凭据及 RoleArn".into()))
        }
    }
}
impl AssumeRoleResolver {
    /// Resolve source credentials, then perform a signed asynchronous STS exchange.
    pub async fn resolve_async(
        &self,
        integration: &CloudIntegration,
        ctx: &CredentialContext,
    ) -> DomainResult<CredentialOutcome> {
        if ctx.mock || !self.allow_network {
            return self.resolve(integration, ctx);
        }
        let source = self.source.resolve(integration, ctx)?.credential;
        assume_role(&self.endpoint, source, &AssumeRoleRequest::from_integration(integration)?, false).await
    }
}

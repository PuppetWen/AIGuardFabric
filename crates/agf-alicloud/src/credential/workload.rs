//! ECS IMDSv2 和 OIDC 工作负载身份。模拟模式零网络，不把身份令牌写入 URL 或错误日志。
use super::sts_async::{AssumeRoleRequest, from_secret_json};
use super::{CloudCredential, CloudCredentialKind, DomainError, DomainResult};
use serde_json::{Value, json};
pub const ECS_METADATA: &str = "http://100.100.100.200";
const LIMIT: usize = 64 * 1024;

pub async fn ecs_role(endpoint: &str, role_name: Option<&str>, mock: bool) -> DomainResult<CloudCredential> {
    real_only(mock)?;
    let root = url::Url::parse(endpoint).map_err(|_| DomainError::Config("ECS 元数据地址无效".into()))?;
    let local = root.host_str().is_some_and(|host| {
        host == "localhost"
            || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
    });
    if (!local && root.as_str().trim_end_matches('/') != ECS_METADATA)
        || root.scheme() != "http"
        || root.path() != "/"
        || !root.username().is_empty()
        || root.password().is_some()
        || root.query().is_some()
        || root.fragment().is_some()
    {
        return Err(DomainError::Config("只允许官方 ECS 元数据地址或本地回环测试地址".into()));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(network)?;
    let base = endpoint.trim_end_matches('/');
    let token = text(
        client
            .put(format!("{base}/latest/api/token"))
            .header("X-aliyun-ecs-metadata-token-ttl-seconds", "21600")
            .send()
            .await
            .map_err(network)?,
    )
    .await?;
    if token.trim().is_empty() || token.len() > 8192 {
        return Err(DomainError::Parse("ECS IMDSv2 未返回有效令牌".into()));
    }
    let role = match role_name.filter(|role| !role.is_empty()) {
        Some(role) => role.to_owned(),
        None => text(
            client
                .get(format!("{base}/latest/meta-data/ram/security-credentials/"))
                .header("X-aliyun-ecs-metadata-token", token.trim())
                .send()
                .await
                .map_err(network)?,
        )
        .await?
        .trim()
        .to_owned(),
    };
    if role.is_empty() || role.len() > 64 || !role.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        return Err(DomainError::Validation("ECS RAM Role 名称无效或实例未绑定角色".into()));
    }
    let body = text(
        client
            .get(format!("{base}/latest/meta-data/ram/security-credentials/{role}"))
            .header("X-aliyun-ecs-metadata-token", token.trim())
            .send()
            .await
            .map_err(network)?,
    )
    .await?;
    let fields: Value = serde_json::from_str(&body).map_err(|_| DomainError::Parse("ECS 凭据响应不是 JSON".into()))?;
    if fields["Code"] != "Success" {
        return Err(DomainError::Forbidden("ECS RAM Role 凭据尚未就绪".into()));
    }
    decode(&fields, CloudCredentialKind::InstanceRole)
}

pub async fn oidc_role(
    endpoint: &str,
    request: &AssumeRoleRequest,
    provider_arn: &str,
    token: &str,
    mock: bool,
) -> DomainResult<CloudCredential> {
    real_only(mock)?;
    if !provider_arn.starts_with("acs:ram::") || !provider_arn.contains(":oidc-provider/") || provider_arn.len() > 2048
    {
        return Err(DomainError::Validation("OIDC 身份提供商 ARN 无效".into()));
    }
    if token.trim().is_empty() || token.len() > LIMIT {
        return Err(DomainError::Validation("工作负载 OIDC Token 为空或过大".into()));
    }
    if request.external_id.is_some() {
        return Err(DomainError::Validation("AssumeRoleWithOIDC 不接受 ExternalId".into()));
    }
    let root = super::sts_async::endpoint(endpoint)?;
    let mut params = request.parameters()?;
    params.extend([
        ("Action".into(), "AssumeRoleWithOIDC".into()),
        ("Version".into(), "2015-04-01".into()),
        ("Format".into(), "JSON".into()),
        ("OIDCProviderArn".into(), provider_arn.into()),
        ("OIDCToken".into(), token.trim().into()),
    ]);
    let form = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(&params).finish();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(network)?;
    // 此 API 使用 OIDC Token 身份认证，不附加 AK 签名；令牌只放 POST 表单。
    let body = text(
        client
            .post(root.url("/"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(network)?,
    )
    .await?;
    let value: Value = serde_json::from_str(&body).map_err(|_| DomainError::Parse("OIDC STS 响应不是 JSON".into()))?;
    if crate::http::check_response(&crate::http::RpcResponse { status: 200, body: value.clone(), raw: String::new() })
        .is_err()
    {
        return Err(DomainError::Forbidden("OIDC STS 拒绝交换，请核对角色信任关系和 Token 有效期".into()));
    }
    let fields = value
        .get("Credentials")
        .ok_or_else(|| DomainError::Forbidden("OIDC STS 拒绝交换，请核对受众、角色信任关系和有效期".into()))?;
    decode(fields, CloudCredentialKind::WorkloadIdentity)
}
pub async fn token_file(path: &std::path::Path) -> DomainResult<String> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| DomainError::Config("无法读取部署端指定的 OIDC Token 文件".into()))?;
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| DomainError::Config("OIDC Token 文件读取失败".into()))?;
    if bytes.len() > LIMIT {
        return Err(DomainError::Validation("OIDC Token 文件超过 64 KiB".into()));
    }
    String::from_utf8(bytes).map_err(|_| DomainError::Validation("OIDC Token 文件不是 UTF-8".into()))
}
fn decode(fields: &Value, kind: CloudCredentialKind) -> DomainResult<CloudCredential> {
    let mut credential = from_secret_json(
        &json!({"access_key_id":fields["AccessKeyId"],"access_key_secret":fields["AccessKeySecret"],
        "security_token":fields["SecurityToken"],"expires_at":fields["Expiration"]})
        .to_string(),
    )?;
    if credential.security_token.is_none() || credential.expires_at.is_none() {
        return Err(DomainError::Parse("工作负载身份必须返回临时令牌与真实有效期".into()));
    }
    credential.kind = kind;
    Ok(credential)
}
fn real_only(mock: bool) -> DomainResult<()> {
    if mock {
        Err(DomainError::PreconditionFailed("模拟模式禁止读取真实工作负载身份".into()))
    } else {
        Ok(())
    }
}
fn network(error: reqwest::Error) -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "alicloud.workload-identity".into(),
        cause: error.without_url().to_string(),
    }
}
async fn text(mut response: reqwest::Response) -> DomainResult<String> {
    if !response.status().is_success() {
        return Err(DomainError::Forbidden(format!("工作负载身份服务返回 HTTP {}", response.status().as_u16())));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network)? {
        if bytes.len() + chunk.len() > LIMIT {
            return Err(DomainError::Parse("工作负载身份响应超过 64 KiB".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| DomainError::Parse("工作负载身份响应不是 UTF-8".into()))
}

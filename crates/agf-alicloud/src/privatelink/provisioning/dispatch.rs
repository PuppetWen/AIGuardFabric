use super::{PreparedChange, WriteEvidence, WriteStatus, expired, validate};
use crate::{
    http::{RpcClient, RpcResponse},
    openapi,
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::Id,
};
use async_trait::async_trait;
use tokio::time::{Instant, timeout_at};

/// 调用层提供原主体、云来源、已领取 UUID 和当前权限的检查。
#[async_trait]
pub trait CurrentGuard: Send + Sync {
    /// 在已有云来源锁下检查，禁止递归获取同一运行锁。
    ///
    /// # Errors
    /// 原 JWT/Key/租户/角色/资源/来源修订或领取证明已失效。
    async fn validate(&self) -> DomainResult<()>;
}

/// 原预算内只进入一次传输。ACK/未知事实不会因随后撤权被改为「未发送」。
///
/// # Errors
/// 仅在进入传输前返回错误；已发送后的任何失败返回安全事实供持久封存。
pub async fn dispatch_once(
    client: &RpcClient,
    planned: &PreparedChange,
    guard: &dyn CurrentGuard,
    original_deadline: Instant,
) -> DomainResult<WriteEvidence> {
    let definition = openapi::contract(AliCloudService::Privatelink, planned.action)?;
    if definition.version != "2020-04-15"
        || definition.style != "RPC"
        || definition.method != "POST"
        || definition.path != "/"
        || definition.read_only
        || !matches!(planned.action, "CreateVpcEndpoint" | "EnableVpcEndpointConnection")
    {
        return Err(DomainError::Config("PrivateLink 建链需要精确的单次写入 API 契约".into()));
    }
    let request = definition.build(client, &planned.input)?;
    timeout_at(original_deadline, guard.validate()).await.map_err(|_| expired())??;
    if Instant::now() >= original_deadline {
        return Err(expired());
    }
    let response = timeout_at(original_deadline, client.execute_async_raw(&request)).await;
    let (status, provider_request_id, endpoint_id) = match response {
        Ok(Ok(response)) => classify(&response, planned),
        Ok(Err(_)) | Err(_) => (WriteStatus::Unknown, None, planned.endpoint_id.clone()),
    };
    let authority_current = matches!(timeout_at(original_deadline, guard.validate()).await, Ok(Ok(())));
    Ok(WriteEvidence {
        attempted: true,
        status,
        provider_request_id,
        endpoint_id,
        authority_current,
        original_deadline_current: Instant::now() < original_deadline,
    })
}

pub(super) fn classify(response: &RpcResponse, planned: &PreparedChange) -> (WriteStatus, Option<Id>, Option<String>) {
    if serde_json::to_vec(&response.body).map_or(true, |bytes| bytes.len() > 4 * 1024 * 1024) {
        return (WriteStatus::Unknown, None, planned.endpoint_id.clone());
    }
    let request_id =
        response.body["RequestId"].as_str().and_then(|value| Id::parse(value).ok()).filter(|id| !id.as_uuid().is_nil());
    let Some(request_id) = request_id else {
        return (WriteStatus::Unknown, None, planned.endpoint_id.clone());
    };
    if matches!(response.status, 400 | 401 | 403 | 404 | 409 | 412 | 422)
        && response.body["Code"]
            .as_str()
            .is_some_and(|code| validate::token(code, 128) || code.split('.').all(|part| validate::token(part, 128)))
    {
        return (WriteStatus::Rejected, Some(request_id), planned.endpoint_id.clone());
    }
    if response.status != 200 || response.body.get("Code").is_some() {
        return (WriteStatus::Unknown, Some(request_id), planned.endpoint_id.clone());
    }
    let endpoint = match &planned.endpoint_id {
        Some(value) => Some(value.clone()),
        None => {
            response.body["EndpointId"].as_str().filter(|value| validate::resource(value, "ep-")).map(str::to_owned)
        }
    };
    if endpoint.is_none() {
        return (WriteStatus::Unknown, Some(request_id), None);
    }
    (WriteStatus::Acknowledged, Some(request_id), endpoint)
}

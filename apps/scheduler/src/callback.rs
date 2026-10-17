//! SchedulerX3 HTTP executor: independent delivery token plus current API admission and start.
use super::*;
use crate::callback_binding::{Identity, Kind, positive_id, valid_execution};
use agf_core::error::DomainError;
use axum::{Json, extract::Path as HttpPath, http::HeaderMap};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) fn cloud_task(name: &str) -> bool {
    matches!(
        name,
        "asset-inventory" | "log-pull" | "redteam-cruise" | "rule-hot-reload" | "report-generate" | "cold-archive"
    )
}
fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok().filter(|value| !value.is_empty())?;
    if values.next().is_some() { None } else { Some(value) }
}
fn request_identity(
    execution: &dispatch::Execution,
    kind: Kind,
    headers: &HeaderMap,
) -> Result<Identity, &'static str> {
    let supplied = text(headers, "authorization").and_then(|value| value.strip_prefix("Bearer ")).unwrap_or("");
    if execution.token.is_empty() || !bool::from(Sha256::digest(supplied).ct_eq(&Sha256::digest(&execution.token))) {
        return Err("unauthorized");
    }
    if !positive_id(&execution.app_id) || text(headers, "schedulerx-appId") != Some(execution.app_id.as_str()) {
        return Err("云应用 ID 不匹配");
    }
    let job = text(headers, "schedulerx-jobId").filter(|value| positive_id(value)).ok_or("缺少有效 JobId")?;
    let execution_id = text(headers, "schedulerx-jobExecutionId")
        .filter(|value| valid_execution(value))
        .ok_or("缺少有效 JobExecutionId")?;
    if ["schedulerx-shardingindex", "schedulerx-shardingtotal"]
        .iter()
        .any(|name| headers.get_all(*name).iter().count() > 1)
    {
        return Err("无效分片参数");
    }
    let partition = Partition::parse(headers).map_err(|_| "无效分片参数")?;
    Ok(Identity { kind, app: execution.app_id.clone(), job: job.into(), execution: execution_id.into(), partition })
}
pub(crate) async fn invoke(
    registry: Arc<Registry>,
    HttpPath(kind): HttpPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(110);
    let fail = |status, message: &str| (status, Json(json!({"ok":false,"error":message})));
    if !registry.execution.cloud {
        return fail(StatusCode::SERVICE_UNAVAILABLE, "当前使用本地调度，云回调未开启");
    }
    let Some(kind) = Kind::parse(&kind) else {
        return fail(StatusCode::NOT_FOUND, "未知任务");
    };
    let identity = match request_identity(&registry.execution, kind, &headers) {
        Ok(identity) => identity,
        Err("unauthorized") => return fail(StatusCode::UNAUTHORIZED, "回调认证失败"),
        Err(message) => return fail(StatusCode::BAD_REQUEST, message),
    };
    let handler = registry.handlers.lock().ok().and_then(|map| map.get(kind.runtime()).cloned());
    let Some(handler) = handler else {
        return fail(StatusCode::CONFLICT, "任务已禁用或未登记");
    };
    if registry.execution.binding.is_none() {
        return fail(StatusCode::SERVICE_UNAVAILABLE, "服务绑定身份未配置");
    }
    let execution_id = identity.execution_id();
    match binding_execution::run(Arc::clone(&registry), identity, handler, deadline).await {
        Ok(receipt) => {
            let complete = receipt.completion_state == "complete";
            let ok = complete && receipt.outcome.as_ref().is_some_and(|outcome| outcome.ok);
            (
                if !complete {
                    StatusCode::CONFLICT
                } else if ok {
                    StatusCode::OK
                } else {
                    StatusCode::BAD_GATEWAY
                },
                Json(json!({"ok":ok,
                "execution_id":execution_id,"tenant_id":registry.execution.tenant,"result":receipt.outcome,"receipt":receipt})),
            )
        }
        Err(error) => {
            let status = match error {
                DomainError::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
                DomainError::Forbidden(_) => StatusCode::FORBIDDEN,
                DomainError::PreconditionFailed(_) => StatusCode::PRECONDITION_FAILED,
                DomainError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
                DomainError::DependencyUnavailable { .. } => StatusCode::BAD_GATEWAY,
                _ => StatusCode::CONFLICT,
            };
            fail(status, "当前云执行未确认；读取原回执并核对绑定，禁止自动重跑业务")
        }
    }
}
pub(crate) async fn configure(
    backend: &str,
    storage: &agf_storage::StorageConfig,
    objects: Arc<dyn agf_storage::ObjectStore>,
    server: &str,
    auth: Option<&tasks::ApiAuth>,
    artifact_roots: Vec<PathBuf>,
) -> anyhow::Result<dispatch::Execution> {
    let cloud = match backend {
        "schedulerx3" => true,
        "local-cron" => false,
        _ => anyhow::bail!("未知调度后端"),
    };
    let mut execution = dispatch::Execution::offline();
    execution.cloud = cloud;
    let tenant = if cloud {
        std::env::var("AGF_SCHEDULER_TENANT_ID").context("云回调须显式配置 AGF_SCHEDULER_TENANT_ID")?
    } else {
        env_or("AGF_SCHEDULER_TENANT_ID", &TenantId::default_tenant().to_string())
    };
    execution.tenant = tenant.parse().map_err(|_| anyhow::anyhow!("AGF_SCHEDULER_TENANT_ID 必须为租户 UUID"))?;
    anyhow::ensure!(!cloud || !execution.tenant.as_uuid().is_nil(), "云调度租户不能为 nil");
    execution.artifact_roots = artifact_roots;
    if cloud {
        execution.token = env_or("AGF_SCHEDULER_CALLBACK_TOKEN", "");
        execution.app_id = env_or("AGF_SCHEDULER_CALLBACK_APP_ID", "");
        anyhow::ensure!(
            (32..=256).contains(&execution.token.len())
                && execution.token.trim() == execution.token
                && !execution.token.contains(['\r', '\n']),
            "云回调令牌需 32–256 UTF-8 字节且无首尾空白或换行"
        );
        anyhow::ensure!(positive_id(&execution.app_id), "云 HTTP AppId 必须为规范正 int64");
        let auth = auth.context("云调度必须配置当前租户的服务 API Key")?;
        let client = callback_binding::Client::new(server, auth, execution.tenant)?;
        client.ready(tokio::time::Instant::now() + Duration::from_secs(110)).await?;
        execution.binding = Some(Arc::new(client));
    }
    match agf_storage::Database::connect(storage).await {
        Ok(db) => {
            let store = Arc::new(agf_storage::Store::new(db, None, objects));
            execution.store = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
            execution.persistent = true;
        }
        Err(_) if !cloud => tracing::warn!("调度数据库不可用；本地执行回执仅在内存中，重启会丢失"),
        Err(_) => anyhow::bail!("云调度需要数据库；请先启动主服务完成迁移"),
    }
    Ok(execution)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_requires_token_app_and_canonical_execution() {
        let mut config = dispatch::Execution::offline();
        config.token = "x".repeat(32);
        config.app_id = "123".into();
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("authorization", format!("Bearer {}", config.token)),
            ("schedulerx-appId", "123".into()),
            ("schedulerx-jobId", "42".into()),
            ("schedulerx-jobExecutionId", "exec-42".into()),
        ] {
            headers.insert(axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
        }
        assert_eq!(
            request_identity(&config, Kind::AssetInventory, &headers).unwrap().execution_id(),
            "cloud:123:42:exec-42"
        );
        for bad in ["042", "+42", "9223372036854775808"] {
            headers.insert("schedulerx-jobid", bad.parse().unwrap());
            assert!(request_identity(&config, Kind::AssetInventory, &headers).is_err());
        }
        headers.insert("schedulerx-jobid", "42".parse().unwrap());
        headers.append("schedulerx-jobid", "43".parse().unwrap());
        assert!(request_identity(&config, Kind::AssetInventory, &headers).is_err());
        headers.insert("schedulerx-jobid", "42".parse().unwrap());
        headers.insert("schedulerx-shardingtotal", "2".parse().unwrap());
        assert!(request_identity(&config, Kind::AssetInventory, &headers).is_err());
        headers.remove("schedulerx-shardingtotal");
        headers.remove("authorization");
        assert_eq!(request_identity(&config, Kind::AssetInventory, &headers).unwrap_err(), "unauthorized");
    }
}

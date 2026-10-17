//! Cross-instance pull leases and persisted cursors. No credentials appear in request errors.
use crate::{
    source_ingest::{self, ResultSummary},
    source_store::{self, KIND, MAX_BYTES, Record},
    state::AppState,
};
use agf_core::{
    enums::{HealthState, IngestProtocol},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};

pub async fn poll(state: &AppState, tenant: TenantId, id: Id, manual: bool) -> DomainResult<Option<ResultSummary>> {
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let now = Timestamp::now().unix_secs();
    let lease = Id::new();
    let record = state
        .configurations
        .mutate::<Record, _>(tenant, KIND, id, |row| {
            let source = row
                .source
                .as_ref()
                .ok_or_else(|| DomainError::NotFound { entity: "log-source", id: id.to_string() })?;
            if source.protocol != IngestProtocol::HttpPull || !source.enabled {
                return Err(DomainError::Validation("只有已启用的 HTTP Pull 日志源可以拉取".into()));
            }
            if row.lease_until > now || (!manual && row.next_poll_at > now) {
                return Ok(());
            }
            row.lease_id = Some(lease);
            row.lease_until = now + 90;
            Ok(())
        })
        .await?;
    if record.lease_id != Some(lease) {
        return Ok(None);
    }
    let result = fetch(state, &record).await;
    match result {
        Ok((summary, cursor)) => {
            source_ingest::record_result(state, tenant, id, &summary, Some((lease, cursor))).await?;
            Ok(Some(summary))
        }
        Err(error) => {
            state
                .configurations
                .mutate::<Record, _>(tenant, KIND, id, |row| {
                    if row.lease_id != Some(lease) {
                        return Ok(());
                    }
                    row.lease_id = None;
                    row.lease_until = 0;
                    row.next_poll_at = now + 60;
                    if let Some(source) = row.source.as_mut() {
                        source.health = HealthState::Unhealthy;
                        source.last_error = Some(error.to_string());
                    }
                    Ok(())
                })
                .await?;
            Err(error)
        }
    }
}

async fn fetch(state: &AppState, record: &Record) -> DomainResult<(ResultSummary, Option<String>)> {
    let source = record.source.as_ref().ok_or_else(|| DomainError::Internal("日志源缺失".into()))?;
    let endpoint = source.connection.endpoint.as_deref().ok_or_else(|| DomainError::Config("未配置拉取地址".into()))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| dependency("HTTP 客户端初始化失败"))?;
    let mut request = client.get(endpoint);
    for (name, value) in source_store::headers(state, source, record)? {
        request = request.header(name, value);
    }
    if let Some(cursor) = &record.cursor {
        request = request.header("x-agf-cursor", cursor);
    }
    let mut response = request.send().await.map_err(|_| dependency("连接失败或超时，请检查地址、证书和网络"))?;
    if !response.status().is_success() {
        return Err(dependency(&format!("上游返回 HTTP {}（不跟随重定向）", response.status().as_u16())));
    }
    let cursor = response
        .headers()
        .get("x-agf-next-cursor")
        .map(|value| {
            value
                .to_str()
                .ok()
                .filter(|value| value.len() <= 4096)
                .map(str::to_owned)
                .ok_or_else(|| DomainError::Validation("上游返回了非法或过长的游标".into()))
        })
        .transpose()?;
    if response.content_length().is_some_and(|size| size > MAX_BYTES as u64) {
        return Err(DomainError::Validation("拉取响应超过 2 MiB，请在上游分页".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| dependency("读取上游响应失败"))? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(DomainError::Validation("拉取响应超过 2 MiB，请在上游分页".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((source_ingest::ingest(state, source, &bytes).await?, cursor))
}

fn dependency(cause: &str) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "http-pull".into(), cause: cause.into() }
}

pub async fn tick(state: &AppState) -> DomainResult<()> {
    let now = Timestamp::now().unix_secs();
    let mut tasks = tokio::task::JoinSet::new();
    for tenant in crate::tenant_directory::list(state).await?.into_iter().filter(|tenant| tenant.enabled) {
        for record in state.configurations.list::<Record>(tenant.id, KIND).await? {
            let Some(source) = record.source else {
                continue;
            };
            if !source.enabled
                || source.protocol != IngestProtocol::HttpPull
                || record.next_poll_at > now
                || record.lease_until > now
            {
                continue;
            }
            if tasks.len() >= 8 {
                let _ = tasks.join_next().await;
            }
            let state = state.clone();
            tasks.spawn(async move {
                if let Err(error) = poll(&state, tenant.id, source.id, false).await {
                    tracing::warn!(source_id=%source.id, %error, "log source pull failed");
                }
            });
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub async fn run_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = tick(&state).await {
            tracing::warn!(%error, "log source scheduler failed");
        }
    }
}

//! 请求上下文（请求 id / tracing span / 指标）与告警辅助（自 `middleware.rs` 拆出）。

use super::*;

/// 请求上下文中间件：生成请求 id、建立 tracing span、记录请求指标。
pub async fn request_context(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let request_id = req
        .headers()
        .get(HEADER_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| Id::new().to_string(), ToString::to_string);
    let method = req.method().clone();
    let path = matched_path(&req);
    let uri_path = req.uri().path().to_string();
    let start = Instant::now();
    state.metrics.in_flight_inc();
    let span = tracing::info_span!(
        "http",
        method = %method,
        path = %uri_path,
        request_id = %request_id,
        status = tracing::field::Empty
    );
    let id_for_scope = request_id.clone();
    let state_for_scope = state.clone();
    let response = REQUEST_ID
        .scope(id_for_scope, async move {
            let response = next.run(req).await;
            let status = response.status().as_u16();
            tracing::Span::current().record("status", status);
            state_for_scope.metrics.record_request(method.as_str(), &path, status, start.elapsed().as_secs_f64());
            response
        })
        .instrument(span)
        .await;
    state.metrics.in_flight_dec();
    let mut response = response;
    insert_header(response.headers_mut(), HEADER_REQUEST_ID, &request_id);
    response
}

/// 记录一次策略拦截（供运行时拦截端点调用）。
pub fn record_block(state: &AppState, tenant: TenantId, action: agf_core::enums::PolicyAction, policy: &str) {
    state.record_interception(tenant, action, policy);
}

/// 请求体过大时的统一错误（供处理大 body 的端点复用）。
#[must_use]
pub fn payload_too_large(limit: usize) -> ApiError {
    ApiError::new(DomainError::Validation(format!("请求体超过上限 {limit} 字节"))).with_status(413)
}

/// 记录客户端在不支持的路径上的访问（便于排障）。
pub fn warn_unknown_route(path: &str) {
    warn!(path, "未匹配任何路由");
}

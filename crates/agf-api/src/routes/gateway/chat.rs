use super::protocol::{Protocol, StreamEncoder};
use super::*;
use agf_aigw::{AiGateway, gateway::CallContext, wire::ChatRequest};
use axum::{
    http::HeaderMap,
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
};
use futures::StreamExt;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{sync::mpsc::Sender, time::Interval};
use tokio_stream::wrappers::ReceiverStream;

pub(super) async fn models(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "models", "read")?;
    let endpoints: Vec<StoredEndpoint> = state.configurations.list(principal.tenant, ENDPOINT_KIND).await?;
    let data: Vec<Value> = endpoints
        .iter()
        .filter(|r| r.endpoint.enabled)
        .map(|r| json!({"id":r.endpoint.model,"object":"model","created":0,"owned_by":r.endpoint.provider.as_str()}))
        .collect();
    Ok(Json(json!({"object":"list", "data":data})))
}

pub(super) async fn complete(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    idempotency: Option<axum::Extension<crate::middleware::IdempotencyContext>>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Response> {
    Box::pin(execute_inner(
        state,
        principal,
        headers,
        wire::request(body.clone())?,
        Protocol::OpenAi,
        Some(body),
        idempotency.map(|row| row.0),
    ))
    .await
}

pub(super) async fn execute(
    state: AppState,
    principal: Principal,
    headers: HeaderMap,
    request: ChatRequest,
    protocol: Protocol,
) -> ApiResult<Response> {
    Box::pin(execute_inner(state, principal, headers, request, protocol, None, None)).await
}

async fn execute_inner(
    state: AppState,
    principal: Principal,
    headers: HeaderMap,
    request: ChatRequest,
    protocol: Protocol,
    original_wire: Option<Value>,
    idempotency: Option<crate::middleware::IdempotencyContext>,
) -> ApiResult<Response> {
    let external_identity = principal.subject_kind == agf_core::rbac::SubjectKind::ApiKey
        || headers.contains_key(axum::http::header::AUTHORIZATION);
    if let Err(error) = principal.require(&state, "models", "write") {
        if state.store.database().is_some() && external_identity {
            let state = state.clone();
            let principal = principal.clone();
            let headers = headers.clone();
            let witness = idempotency.clone();
            let audit = tokio::spawn(async move {
                crate::gateway_settlement::permission_denial(&state, &principal, &headers, witness.as_ref()).await
            })
            .await;
            if let Ok(Ok(id)) = audit {
                return attempt_error(error, id);
            }
            tracing::warn!("Authenticated gateway permission rejection was not committed");
        }
        return Err(error);
    }
    let class = headers.get("x-agf-data-class").and_then(|v| v.to_str().ok()).unwrap_or("internal");
    let class: DataClass =
        serde_json::from_value(json!(class)).map_err(|_| DomainError::Validation("无效数据分级".into()))?;
    let mut context = CallContext::new(principal.tenant).with_data_class(class);
    context.agent_id = principal.agent_id;
    if let Some(session) = headers.get("x-agf-session").and_then(|v| v.to_str().ok()) {
        context.session_id = session.to_string();
    }
    if let Some(agent) = headers.get("x-agf-agent").and_then(|v| v.to_str().ok()) {
        let id = parse_id(agent, "agent")?;
        context.agent_id = principal.resolve_agent(Some(id))?;
        if state
            .store
            .asset_get_durable(principal.tenant, id)
            .await?
            .is_none_or(|asset| asset.kind != agf_core::enums::AssetKind::Agent)
        {
            return Err(DomainError::Validation("Agent 不属于当前租户".into()).into());
        }
    }
    let preparation = if state.store.database().is_some() && external_identity {
        Some(
            crate::gateway_settlement::begin(&state, &principal, &headers, context.agent_id, idempotency.as_ref())
                .await?,
        )
    } else {
        None
    };
    let preparation = match preparation {
        Some(preparation) => {
            if let Err(error) = preparation.require_request(&context.session_id, &request.model) {
                let id = preparation.rejected(&state, &principal, &error).await?;
                return attempt_error(error.into(), id);
            }
            context.data_class = preparation.raise_class(context.data_class);
            Some(preparation)
        }
        None => None,
    };
    let evaluate = super::prepared::evaluate(&state, &principal, context, request);
    let evaluation = if let Some(preparation) = &preparation {
        tokio::time::timeout_at(preparation.deadline(), evaluate)
            .await
            .map_err(|_| DomainError::Timeout("Model evaluation exhausted its original budget".into()).into())
            .and_then(|value| value)
    } else {
        evaluate.await
    };
    let evaluated = match evaluation {
        Ok(value) => value,
        Err(error) => {
            if let Some(preparation) = preparation {
                // The original typed denial is fixed service evidence; it never grants dispatch.
                if let Ok(id) = preparation.rejected(&state, &principal, &error.error).await {
                    return attempt_error(error, id);
                }
            }
            return Err(error);
        }
    };
    // External durable calls never weaken their accounting lane when its limits are exceeded.
    if let Some(preparation) = preparation {
        if let Err(error) = preparation.require_request(&evaluated.context.session_id, &evaluated.request.model) {
            let id = preparation.rejected(&state, &principal, &error).await?;
            return attempt_error(error.into(), id);
        }
        let components = evaluated.gateway.router().eligible(&evaluated.context.routing_context(&evaluated.request));
        if let Err(error) =
            components.and_then(|items| crate::gateway_settlement::Preparation::require_components(items.len()))
        {
            let id = preparation.rejected(&state, &principal, &error).await?;
            return attempt_error(error.into(), id);
        }
        let admitted = crate::gateway_settlement::execute(crate::gateway_settlement::Call {
            state: state.clone(),
            principal: principal.clone(),
            gateway: evaluated.gateway,
            context: evaluated.context,
            request: evaluated.request,
            route: evaluated.route,
            preparation,
            original_wire,
            idempotency,
        })
        .await?;
        let mut response = match admitted.response {
            crate::gateway_settlement::AdmittedResponse::Complete(result) => match *result {
                Ok(result) => completed_response(protocol, result).unwrap_or_else(IntoResponse::into_response),
                Err(error) => crate::error::ApiError::from(error).into_response(),
            },
            crate::gateway_settlement::AdmittedResponse::Stream(result) => match *result {
                Ok(stream) => super::atomic_stream::response(protocol, stream),
                Err(error) => crate::error::ApiError::from(error).into_response(),
            },
        };
        response.headers_mut().insert(
            "x-agf-attempt-id",
            admitted.attempt.to_string().parse().map_err(|_| DomainError::Internal("header".into()))?,
        );
        return Ok(response);
    }
    let super::prepared::PreparedCall { gateway, context, request, lease } =
        super::prepared::reserve_legacy(&state, &principal, evaluated).await?;
    if request.stream {
        return stream(state, principal, gateway, context, request, lease, protocol).await;
    }
    let audit_context = context.clone();
    let result = match gateway.chat(context, request).await {
        Ok(result) => result,
        Err(error) => {
            super::prepared::audit_call_error(&state, &principal, &audit_context, &error).await;
            return Err(error.into());
        }
    };
    lease.finish(Some(&result.usage_record)).await?;
    super::prepared::reject_over_limit(&state, &principal, &audit_context, &result).await?;
    completed_response(protocol, result)
}

fn attempt_error(error: crate::error::ApiError, id: Id) -> ApiResult<Response> {
    let mut response = error.into_response();
    response
        .headers_mut()
        .insert("x-agf-attempt-id", id.to_string().parse().map_err(|_| DomainError::Internal("header".into()))?);
    Ok(response)
}

fn completed_response(protocol: Protocol, result: agf_aigw::gateway::GatewayResponse) -> ApiResult<Response> {
    let mut response = Json(protocol.response(result.response)).into_response();
    response.headers_mut().insert(
        "x-agf-mocked",
        if result.mocked { "true" } else { "false" }.parse().map_err(|_| DomainError::Internal("header".into()))?,
    );
    response.headers_mut().insert(
        "x-agf-cached",
        if result.cached { "true" } else { "false" }.parse().map_err(|_| DomainError::Internal("header".into()))?,
    );
    Ok(response)
}

async fn stream(
    state: AppState,
    principal: Principal,
    gateway: Arc<AiGateway>,
    context: CallContext,
    request: ChatRequest,
    lease: crate::gateway_quota::Lease,
    protocol: Protocol,
) -> ApiResult<Response> {
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(16);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let audit_context = context.clone();
        let result = tokio::select! {
            () = sender.closed() => return,
            result = gateway.chat_stream_with_metadata(context, request) => result,
        };
        let (metadata, mut chunks) = match result {
            Ok((metadata, stream)) => {
                let _ = ready_tx.send(Ok::<bool, DomainError>(metadata.mocked));
                (metadata, stream)
            }
            Err(error) => {
                super::prepared::audit_call_error(&state, &principal, &audit_context, &error).await;
                let _ = ready_tx.send(Err(error));
                return;
            }
        };
        let id = format!("chatcmpl-{}", Id::new());
        let mut encoder = StreamEncoder::new(protocol, id, metadata.model.clone());
        let mut keep_lease = tokio::time::interval(Duration::from_mins(1));
        keep_lease.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        keep_lease.tick().await;
        loop {
            let chunk = tokio::select! {
                () = sender.closed() => return,
                _ = keep_lease.tick() => {
                    if let Err(error) = lease.renew().await {
                        send_stream_error(&sender, encoder.error(&error.to_string())).await;
                        return;
                    }
                    continue;
                }
                chunk = chunks.next() => chunk,
            };
            let Some(chunk) = chunk else { break };
            let events = match chunk {
                Ok(chunk) => encoder.chunk(chunk),
                Err(error) => {
                    let (reason, policy) = if matches!(&error,
                        DomainError::DependencyUnavailable { dependency, cause }
                            if dependency == "model-provider" && cause.starts_with("模型流式"))
                    {
                        ("模型上游流式输出超过请求或安全上限", "gateway-output-limit")
                    } else {
                        ("模型流式响应失败", "gateway-stream-error")
                    };
                    if let Err(audit_error) = super::prepared::record_gateway_rejection(
                        &state,
                        &principal,
                        &audit_context,
                        reason,
                        agf_core::enums::PolicyAction::Deny,
                        policy,
                    )
                    .await
                    {
                        tracing::error!(%audit_error, "模型流式拒绝审计写入失败");
                    }
                    drop(chunks);
                    let usage =
                        tokio::time::timeout(Duration::from_secs(5), metadata.usage).await.ok().and_then(Result::ok);
                    if let Err(settle_error) = lease.finish(usage.as_ref()).await {
                        tracing::error!(%settle_error, "模型流式拒绝配额结算失败");
                    }
                    send_stream_error(&sender, encoder.error(reason)).await;
                    return;
                }
            };
            match forward_events(&sender, events, &lease, &mut keep_lease).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    send_stream_error(&sender, encoder.error(&error.to_string())).await;
                    return;
                }
            }
        }
        drop(chunks);
        let usage = tokio::time::timeout(Duration::from_mins(5), metadata.usage).await.ok().and_then(Result::ok);
        if let Err(error) = lease.finish(usage.as_ref()).await {
            send_stream_error(&sender, encoder.error(&error.to_string())).await;
            return;
        }
        for event in encoder.finish() {
            if !matches!(tokio::time::timeout(Duration::from_mins(5), sender.send(Ok(event))).await, Ok(Ok(()))) {
                return;
            }
        }
    });
    let mocked = ready_rx.await.map_err(|_| DomainError::Internal("流式连接任务中断".into()))??;
    let mut response = Sse::new(ReceiverStream::new(receiver)).keep_alive(KeepAlive::default()).into_response();
    response
        .headers_mut()
        .insert("x-agf-mocked", axum::http::HeaderValue::from_static(if mocked { "true" } else { "false" }));
    Ok(response)
}

async fn forward_events(
    sender: &Sender<Result<Event, Infallible>>,
    events: Vec<Event>,
    lease: &crate::gateway_quota::Lease,
    keep_lease: &mut Interval,
) -> agf_core::error::DomainResult<bool> {
    for event in events {
        let send = sender.send(Ok(event));
        tokio::pin!(send);
        let deadline = tokio::time::sleep(Duration::from_mins(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                result = &mut send => {
                    if result.is_err() { return Ok(false); }
                    break;
                }
                _ = keep_lease.tick() => lease.renew().await?,
                () = &mut deadline => return Ok(false),
            }
        }
    }
    Ok(true)
}

async fn send_stream_error(sender: &Sender<Result<Event, Infallible>>, event: Event) {
    let _ = tokio::time::timeout(Duration::from_secs(5), sender.send(Ok(event))).await;
}

//! Shared real streaming pipeline; durable calls retain safe usage across caller loss.
use super::*;

impl AiGateway {
    /// Legacy immediate stream behavior remains available to non-durable internal callers.
    /// # Errors
    /// Request screening, routing or provider connection can reject the stream.
    pub async fn chat_stream_with_metadata(
        &self,
        ctx: CallContext,
        req: ChatRequest,
    ) -> DomainResult<(StreamMetadata, ProviderStream)> {
        self.stream_inner(ctx, req, None).await
    }

    /// Atomic owner entry: no immediate meter writes and no renewed execution window.
    /// # Errors
    /// Reuse, current authority, bounded immutable chain or original deadline can reject dispatch.
    pub async fn chat_stream_deferred(
        &self,
        mut ctx: CallContext,
        req: ChatRequest,
        call: Arc<DeferredCall>,
    ) -> DomainResult<(StreamMetadata, ProviderStream)> {
        call.start()?;
        ctx.budget.max_total_micro = 0;
        call.check().await?;
        self.stream_inner(ctx, req, Some(call)).await
    }

    // -----------------------------------------------------------------------
    // chat_stream
    // -----------------------------------------------------------------------

    /// 流式对话：返回分片流（**末尾必定有一个携带 usage 的结束分片**）。
    ///
    /// 说明：
    /// - 走预筛 → 路由 → 降级，但不做缓存读取（流式无法预知完整响应）；
    /// - 计量在流结束时发生（累积器收尾），并记录 `UsageRecord`；
    /// - 后置过滤对流式内容是"累积后一次性"执行（逐分片过滤会切碎多字节字符）。
    ///
    /// # Errors
    /// 预筛阻断、无可用端点、或首个端点建立连接失败。
    pub async fn chat_stream(&self, ctx: CallContext, req: ChatRequest) -> DomainResult<ProviderStream> {
        self.chat_stream_with_metadata(ctx, req).await.map(|(_, stream)| stream)
    }

    /// 返回实际选中端点与此请求独有的计量回执，避免并发会话串账。
    async fn stream_inner(
        &self,
        ctx: CallContext,
        req: ChatRequest,
        deferred: Option<Arc<DeferredCall>>,
    ) -> DomainResult<(StreamMetadata, ProviderStream)> {
        let prepared = self.prepare_request(&ctx, req)?;
        let req = prepared.request;
        let chain = if let Some(call) = &deferred {
            call.chain(self, &ctx, &req)?
        } else {
            self.router.select(&ctx.routing_context(&req))?
        };
        if let Some(call) = &deferred {
            call.selected(&chain)?;
        }
        if chain.is_empty() {
            return Err(DomainError::Config("无可用模型端点（请检查端点启用状态与数据分级约束）".to_string()));
        }

        // 找到第一个能成功建立流的端点（建立失败则降级）
        let mut last_error: Option<DomainError> = None;
        let mut selected: Option<(ModelEndpoint, ProviderStream, bool, bool)> = None;
        for (index, endpoint) in chain.iter().enumerate() {
            if req.anthropic_native.is_some()
                && endpoint.provider != LlmProvider::Anthropic
                && !self.endpoint_is_mock(endpoint)
            {
                last_error = Some(DomainError::Validation(
                    "原生 Claude 扩展请求只支持 Anthropic 端点；当前候选端点不兼容".into(),
                ));
                continue;
            }
            let provider =
                match if deferred.is_some() { self.deferred_provider(endpoint) } else { self.provider_for(endpoint) } {
                    Ok(p) => p,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                };
            let mocked = self.endpoint_is_mock(endpoint);
            if let Err(error) = ctx.budget.ensure_within_budget_for_request(
                &ctx.tenant.to_string(),
                endpoint,
                &req,
                self.meter.tenant_totals(ctx.tenant).cost_micro,
            ) {
                last_error = Some(error);
                continue;
            }
            let mut outbound = req.clone();
            outbound.model.clone_from(&endpoint.model);
            let connection = if let Some(call) = &deferred {
                call.check().await?;
                call.entered(endpoint.id)?;
                tokio::time::timeout_at(call.deadline(), provider.stream(&outbound))
                    .await
                    .map_err(|_| DomainError::Timeout("Stream connection exhausted original budget".into()))?
            } else {
                provider.stream(&outbound).await
            };
            match connection {
                Ok(stream) => {
                    selected = Some(((*endpoint).clone(), stream, index > 0, mocked));
                    break;
                }
                Err(e) => {
                    if deferred.is_some() {
                        warn!(endpoint_id = %endpoint.id, "Admitted stream connection failed; explicit fallback remains bounded");
                    } else {
                        warn!(endpoint = %endpoint.name, error = %e, "建立流式连接失败，尝试降级");
                    }
                    last_error = Some(e);
                }
            }
        }
        let Some((endpoint, upstream, fallback_used, mocked)) = selected else {
            return Err(last_error.unwrap_or_else(|| DomainError::Config("无可用模型端点".to_string())));
        };

        let started = Instant::now();
        let tenant = ctx.tenant;
        let session_id = ctx.session_id.clone();
        let agent_id = ctx.agent_id;
        let meter = self.meter.clone();
        let screen = self.screen.clone();
        let mut screening = prepared.screening;
        let model = endpoint.model.clone();
        let mock_mode = mocked;
        let max_completion = u64::from(req.max_tokens.unwrap_or(1024));

        let (usage_tx, usage_rx) = tokio::sync::oneshot::channel();
        let metadata = StreamMetadata { endpoint_id: endpoint.id, model: model.clone(), mocked, usage: usage_rx };
        let out = async_stream::stream! {
            let mut acc = StreamAccumulator::new();
            let mut upstream = upstream;
            let mut errored = false;
            let mut received_bytes = 0usize;
            let mut usage_forwarded = false;
            let mut saw_usage = false;
            let mut buffered_native = Vec::new();
            loop {
                let item = if let Some(call) = &deferred {
                    if let Err(error) = call.check().await { yield Err(error); return; }
                    match tokio::time::timeout_at(call.deadline(), upstream.next()).await {
                        Ok(item) => item,
                        Err(_) => { yield Err(DomainError::Timeout("Stream exhausted original budget".into())); return; }
                    }
                } else { upstream.next().await };
                let Some(item) = item else { break };
                match item {
                    Ok(chunk) => {
                        // Capture only numeric usage before any response-buffer rejection.
                        // A rejected oversized body must not erase a provider-reported lower bound.
                        let usage_only = StreamChunk { usage: chunk.usage, ..Default::default() };
                        acc.push(&usage_only);
                        if chunk.usage.is_some() {
                            saw_usage = true;
                            if let Some(call) = &deferred {
                                if let Err(error) = call.observe_partial(crate::meter::UsageInput {
                                    id: call.usage_id(), tenant, session_id: &session_id, agent_id,
                                    endpoint: &endpoint, usage: acc.usage(), cache_hit: false, mocked: mock_mode,
                                    latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                                }) { yield Err(error); return; }
                            }
                        }
                        let canonical_bytes = chunk.delta.tool_calls.iter().fold(chunk.delta.content.len(), |size, call| {
                            size.saturating_add(call.arguments_fragment.len())
                                .saturating_add(call.id.as_ref().map_or(0, String::len))
                                .saturating_add(call.name.as_ref().map_or(0, String::len))
                        });
                        let chunk_bytes = chunk.anthropic_event.as_ref().map_or(canonical_bytes, |raw|
                            serde_json::to_vec(raw).map_or(usize::MAX, |bytes| bytes.len()));
                        received_bytes = received_bytes.saturating_add(chunk_bytes);
                        if received_bytes > 4 * 1024 * 1024 {
                            yield Err(DomainError::DependencyUnavailable {
                                dependency: "model-provider".into(),
                                cause: "模型流式响应超过 4 MiB 安全缓冲上限".into(),
                            });
                            return;
                        }
                        let mut body_only = chunk.clone();
                        body_only.usage = None;
                        acc.push(&body_only);
                        if chunk.usage.is_some_and(|usage| usage.completion_tokens > max_completion) {
                            if let Some(call) = &deferred {
                                call.block_response("gateway-output-limit");
                                if let Some(record) = call.observed_for(endpoint.id) { let _ = usage_tx.send(record); }
                            } else {
                                let record = meter.record(tenant, &session_id, agent_id, &endpoint,
                                    acc.usage(), false, mock_mode,
                                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
                                let _ = usage_tx.send(record);
                            }
                            yield Err(DomainError::DependencyUnavailable {
                                dependency: "model-provider".into(),
                                cause: "模型流式输出超过请求的 max_tokens".into(),
                            });
                            return;
                        }
                        // 开启后置检查时，裁决前不能泄露任何上游正文或工具参数。
                        if screen.is_noop() { usage_forwarded |= chunk.usage.is_some(); yield Ok(chunk); }
                        else if chunk.anthropic_event.is_some() { buffered_native.push(chunk); }
                    }
                    Err(error) => { errored = true; yield Err(error); break; }
                }
            }
            if !errored {
                let mut complete = acc.snapshot(&model);
                if let Some(call) = &deferred {
                    if (saw_usage && acc.finish_reason().is_some()) || mock_mode {
                        if let Err(error) = call.observe_usage(crate::meter::UsageInput {
                            id: call.usage_id(), tenant, session_id: &session_id, agent_id,
                            endpoint: &endpoint, usage: complete.usage, cache_hit: false, mocked: mock_mode,
                            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        }) { yield Err(error); return; }
                    } else {
                        yield Err(DomainError::DependencyUnavailable {
                            dependency: "model-provider".into(),
                            cause: "Stream ended without a complete usage and finish witness".into(),
                        });
                        return;
                    }
                    if let Err(error) = call.check().await { yield Err(error); return; }
                }
                if !screen.is_noop() {
                    let native_view = native_stream_view(&complete, &buffered_native);
                    let outcome = screen.screen_response(native_view.as_ref().unwrap_or(&complete));
                    let native_allowed = native_view.is_some() && matches!(&outcome.verdict, ScreenVerdict::Allow);
                    match outcome.verdict {
                        ScreenVerdict::Block { rule, .. } => {
                            screening.response_rules.push(rule.id.clone());
                            if let Some(call) = &deferred { call.block_response(&rule.id); }
                            complete.message.content = MessageContent::text(crate::screen::safe_response_text(&rule.id));
                            complete.message.tool_calls.clear();
                            complete.finish_reason = crate::wire::FinishReason::ContentFilter;
                        }
                        ScreenVerdict::Redact(_) if native_view.is_some() => {
                            complete.message.content = MessageContent::text(crate::screen::safe_response_text("native-output-redacted"));
                            complete.message.tool_calls.clear();
                            complete.finish_reason = crate::wire::FinishReason::ContentFilter;
                        }
                        ScreenVerdict::Redact(_) => { if let Some(rewritten) = outcome.response { complete = rewritten; } }
                        ScreenVerdict::Allow => {}
                    }
                    if native_allowed {
                        for chunk in buffered_native { yield Ok(chunk); }
                    } else {
                        let calls = complete.message.tool_calls.iter().enumerate().map(|(i, call)|
                            crate::wire::ToolCallDelta { index: u32::try_from(i).unwrap_or(u32::MAX),
                                id: Some(call.id.clone()), name: Some(call.name.clone()),
                                arguments_fragment: call.arguments.to_string() }).collect();
                        yield Ok(StreamChunk { delta: crate::wire::ChatDelta {
                            role: Some(crate::wire::Role::Assistant), content: complete.text_content(), tool_calls: calls,
                        }, ..StreamChunk::default() });
                        yield Ok(StreamChunk::finished(complete.finish_reason, Some(complete.usage)));
                    }
                } else if acc.finish_reason().is_none() {
                    yield Ok(StreamChunk::finished(crate::wire::FinishReason::Stop, (!usage_forwarded).then(|| acc.usage())));
                } else if !usage_forwarded {
                    yield Ok(StreamChunk { delta: crate::wire::ChatDelta::default(),
                        finish_reason: None, usage: Some(acc.usage()), anthropic_event: None });
                }
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                if let Some(call) = &deferred {
                    if let Some(record) = call.observed_for(endpoint.id) { let _ = usage_tx.send(record); }
                } else {
                    let record = meter.record(tenant, &session_id, agent_id, &endpoint,
                        complete.usage, false, mock_mode, latency_ms);
                    let _ = usage_tx.send(record);
                }
                debug!(?fallback_used, "流式调用结束并已计量");
            }
        };
        Ok((metadata, Box::pin(out)))
    }
}

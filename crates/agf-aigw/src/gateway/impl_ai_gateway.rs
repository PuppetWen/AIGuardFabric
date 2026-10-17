//! 由 `gateway.rs` 拆分：`AiGateway` 的实现（纯搬移，逻辑不变）。
use super::*;
use sha2::{Digest, Sha256};

impl AiGateway {
    pub(crate) async fn chat_inner(
        &self,
        ctx: CallContext,
        req: ChatRequest,
        mut screening: ScreeningSummary,
        started: Instant,
        deferred: Option<&DeferredCall>,
    ) -> DomainResult<GatewayResponse> {
        let chain = if let Some(call) = deferred {
            call.chain(self, &ctx, &req)?
        } else {
            self.router.select(&ctx.routing_context(&req))?
        };
        if let Some(call) = deferred {
            call.selected(&chain)?;
        }
        if chain.is_empty() {
            return Err(DomainError::Config("无可用模型端点（请检查端点启用状态与数据分级约束）".to_string()));
        }

        let max_completion = u64::from(req.max_tokens.unwrap_or(1024));

        // ---- 缓存查询（仅精确指纹）----
        let candidate = self.pick_cache_candidate(&ctx, &req, &chain);
        if let Some((endpoint, fingerprint)) = &candidate {
            match self.cache.get(ctx.tenant, fingerprint).await {
                Ok(Some(hit)) if hit.endpoint_id == endpoint.id => {
                    let mut response = hit.response;
                    if let Some(call) = deferred {
                        call.check().await?;
                    }
                    if let Some(call) = deferred {
                        call.observe_usage(crate::meter::UsageInput {
                            id: call.usage_id(),
                            tenant: ctx.tenant,
                            session_id: &ctx.session_id,
                            agent_id: ctx.agent_id,
                            endpoint,
                            usage: response.usage,
                            cache_hit: true,
                            mocked: false,
                            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        })?;
                    }
                    screening = self.process_response(&mut response, screening, max_completion)?;
                    let saved = breakdown(endpoint, &response.usage);
                    let usage = response.usage;
                    let record = self.record_usage(
                        deferred,
                        crate::meter::UsageInput {
                            id: deferred.map_or_else(Id::nil, DeferredCall::usage_id),
                            tenant: ctx.tenant,
                            session_id: &ctx.session_id,
                            agent_id: ctx.agent_id,
                            endpoint,
                            usage,
                            cache_hit: true,
                            mocked: false,
                            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        },
                    )?;
                    info!(
                        endpoint = %endpoint.name,
                        saved_micro = saved.total_micro,
                        "语义缓存命中，跳过上游调用"
                    );
                    return Ok(GatewayResponse {
                        response,
                        endpoint_id: endpoint.id,
                        provider: endpoint.provider,
                        model: endpoint.model.clone(),
                        usage,
                        cost_micro: 0,
                        cost: CostBreakdown::default(),
                        cached: true,
                        mocked: false,
                        fallback_used: false,
                        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        screening,
                        usage_record: record,
                    });
                }
                Ok(Some(hit)) => {
                    warn!(cached_endpoint = %hit.endpoint_id, selected_endpoint = %endpoint.id, "缓存条目端点不匹配，忽略命中");
                }
                Ok(None) => debug!("语义缓存未命中"),
                Err(e) => warn!(error = %e, "语义缓存读取失败（不影响主流程）"),
            }
        }

        // ---- 逐端点调用 + 降级 ----
        let mut last_error: Option<DomainError> = None;
        let mut fallback_used = false;
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
            if index > 0 {
                fallback_used = true;
                debug!(endpoint = %endpoint.name, "沿降级链切换端点");
            }
            if let Err(e) = ctx.budget.ensure_within_budget_for_request(
                ctx.tenant.to_string().as_str(),
                endpoint,
                &req,
                self.meter.tenant_totals(ctx.tenant).cost_micro,
            ) {
                warn!(endpoint = %endpoint.name, error = %e, "预算守卫拒绝本次调用");
                last_error = Some(e);
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

            let mut outbound = req.clone();
            outbound.model.clone_from(&endpoint.model);
            if let Some(call) = deferred {
                call.check().await?;
                call.entered(endpoint.id)?;
            }
            let completion = if let Some(call) = deferred {
                tokio::time::timeout_at(call.deadline(), provider.complete(&outbound))
                    .await
                    .map_err(|_| DomainError::Timeout("Deferred model attempt exhausted its original budget".into()))?
            } else {
                provider.complete(&outbound).await
            };
            match completion {
                Ok(mut response) => {
                    if let Some(call) = deferred {
                        call.observe_usage(crate::meter::UsageInput {
                            id: call.usage_id(),
                            tenant: ctx.tenant,
                            session_id: &ctx.session_id,
                            agent_id: ctx.agent_id,
                            endpoint,
                            usage: response.usage,
                            cache_hit: false,
                            mocked,
                            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        })?;
                    }
                    screening = self.process_response(&mut response, screening, max_completion)?;
                    let usage = response.usage;
                    let cost = if mocked { CostBreakdown::default() } else { breakdown(endpoint, &usage) };
                    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let record = self.record_usage(
                        deferred,
                        crate::meter::UsageInput {
                            id: deferred.map_or_else(Id::nil, DeferredCall::usage_id),
                            tenant: ctx.tenant,
                            session_id: &ctx.session_id,
                            agent_id: ctx.agent_id,
                            endpoint,
                            usage,
                            cache_hit: false,
                            mocked,
                            latency_ms,
                        },
                    )?;
                    // 降级端点的回复不能以首选端点身份返回给下一次请求。
                    if candidate.as_ref().is_some_and(|(first, _)| first.id == endpoint.id) {
                        if let Some(call) = deferred {
                            call.hold_cache(ctx.clone(), req.clone(), (*endpoint).clone(), response.clone());
                        } else {
                            self.write_cache(&ctx, &req, endpoint, &response).await;
                        }
                    }
                    self.session_affinity.lock().insert(ctx.session_id.clone(), endpoint.id);
                    return Ok(GatewayResponse {
                        response,
                        endpoint_id: endpoint.id,
                        provider: endpoint.provider,
                        model: endpoint.model.clone(),
                        usage,
                        cost_micro: cost.total_micro,
                        cost,
                        cached: false,
                        mocked,
                        fallback_used,
                        latency_ms,
                        screening,
                        usage_record: record,
                    });
                }
                Err(e) => {
                    if deferred.is_some() {
                        warn!(endpoint_id = %endpoint.id, "Admitted model dispatch failed; explicit fallback remains bounded");
                    } else {
                        warn!(endpoint = %endpoint.name, error = %e, "端点调用失败，尝试降级");
                    }
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| DomainError::Config("无可用模型端点".to_string())))
    }
    /// 选择"可用于缓存查询"的端点（必须满足 `is_cacheable`）。
    // `&self` 为未来扩展（按端点级缓存开关过滤）保留，当前实现不读实例状态
    #[allow(clippy::unused_self)]
    pub(crate) fn pick_cache_candidate(
        &self,
        ctx: &CallContext,
        req: &ChatRequest,
        chain: &[&ModelEndpoint],
    ) -> Option<(ModelEndpoint, String)> {
        let endpoint = chain.first()?;
        // 先按 CallContext 的分级写入 metadata，再做可缓存性判定（判定依赖 metadata）
        let mut probe = req.clone();
        probe.metadata.insert("data_class".into(), ctx.data_class.as_str().to_string());
        if ctx.disable_cache || !is_cacheable(&probe, endpoint, ctx.allow_cache) {
            return None;
        }
        Some(((*endpoint).clone(), Self::cache_fingerprint(&probe, endpoint)?))
    }
    /// 将端点配置纳入键。改模型、地址、凭据引用或价格后，旧回复不会继续命中。
    fn cache_fingerprint(req: &ChatRequest, endpoint: &ModelEndpoint) -> Option<String> {
        let mut hasher = Sha256::new();
        hasher.update(req.fingerprint());
        hasher.update(req.data_class_hint().unwrap_or(DataClass::Internal).as_str());
        hasher.update(serde_json::to_vec(endpoint).ok()?);
        Some(hex::encode(hasher.finalize()))
    }
    /// 命中缓存则写入（失败只告警，不影响主流程）。
    pub(crate) async fn write_cache(
        &self,
        ctx: &CallContext,
        req: &ChatRequest,
        endpoint: &ModelEndpoint,
        response: &ChatResponse,
    ) {
        let mut probe = req.clone();
        probe.metadata.insert("data_class".into(), ctx.data_class.as_str().to_string());
        if ctx.disable_cache || !should_write_cache(&probe, endpoint, ctx.allow_cache, response) {
            return;
        }
        let entry = CachedResponse::from_response(
            ctx.tenant,
            match Self::cache_fingerprint(&probe, endpoint) {
                Some(fingerprint) => fingerprint,
                None => return,
            },
            endpoint,
            response.clone(),
            crate::cache::DEFAULT_TTL_SECS,
        );
        if let Err(e) = self.cache.put(entry, crate::cache::DEFAULT_TTL_SECS).await {
            warn!(error = %e, "语义缓存写入失败（不影响主流程）");
        }
    }
    // -----------------------------------------------------------------------
    // analyze（Prompt 模板 + 分析模型）
    // -----------------------------------------------------------------------

    /// 渲染 Prompt 模板（`{{var}}`）——**复用** `agf_core::skill::PromptTemplate` 的变量抽取。
    ///
    /// # Errors
    /// 模板不存在或缺少必需变量时返回 `DomainError::Validation`。
    pub fn render_prompt(&self, prompt_name: &str, vars: &BTreeMap<String, String>) -> DomainResult<String> {
        let template = self
            .prompts
            .get(prompt_name)
            .ok_or_else(|| DomainError::NotFound { entity: "prompt_template", id: prompt_name.to_string() })?;
        render_template(template, vars)
    }
    /// 分析入口：渲染模板 → 调用分析模型 → 返回纯文本。
    ///
    /// 用于"告警研判 / 攻击链路总结 / 报告生成"三类离线可演示场景。
    ///
    /// # Errors
    /// 模板缺失/变量缺失、内容安全阻断、全部端点失败。
    pub async fn analyze(
        &self,
        ctx: CallContext,
        prompt_name: &str,
        vars: &BTreeMap<String, String>,
    ) -> DomainResult<String> {
        let text = self.render_prompt(prompt_name, vars)?;
        let model = self
            .analysis_model
            .clone()
            .or_else(|| self.router.endpoints().first().map(|e| e.model.clone()))
            .unwrap_or_else(|| crate::mock::MOCK_MODEL.to_string());
        let req = ChatRequest::simple(model, text);
        let response = self.chat(ctx, req).await?;
        Ok(response.response.text_content())
    }
}

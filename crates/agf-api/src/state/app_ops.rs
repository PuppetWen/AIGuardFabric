//! `AppState` 的运行期操作（发布事件、NATS、API Key、审计、未实现端点）（自 `state.rs` 拆出）。

use super::*;

impl AppState {
    /// 默认 JWT issuer 名。
    #[must_use]
    pub fn jwt_issuer_name(&self) -> &str {
        if self.config.security.jwt_issuer.is_empty() { JWT_ISSUER } else { &self.config.security.jwt_issuer }
    }

    /// 广播事件（多副本部署下经 NATS，单机部署走进程内广播）。
    ///
    /// **投递语义**（见模块文档的"事件面"一节）：
    ///
    /// - NATS 面可用：入队交给 [`NatsEventPlane`] 投递到 `agf.ws.<tenant>.<kind>`，
    ///   本副本的 `/ws` 由**订阅泵回灌**（因此本副本的事件也真的过了 NATS，与其它副本同一条路径）；
    /// - 未启用 / 已降级 / 队列满 / 序列化失败：**立即退回进程内广播**（事件不丢，
    ///   只是跨副本不可见），并计入 `agf_ws_local_fallback_total`；
    /// - 无订阅者（没有 `/ws` 连接）时静默丢弃，与既有进程内广播语义一致。
    pub fn publish(&self, event: WsEvent) {
        if let Some(plane) = &self.nats {
            if plane.try_publish(&event) {
                return;
            }
        }
        let _ = self.events.send(event);
    }

    /// 按配置装配 `/ws` 的 NATS 事件面（`AGF_NATS_ENABLED` / `AGF_NATS_URL`）。
    ///
    /// **降级铁律**：连接失败只 `warn` + 追加 `notes`（`/readyz` 可见）并保持进程内广播，
    /// 绝不返回错误、绝不阻断启动、绝不让 `/ws` 不可用。`AGF_NATS_ENABLED=0` 时不发起任何连接。
    #[must_use]
    pub async fn attach_nats_events(self) -> Self {
        let enabled = self.config.nats.enabled;
        let url = self.config.nats.url.clone();
        self.attach_nats_events_with(enabled, &url).await
    }

    /// [`Self::attach_nats_events`] 的显式参数版本（测试与多环境脚本用；不读环境变量）。
    #[must_use]
    pub async fn attach_nats_events_with(mut self, enabled: bool, url: &str) -> Self {
        let mut notes = self.notes.as_ref().clone();
        if !enabled {
            notes.push(format!(
                "AGF_NATS_ENABLED=0：/ws 事件走进程内广播（写入 `{}` 主题的事件不跨副本分发）",
                crate::ws::wildcard_subject()
            ));
            info!("AGF_NATS_ENABLED=0：/ws 使用进程内广播（多副本事件不互通）");
            self.notes = Arc::new(notes);
            return self;
        }
        let url = url.trim();
        if url.is_empty() {
            warn!("AGF_NATS_ENABLED=1 但 AGF_NATS_URL 为空：/ws 退回进程内广播");
            notes.push("AGF_NATS_ENABLED=1 但 AGF_NATS_URL 为空：/ws 已退回进程内广播（多副本不互通）".to_string());
            self.notes = Arc::new(notes);
            return self;
        }
        let endpoint = agf_ingest::bus::nats_endpoint_label(url);
        match NatsEventPlane::connect(url, self.events.clone(), Arc::clone(&self.metrics)).await {
            Ok(plane) => {
                info!(
                    endpoint = %endpoint,
                    subject = %crate::ws::wildcard_subject(),
                    "NATS 事件面已装配：/ws 事件经 NATS 跨副本分发"
                );
                notes.push(format!(
                    "NATS 事件总线已连接（{endpoint}，主题 {}）：/ws 事件经 NATS 分发，多副本互通",
                    crate::ws::wildcard_subject()
                ));
                self.nats = Some(plane);
            }
            Err(error) => {
                warn!(error = %error, endpoint = %endpoint, "NATS 不可达：/ws 退回进程内广播（服务继续启动）");
                notes.push(format!("NATS {endpoint} 不可达（{error}）：/ws 已退回进程内广播，多副本事件不互通"));
            }
        }
        self.notes = Arc::new(notes);
        self
    }

    /// 事件面名称（`nats` = 经 NATS 分发；`local` = 进程内广播）。
    ///
    /// 用于 `/ws` 的 `hello` 帧与自检：**已降级的 NATS 面同样报 `local`**，
    /// 因为事件此时确实只在本进程内流转。
    #[must_use]
    pub fn event_plane_name(&self) -> &'static str {
        match &self.nats {
            Some(plane) if !plane.is_degraded() => "nats",
            _ => "local",
        }
    }

    /// 记录一次运行时拦截（指标 + 广播）。
    pub fn record_interception(&self, tenant: TenantId, action: PolicyAction, policy: &str) {
        self.metrics.record_interception(action.as_str());
        self.publish(WsEvent {
            kind: "interception".to_string(),
            tenant_id: tenant,
            at: Timestamp::now(),
            payload: serde_json::json!({ "action": action.as_str(), "policy": policy }),
        });
    }

    /// 校验某个 API Key 明文（`X-AGF-Key`）。
    ///
    /// # Errors
    /// 前缀非法、Key 不存在、指纹不匹配、已吊销/过期/来源不允许。
    pub async fn verify_api_key(
        &self,
        plaintext: &str,
        source_ip: Option<&str>,
    ) -> DomainResult<agf_core::rbac::ApiKey> {
        let prefix = self.api_keys.extract_prefix(plaintext)?;
        let Some(candidate) = self.store.api_key_by_prefix_durable(&prefix).await? else {
            return Err(DomainError::Unauthenticated("API Key 无效".to_string()));
        };
        // The verified secret authenticates the identity bound by the administrator.
        // Callers cannot choose another Agent; request hints are checked against this binding.
        self.api_keys.validate(
            &candidate,
            plaintext,
            source_ip,
            candidate.bound_agent_id.as_ref(),
            Timestamp::now(),
        )?;
        Ok(candidate)
    }

    /// 创建引导管理员（幂等：已存在直接返回）。
    ///
    /// # Errors
    /// 口令策略不通过或存储错误。
    pub async fn ensure_bootstrap_admin(
        &self,
        tenant: TenantId,
        username: &str,
        email: &str,
        explicit_password: Option<&str>,
        force_password_change: bool,
    ) -> DomainResult<BootstrapOutcome> {
        if let Some(existing) = self.auth_backend.find_user_with_secret(tenant, username).await? {
            return Ok(BootstrapOutcome::AlreadyExists { user: existing.user });
        }
        let (password, generated) = match explicit_password {
            Some(p) if !p.is_empty() => (p.to_string(), None),
            _ => (self.auth.hasher().generate_initial_password(), Some(true)),
        };
        let phc = self.auth.hasher().hash_checked(&password, username)?;
        let mut user = User::new_local(tenant, username, email);
        user.must_change_password = force_password_change;
        user.is_superadmin = true;
        self.auth_backend.save_account(&user, Some(&phc), &[builtin::SUPERADMIN.to_string()]).await?;
        info!(username, force_password_change, "已创建引导管理员（口令不打印）");
        Ok(BootstrapOutcome::Created { user, generated_password: generated.map(|_| password) })
    }

    /// 写审计（数据库模式先提交哈希链；离线模式使用进程内链）。
    ///
    /// # Errors
    /// 持久化或内存链写入失败。
    pub async fn audit(
        &self,
        tenant: TenantId,
        action: agf_core::audit::AuditAction,
        outcome: agf_core::audit::AuditOutcome,
        actor: agf_core::audit::AuditActor,
        target: agf_core::audit::AuditTarget,
        note: &str,
    ) -> DomainResult<agf_core::audit::AuditLog> {
        let entry = Self::audit_entry(tenant, action, outcome, actor, target, note);
        self.store.audit_append_durable(entry).await
    }

    /// Construct a success or failure audit for callers that commit it with business data.
    #[must_use]
    pub fn audit_entry(
        tenant: TenantId,
        action: agf_core::audit::AuditAction,
        outcome: agf_core::audit::AuditOutcome,
        actor: agf_core::audit::AuditActor,
        target: agf_core::audit::AuditTarget,
        note: &str,
    ) -> agf_core::audit::AuditLog {
        agf_core::audit::AuditLog {
            id: Id::new(),
            tenant_id: tenant,
            sequence: 0,
            action,
            outcome,
            actor,
            target,
            before: None,
            after: None,
            changed_fields: Vec::new(),
            request_id: crate::error::current_request_id(),
            error: None,
            note: note.to_string(),
            prev_hash: String::new(),
            entry_hash: String::new(),
            at: Timestamp::now(),
        }
    }

    /// 由请求构造审计主体。
    #[must_use]
    pub fn audit_actor(principal: &crate::middleware::Principal, name: &str) -> agf_core::audit::AuditActor {
        agf_core::audit::AuditActor {
            id: principal.subject_id,
            kind: principal.subject_kind.as_str().to_string(),
            name: name.to_string(),
            source_ip: principal.source_ip.clone(),
            user_agent: principal.user_agent.clone(),
            session_id: principal.session_id.clone(),
        }
    }
}

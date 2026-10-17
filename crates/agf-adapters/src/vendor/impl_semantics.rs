//! 由 `vendor.rs` 拆分：`push` / `pull` / `sync` 三条语义的运行时。
//!
//! 三条语义共用同一条横切链路，**厂商无法绕过**（对齐 spec §2.6 的硬约束）：
//!
//! ```text
//! 能力判定（Unsupported ⇒ 不可重试的 Validation，带原因）
//!      ↓
//! 模式判定（Mocked ⇒ 确定性降级结果；Unconfigured ⇒ Config 错误列出缺项）
//!      ↓
//! 纯函数编码（VendorSpec::encode_push / encode_pull）
//!      ↓
//! 熔断 + 重试（VendorAdapterImpl::invoke → invoke_with_policy）
//!      ↓
//! 真实往返（VendorSpec::invoke_push / invoke_pull → http::execute）
//!      ↓
//! 纯函数解析（parse_push_response / parse_pull）
//!      ↓
//! 增量去重（pull）/ 冲突裁决与决策日志（sync）
//! ```
//!
//! `sync` **不实现第三套逻辑**：它就是"`pull` 增量 → 逐条与本地快照比对 →
//! 按 [`ConflictPolicy`] 裁决 → 需要时走同一条 `push` 链路"的组合。

use super::*;
use crate::vendor::reconcile::{ReconcileDecision, reconcile};

impl<V: VendorSpec> VendorAdapterImpl<V> {
    /// 语义不可用时的如实错误。
    ///
    /// 1. 档位 `Implemented` 却走到这里 ⇒ `Internal`（实现漏覆盖，是缺陷不是"不支持"）；
    /// 2. 档位为"未登记"或适配器是脚手架（`REAL_TRANSPORT=false`）⇒ `NotImplemented` + TODO 锚点；
    /// 3. 其余（已实现真实传输的内置适配器，档位为 `Unsupported`）⇒ `Validation` + 不适用原因。
    fn semantic_error(semantic: Semantic) -> DomainError {
        V::semantic_error(semantic)
    }

    /// Mock 回写回执 id（确定性派生；同 `entity_id` + 同幂等键 ⇒ 同 id）。
    fn mock_push_id(payload: &PushPayload) -> String {
        let seed =
            format!("{}|{}|{}", payload.entity, payload.entity_id, payload.idempotency_key.clone().unwrap_or_default());
        format!("mock-push-{}", crate::transport::deterministic_token(V::NAME, &seed))
    }

    /// 增量窗口的键（`resource` 为空时归一为 `default`，避免空键互相污染）。
    fn window_key(req: &PullRequest) -> String {
        let resource = req.resource.trim();
        if resource.is_empty() { "default".to_string() } else { resource.to_ascii_lowercase() }
    }

    /// 状态回写（平台 → 外部已存在的对象）。
    pub(crate) async fn push_semantic(&self, payload: &PushPayload) -> DomainResult<PushOutcome> {
        self.ensure_open()?;
        if !V::push_support().is_implemented() {
            return Err(Self::semantic_error(Semantic::Push));
        }
        match self.core.mode {
            AdapterMode::Mocked => {
                // Mock 不依赖真实 endpoint/凭据（Config 属计划内降级）；载荷本身的问题必须暴露
                if let Err(error) = V::encode_push(payload, &self.core.settings) {
                    if !matches!(error, DomainError::Config(_)) {
                        return Err(error);
                    }
                }
                Ok(PushOutcome::mocked(V::NAME, Self::mock_push_id(payload)))
            }
            AdapterMode::Unconfigured => Err(self.unconfigured_error()),
            AdapterMode::Live => self.push_live(payload).await,
        }
    }

    /// Live 回写：编码 → 熔断 + 重试 → 回执。
    async fn push_live(&self, payload: &PushPayload) -> DomainResult<PushOutcome> {
        let settings = self.settings_arc();
        let requests = Arc::new(V::encode_push(payload, &settings)?);
        let request_count = requests.len();
        let origin = requests.first().map_or_else(|| settings.adapter.clone(), VendorRequest::masked_endpoint);
        let requests_for_op = Arc::clone(&requests);
        let settings_for_op = Arc::clone(&settings);
        let started = std::time::Instant::now();
        let (result, attempts) = self
            .invoke(move |_attempt| {
                let reqs = Arc::clone(&requests_for_op);
                let cfg = Arc::clone(&settings_for_op);
                async move { V::invoke_push(&reqs, &cfg).await }
            })
            .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(remote_id) => {
                self.note_success(attempts, elapsed_ms);
                Ok(PushOutcome::new(request_count, remote_id, attempts, elapsed_ms, origin))
            }
            Err(error) => {
                self.note_failure(&error, attempts, elapsed_ms);
                Err(error)
            }
        }
    }

    /// 增量读取（外部 → 平台）。
    pub(crate) async fn pull_semantic(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        self.ensure_open()?;
        if !V::pull_support().is_implemented() {
            return Err(Self::semantic_error(Semantic::Pull));
        }
        match self.core.mode {
            AdapterMode::Mocked => {
                if let Err(error) = V::encode_pull(req, &self.core.settings) {
                    if !matches!(error, DomainError::Config(_)) {
                        return Err(error);
                    }
                }
                Ok(PullResponse {
                    items: Vec::new(),
                    next_cursor: None,
                    mocked: true,
                    origin: format!("mock://{}?resource={}", V::NAME, req.resource),
                })
            }
            AdapterMode::Unconfigured => Err(self.unconfigured_error()),
            AdapterMode::Live => self.pull_live(req).await,
        }
    }

    /// Live 拉取：编码 → 熔断 + 重试 → 解析 → **增量去重** → 推进游标。
    async fn pull_live(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let settings = self.settings_arc();
        let request = Arc::new(V::encode_pull(req, &settings)?);
        let origin = request.masked_endpoint();
        let pull = Arc::new(req.clone());
        let request_for_op = Arc::clone(&request);
        let pull_for_op = Arc::clone(&pull);
        let settings_for_op = Arc::clone(&settings);
        let started = std::time::Instant::now();
        let (result, attempts) = self
            .invoke(move |_attempt| {
                let req = Arc::clone(&request_for_op);
                let pull = Arc::clone(&pull_for_op);
                let cfg = Arc::clone(&settings_for_op);
                async move { V::invoke_pull(&req, &pull, &cfg).await }
            })
            .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(page) => {
                self.note_success(attempts, elapsed_ms);
                let key = Self::window_key(req);
                let mut window = self.pull_window(&key);
                let (fresh, duplicates) = window.accept(&page);
                let next_cursor = window.advance(&page, &fresh);
                let delivered = fresh.len();
                let seen = window.seen_count();
                self.store_pull_window(&key, window);
                if duplicates > 0 {
                    tracing::debug!(
                        adapter = V::NAME,
                        resource = %key,
                        duplicates,
                        delivered,
                        seen,
                        "增量拉取去重：上游重复返回的条目未二次交付"
                    );
                }
                Ok(PullResponse { items: fresh, next_cursor, mocked: false, origin })
            }
            Err(error) => {
                self.note_failure(&error, attempts, elapsed_ms);
                Err(error)
            }
        }
    }

    /// 双向对账（`pull` → 比对本地快照 → 需要时 `push`）。
    pub(crate) async fn sync_semantic(&self, req: &SyncRequest) -> DomainResult<SyncOutcome> {
        self.ensure_open()?;
        if !V::sync_support().is_implemented() {
            return Err(Self::semantic_error(Semantic::Sync));
        }
        if !V::pull_support().is_implemented() || !V::push_support().is_implemented() {
            // `sync` = `pull` + `push` 组合：声明了 sync 却没声明两侧是登记矛盾，明确报缺陷
            return Err(DomainError::Internal(format!(
                "{}：sync 已登记为 Implemented，但 pull/push 未同时登记（能力登记矛盾）",
                V::NAME
            )));
        }
        match self.core.mode {
            AdapterMode::Mocked => {
                let mut outcome = SyncOutcome {
                    mocked: true,
                    degraded: true,
                    finished_at: Some(Timestamp::now()),
                    ..SyncOutcome::default()
                };
                outcome
                    .warnings
                    .push(format!("{}：Mock 模式返回确定性降级结果，未触达真实外部系统（AGF_MOCK_MODE）", V::NAME));
                outcome.changes.insert("mocked".to_string(), 1);
                Ok(outcome)
            }
            AdapterMode::Unconfigured => Err(self.unconfigured_error()),
            AdapterMode::Live => self.sync_live(req).await,
        }
    }

    /// Live 对账：拉增量 → 逐条裁决（含冲突策略与决策日志）→ 回写差异 → 汇总。
    async fn sync_live(&self, req: &SyncRequest) -> DomainResult<SyncOutcome> {
        let started = std::time::Instant::now();
        let policy = req.conflict_policy.unwrap_or_else(|| ConflictPolicy::from_settings(&self.core.settings));
        let pull_request = PullRequest {
            resource: req.resource.clone(),
            filter: req.filters.clone(),
            cursor: req.cursor.clone(),
            limit: req.limit,
        };
        let response = self.pull_semantic(&pull_request).await?;

        let mut outcome = SyncOutcome { pulled: response.items.len(), ..SyncOutcome::default() };
        outcome.changes.insert("pulled".to_string(), response.items.len());
        outcome.warnings.push(format!(
            "sync 策略：{}（{}）；拉取 {} 条，本地快照 {} 条",
            policy.as_str(),
            policy.display_name(),
            response.items.len(),
            req.local.len()
        ));

        for item in &response.items {
            let Some(remote_id) = item_remote_id(item) else {
                outcome.skipped += 1;
                outcome.warnings.push("sync 决策[?] 无法从外部条目解析远端 id，跳过（不回写）".to_string());
                continue;
            };
            let external_updated = item_updated_at(item);
            let external_state = item_state(item);
            match req.local_snapshot(&remote_id) {
                None => {
                    *outcome.changes.entry("external_only".to_string()).or_insert(0) += 1;
                    outcome
                        .warnings
                        .push(format!("sync 决策[{remote_id}] external-only：本地无对应案件，交付上游状态且不回写"));
                }
                Some(local) => {
                    let decision = reconcile(external_updated, local.updated_at, local.state != external_state, policy);
                    let note = format!(
                        "sync 决策[{remote_id}] {}：外部更新={} 本地更新={} 策略={}——{}",
                        decision.as_str(),
                        stamp_text(external_updated),
                        stamp_text(local.updated_at),
                        policy.as_str(),
                        decision.log_text()
                    );
                    tracing::info!(adapter = V::NAME, decision = decision.as_str(), record_id = %remote_id, "{}", note);
                    outcome.warnings.push(note);
                    Self::apply_decision(&mut outcome, decision, policy, &remote_id, &local.state);
                    if decision.should_push() {
                        match self.sync_push(&remote_id, &local.state).await {
                            Ok(()) => outcome.pushed += 1,
                            Err(error) => {
                                outcome.failed += 1;
                                outcome.warnings.push(format!("sync：{remote_id} 回写失败——{error}"));
                            }
                        }
                    }
                }
            }
        }

        for local in &req.local {
            let present =
                response.items.iter().any(|item| item_remote_id(item).as_deref() == Some(local.remote_id.as_str()));
            if !present {
                *outcome.changes.entry("local_only".to_string()).or_insert(0) += 1;
                outcome.warnings.push(format!(
                    "sync 决策[{}] local-only：外部未返回该对象，不新建也不回写（外部为准）",
                    local.remote_id
                ));
            }
        }

        outcome.degraded = outcome.failed > 0;
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        outcome.finished_at = Some(Timestamp::now());
        Ok(outcome)
    }

    /// 记录裁决计数（决策日志的计数侧；日志文本由上一步写入 warnings）。
    fn apply_decision(
        outcome: &mut SyncOutcome,
        decision: ReconcileDecision,
        policy: ConflictPolicy,
        remote_id: &str,
        state: &serde_json::Value,
    ) {
        match decision {
            ReconcileDecision::Skip => outcome.skipped += 1,
            ReconcileDecision::TakeExternal => {
                *outcome.changes.entry("take_external".to_string()).or_insert(0) += 1;
            }
            ReconcileDecision::PushLocal => {
                *outcome.changes.entry("push_local".to_string()).or_insert(0) += 1;
            }
            ReconcileDecision::ConflictExternalWins => {
                outcome.skipped += 1;
                *outcome.changes.entry(format!("conflict_{}", policy.as_str())).or_insert(0) += 1;
            }
            ReconcileDecision::ConflictLocalWins => {
                *outcome.changes.entry(format!("conflict_{}", policy.as_str())).or_insert(0) += 1;
            }
        }
        tracing::debug!(adapter = V::NAME, record_id = %remote_id, state = %state, "sync 裁决已记录");
    }

    /// `sync` 的回写：复用同一条 `push` 链路（幂等键由"对象 id + 状态"确定性派生）。
    async fn sync_push(&self, remote_id: &str, state: &serde_json::Value) -> DomainResult<()> {
        let payload = PushPayload {
            entity: V::SYNC_PUSH_ENTITY.to_string(),
            entity_id: remote_id.to_string(),
            body: state.clone(),
            idempotency_key: Some(crate::transport::deterministic_token(
                "agf-sync",
                &format!("{}|{remote_id}|{state}", V::NAME),
            )),
        };
        self.push_semantic(&payload).await.map(|_| ())
    }

    /// `sync` 的方向桥接（`agf_core::adapter::Adapter::sync(direction, req)` 用）。
    ///
    /// - `Pull`：只拉取（`local` 快照缺省为空 ⇒ 不做任何回写）；
    /// - `Push`：只回写（不发拉取请求）；
    /// - `Both`：拉取 + 比对 + 回写差异。
    pub(crate) async fn sync_direction(
        &self,
        direction: SyncDirection,
        req: &SyncRequest,
    ) -> DomainResult<SyncOutcome> {
        match direction {
            SyncDirection::Both => self.sync_semantic(req).await,
            SyncDirection::Pull => self.sync_semantic(&req.clone().with_local(Vec::new())).await,
            SyncDirection::Push => {
                self.ensure_open()?;
                if !V::sync_support().is_implemented() || !V::push_support().is_implemented() {
                    return Err(Self::semantic_error(Semantic::Push));
                }
                let started = std::time::Instant::now();
                let mut outcome = SyncOutcome::default();
                for local in &req.local {
                    match self.sync_push(&local.remote_id, &local.state).await {
                        Ok(()) => {
                            outcome.pushed += 1;
                            outcome
                                .warnings
                                .push(format!("sync(push 方向)[{}] 已回写本地状态（未拉取外部）", local.remote_id));
                        }
                        Err(error) => {
                            outcome.failed += 1;
                            outcome.warnings.push(format!("sync(push 方向)[{}] 回写失败——{error}", local.remote_id));
                        }
                    }
                }
                if req.local.is_empty() {
                    outcome.warnings.push("sync(push 方向) 本地快照为空：无可回写条目".to_string());
                }
                outcome.degraded = outcome.failed > 0;
                outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                outcome.finished_at = Some(Timestamp::now());
                Ok(outcome)
            }
        }
    }
}

/// 时间戳文本（决策日志用；缺省为 `-`）。
fn stamp_text(stamp: Option<Timestamp>) -> String {
    stamp.map_or_else(|| "-".to_string(), |value| value.to_rfc3339())
}

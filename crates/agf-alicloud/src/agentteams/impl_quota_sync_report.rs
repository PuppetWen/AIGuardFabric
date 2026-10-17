//! 由 `agentteams.rs` 拆分：`impl_QuotaSyncReport`/`impl_TeamSyncReport` 等 7 项（纯搬移，逻辑不变）。
use super::*;

impl QuotaSyncReport {
    /// 本次是否产生了新的冲突告警。
    #[must_use]
    pub fn has_conflict(&self) -> bool {
        !self.conflict_alerts.is_empty()
    }

    /// 处于冲突状态的维度数。
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.states.iter().filter(|state| state.conflict).count()
    }
}

impl TeamSyncReport {
    /// 纳管率。
    #[must_use]
    pub fn managed_ratio(&self) -> f32 {
        if self.total_agents == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.managed_agents as f32 / self.total_agents as f32
        }
    }
}

/// Complete definition fingerprint; set ordering and ordinary observation timestamps are ignored.
///
/// Member identity, exact asset mapping, models/tools/roles and every declared DAG field are retained.
#[must_use]
pub fn team_content_signature(team: &AgentTeam) -> String {
    super::definition_signature::fingerprint(team)
}

impl std::fmt::Debug for AgentTeamsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentTeamsAdapter")
            .field("core", &self.core)
            .field("has_client", &self.client.is_some())
            .field("transport", &"<transport-double>")
            .field("quota_state", &"<quota-state>")
            .finish_non_exhaustive()
    }
}

impl Default for AgentTeamsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentTeamsAdapter {
    /// 未配置态构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: AdapterCore::new(AliCloudService::AgentTeams),
            instance_id: String::new(),
            worker_name: String::new(),
            quota_period: String::new(),
            client: None,
            transport: null_transport(),
            quota_state: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Mock 模式构造。
    #[must_use]
    pub fn mocked() -> Self {
        let mut adapter = Self::new();
        adapter.core.mode = AdapterMode::Mocked;
        adapter.core.unconfigured_reason = None;
        adapter
    }

    /// 注入录制替身（测试用）。
    ///
    /// # Errors
    /// 缺少凭据或未初始化。
    pub fn with_recording_transport(&mut self, transport: Arc<dyn crate::http::Transport>) -> DomainResult<()> {
        self.client = Some(self.core.build_test_client(transport)?);
        Ok(())
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.core.mode()
    }

    /// 只读核心。
    #[must_use]
    pub const fn core(&self) -> &AdapterCore {
        &self.core
    }

    /// 可变核心。
    pub const fn core_mut(&mut self) -> &mut AdapterCore {
        &mut self.core
    }

    /// 传输替身句柄（Mock 模式下恒不被调用；测试用它断言"零网络"）。
    #[must_use]
    pub fn transport(&self) -> Arc<crate::http::RecordingTransport> {
        self.transport.clone()
    }

    pub(crate) fn live_client(&self) -> DomainResult<&RpcClient> {
        if self.core.is_mock() {
            return Err(mock::mock_blocked(AliCloudService::AgentTeams));
        }
        self.client.as_deref().ok_or_else(|| {
            mock::unavailable(AliCloudService::AgentTeams, "适配器未初始化或凭据未就绪（无真实调用通道）")
        })
    }

    /// 云侧配额值（Mock 来自 fixtures；真实模式从云 API 拉取）。
    pub(crate) async fn cloud_quota_values(&self) -> DomainResult<Vec<(QuotaDimension, i64)>> {
        if self.core.is_mock() {
            return Ok(mock::agentteams_quota_fixture()
                .into_iter()
                .map(|(dimension, _platform, cloud)| (dimension, cloud))
                .collect());
        }
        Err(DomainError::Config("真实配额需要读取并写入明确 Worker，不能使用 Team 演示配额".into()))
    }

    /// 平台侧待下发的配额（生产由 `agf-runtime` 的配额服务注入；此处给出默认值）。
    #[must_use]
    pub fn platform_quota_defaults() -> Vec<(QuotaDimension, i64)> {
        mock::agentteams_quota_fixture()
            .into_iter()
            .map(|(dimension, platform, _cloud)| (dimension, platform))
            .collect()
    }
}

#[async_trait]
impl Adapter for AgentTeamsAdapter {
    fn name(&self) -> &str {
        AliCloudService::AgentTeams.as_str()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        mock::descriptor_of(AliCloudService::AgentTeams)
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.core.load_from_config(config)?;
        self.instance_id =
            config.settings.get("instance_id").and_then(serde_json::Value::as_str).unwrap_or_default().into();
        self.worker_name =
            config.settings.get("worker_name").and_then(serde_json::Value::as_str).unwrap_or_default().into();
        self.quota_period =
            config.settings.get("quota_period").and_then(serde_json::Value::as_str).unwrap_or_default().into();
        self.client = self.core.build_live_client();
        mock::log_init(AliCloudService::AgentTeams, self.core.mode());
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(self.core.health_of())
    }

    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome> {
        if !self.core.is_mock() && direction.includes_push() {
            return Err(DomainError::Validation(
                "真实同步不会下发演示配额；请显式提供 Worker、周期和 Token 限额".into(),
            ));
        }
        let started = std::time::Instant::now();
        let mut outcome = SyncOutcome {
            mocked: self.core.is_mock(),
            degraded: !self.core.is_live(),
            finished_at: Some(Timestamp::now()),
            ..SyncOutcome::default()
        };
        let integration_id =
            req.filter.get("integration_id").and_then(|value| Id::parse(value).ok()).unwrap_or_default();

        if direction.includes_pull() {
            let teams = self.pull_teams().await?;
            outcome.pulled = teams.len();
            outcome.changes.insert("team".to_string(), teams.len());
            outcome.changes.insert("agent".to_string(), teams.iter().map(|team| team.agents.len()).sum::<usize>());
            outcome.changes.insert(
                "orchestration_node".to_string(),
                teams.iter().map(|team| team.orchestration.len()).sum::<usize>(),
            );
            let managed = teams
                .iter()
                .map(|team| team.agents.iter().filter(|agent| agent.asset_id.is_some()).count())
                .sum::<usize>();
            outcome.changes.insert("managed_agent".to_string(), managed);

            // 免改造纳管：为每个未纳管成员给出建议模式
            for team in &teams {
                for member in &team.agents {
                    if member.asset_id.is_none() {
                        let mode = self.select_onboarding(member)?;
                        outcome
                            .changes
                            .entry(format!("onboarding:{}", mode.as_str()))
                            .and_modify(|value| *value += 1)
                            .or_insert(1);
                    }
                }
            }

            if self.core.is_mock() {
                let calls = self.pull_cross_team_calls(None).await?;
                outcome.changes.insert("cross_team_call".to_string(), calls.len());
                outcome.changes.insert("cross_team_blocked".to_string(), calls.iter().filter(|c| c.blocked).count());
                outcome
                    .changes
                    .insert("cross_team_cross_account".to_string(), calls.iter().filter(|c| c.cross_account).count());

                let events = self.pull_audit_events(req.limit).await?;
                outcome.changes.insert("audit_event".to_string(), events.len());
            } else {
                outcome.warnings.push("本次仅盘点团队和 Worker；调用链、审计与编排定义未由资源列表提供".into());
            }
        }

        if direction.includes_push() {
            // Mock 配额演示与角色名称评审提示；这里没有平台角色授权存储。
            let report = self.sync_quotas(integration_id, &Self::platform_quota_defaults()).await?;
            outcome.pushed = report.states.len();
            outcome.changes.insert("quota_synced".to_string(), report.states.len());
            outcome.changes.insert("quota_conflict".to_string(), report.conflict_count());
            for alert in &report.conflict_alerts {
                outcome.warnings.push(alert.clone());
            }
            let teams = self.pull_teams().await?;
            let roles = teams.iter().flat_map(|team| team.roles.clone()).collect::<Vec<_>>();
            let role_pairs = self.map_roles(&roles)?;
            outcome.changes.insert("role_mapping_hints".to_string(), role_pairs.len());
            outcome.changes.insert("role_mapped".to_string(), 0);
            outcome.warnings.push("Role 名称仅为评审提示，未保存或授予平台权限；请显式采用真实平台角色约束".into());
        }

        if self.core.is_mock() {
            outcome.warnings.push("Mock 模式：返回确定性 fixtures，未触达真实 AgentTeams（AGF_MOCK_MODE）".to_string());
        }
        if !self.core.is_live() {
            outcome.warnings.push("台账只读模式：双向同步已停，平台侧配置继续生效（平台为准）".to_string());
        }
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(outcome)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        match payload.entity.as_str() {
            "quota" => {
                let raw = payload
                    .body
                    .get("dimension")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| DomainError::Validation("配额缺少 dimension".into()))?;
                let dimension = QuotaDimension::all()
                    .into_iter()
                    .find(|candidate| candidate.as_str() == raw)
                    .ok_or_else(|| DomainError::Validation("未知配额维度".into()))?;
                let value = payload
                    .body
                    .get("value")
                    .and_then(serde_json::Value::as_i64)
                    .filter(|n| *n > 0)
                    .ok_or_else(|| DomainError::Validation("配额 value 必须是正整数".into()))?;
                let integration_id = payload
                    .body
                    .get("integration_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|raw| Id::parse(raw).ok())
                    .unwrap_or_default();
                self.sync_quotas(integration_id, &[(dimension, value)]).await?;
                Ok(())
            }
            "role-mapping" => {
                if !self.core.is_mock() {
                    return Err(DomainError::Validation("角色映射必须保存到平台授权配置，不能伪报云端下发成功".into()));
                }
                let roles: Vec<AgentTeamRole> = serde_json::from_value(payload.body.clone())?;
                self.map_roles(&roles)?;
                Ok(())
            }
            other => {
                Err(DomainError::Validation(format!("AgentTeams 适配器只接受 quota / role-mapping 载荷，收到 {other}")))
            }
        }
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let resource = if req.resource.is_empty() { "teams".to_string() } else { req.resource.clone() };
        let items = match resource.as_str() {
            "teams" => self
                .pull_teams()
                .await?
                .into_iter()
                .map(|team| serde_json::to_value(team).unwrap_or(serde_json::Value::Null))
                .collect(),
            "cross-team-calls" | "calls" => self
                .pull_cross_team_calls(None)
                .await?
                .into_iter()
                .map(|call| serde_json::to_value(call).unwrap_or(serde_json::Value::Null))
                .collect(),
            "audit-events" | "events" => self.pull_audit_events(req.limit).await?,
            other => return Err(DomainError::Validation(format!("AgentTeams 不支持拉取资源类型 {other}"))),
        };
        Ok(PullResponse {
            items,
            next_cursor: None,
            mocked: self.core.is_mock(),
            origin: if self.core.is_mock() {
                format!("fixture:crates/agf-alicloud/src/mock.rs#{resource}")
            } else {
                format!("https://{}", self.core.endpoint_host().unwrap_or_default())
            },
        })
    }

    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        let checks = crate::selfcheck::service_checks(AliCloudService::AgentTeams, &self.core, None);
        health.message = Some(crate::selfcheck::summarize_checks(&checks, self.core.mode()));
        Ok(health)
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.core.shutdown_common();
        self.client = None;
        Ok(())
    }
}

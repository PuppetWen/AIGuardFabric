//! 由 `agentteams.rs` 拆分：`impl_AgentTeamsAdapter`/`select_onboarding_mode` 等 12 项（纯搬移，逻辑不变）。
use super::*;

#[async_trait]
impl AgentTeamsApi for AgentTeamsAdapter {
    async fn pull_teams(&self) -> DomainResult<Vec<AgentTeam>> {
        if self.core.is_mock() {
            return Ok(mock::agentteams_teams());
        }
        self.live_teams().await
    }

    async fn sync_teams(&self, local: &[AgentTeam], direction: SyncDirection) -> DomainResult<TeamSyncReport> {
        if !self.core.is_mock() && direction.includes_push() {
            return Err(DomainError::Validation(
                "Team 的人类成员与 Worker 定义不同；请用显式 UpdateTeam/UpdateWorker 操作下发所需字段".into(),
            ));
        }
        let remote = self.pull_teams().await?;
        let mut report = TeamSyncReport::default();
        let local_by_id: BTreeMap<String, &AgentTeam> =
            local.iter().map(|team| (team.cloud_team_id.clone(), team)).collect();
        if local_by_id.len() != local.len() {
            return Err(DomainError::Validation("平台定义包含重复 Team 标识；不会选择任意一条".into()));
        }
        if remote
            .iter()
            .any(|team| local_by_id.get(&team.cloud_team_id).is_some_and(|local| local.tenant_id != team.tenant_id))
        {
            return Err(DomainError::Forbidden("Team 同步不得合并其他租户的声明".into()));
        }

        for mut team in remote {
            let agents = team.agents.len();
            let managed = team.agents.iter().filter(|agent| agent.asset_id.is_some()).count();
            report.pulled += 1;
            report.total_agents += agents;
            report.managed_agents += managed;

            match local_by_id.get(&team.cloud_team_id) {
                None => {
                    if direction.includes_pull() {
                        team.synced = true;
                        report.created += 1;
                    } else {
                        report.skipped += 1;
                    }
                }
                Some(existing) => {
                    let remote_changed = team_content_signature(&team) != team_content_signature(existing);
                    if !remote_changed {
                        report.skipped += 1;
                    } else if direction.includes_push() {
                        // **冲突规则：平台为准并告警**
                        report.conflicts += 1;
                        report.warnings.push(format!(
                            "团队 {} 远端与平台不一致（远端 {} 个 Agent / 平台 {} 个）：按「平台为准」保留平台定义并告警",
                            team.cloud_team_id,
                            team.agents.len(),
                            existing.agents.len()
                        ));
                        // Return the selected definition, rather than contradicting the conflict warning.
                        team = (*existing).clone();
                        team.synced = true;
                        report.updated += 1;
                    } else {
                        report.updated += 1;
                    }
                }
            }
            report.teams.push(team);
        }
        Ok(report)
    }

    fn select_onboarding(&self, member: &AgentTeamMember) -> DomainResult<OnboardingMode> {
        Ok(select_onboarding_mode(member))
    }

    async fn pull_cross_team_calls(&self, since: Option<Timestamp>) -> DomainResult<Vec<CrossTeamCall>> {
        if self.core.is_mock() {
            let mut calls = mock::agentteams_cross_calls();
            if let Some(since) = since {
                calls.retain(|call| call.at.is_at_or_after(&since));
            }
            return Ok(calls);
        }
        Err(DomainError::Config("公开 AgentTeams API 不提供调用链明细；请接入网关/SDK 的追踪日志".into()))
    }

    async fn sync_quotas(
        &self,
        integration_id: Id,
        platform_values: &[(QuotaDimension, i64)],
    ) -> DomainResult<QuotaSyncReport> {
        if platform_values.is_empty() {
            return Err(DomainError::Validation("配额同步需要至少一个维度".to_string()));
        }
        let cloud_values = if self.core.is_mock() {
            self.cloud_quota_values().await?
        } else {
            self.apply_live_quota(integration_id, platform_values).await?
        };
        let now = Timestamp::now();
        let mut states = Vec::new();
        let mut alerts = Vec::new();
        let mut effective = BTreeMap::new();
        for (dimension, platform_value) in platform_values {
            let cloud_value = cloud_values
                .iter()
                .find(|(cloud_dimension, _)| cloud_dimension == dimension)
                .map_or(*platform_value, |(_, value)| *value);
            let mut state = QuotaSyncState {
                id: deterministic_id("aiguardfabric.alicloud.quota", &format!("{integration_id}/{dimension:?}")),
                tenant_id: self.core.tenant_id,
                integration_id,
                dimension: *dimension,
                platform_value: *platform_value,
                cloud_value,
                conflict: false,
                effective_value: *platform_value,
                conflict_alerted: false,
                synced_at: now,
            };
            // 与上次告警状态合并：冲突未消失则不重复告警（QuotaSyncState::resolve 的语义）
            if let Ok(mut guard) = self.quota_state.lock() {
                if let Some(previous) = guard.get(dimension.as_str()) {
                    state.conflict_alerted = previous.conflict_alerted;
                }
                let should_alert = state.resolve();
                if should_alert {
                    alerts.push(format!(
                        "配额冲突（{}）：平台 {} / 云侧 {}，按「平台为准」生效 {} 并告警",
                        dimension.as_str(),
                        state.platform_value,
                        state.cloud_value,
                        state.effective_value
                    ));
                }
                guard.insert(dimension.as_str().to_string(), state.clone());
            } else {
                // 锁中毒：仍按"平台为准"解析，只是不保留告警去重状态
                state.resolve();
            }
            effective.insert(dimension.as_str().to_string(), state.effective_value);
            states.push(state);
        }
        Ok(QuotaSyncReport { states, conflict_alerts: alerts, effective })
    }

    fn map_roles(&self, roles: &[AgentTeamRole]) -> DomainResult<Vec<(String, String)>> {
        Ok(map_roles_to_platform(roles))
    }

    async fn pull_audit_events(&self, limit: Option<u32>) -> DomainResult<Vec<serde_json::Value>> {
        if self.core.is_mock() {
            let mut events = mock::agentteams_audit_events();
            if let Some(limit) = limit {
                events.truncate(usize::try_from(limit).unwrap_or(events.len()));
            }
            return Ok(events);
        }
        Err(DomainError::Config("公开 AgentTeams API 不提供完整消息审计；请在接入管理配置审计日志源".into()))
    }
}

/// 免改造纳管模式选择（纯函数，公开可解释）。
#[must_use]
pub fn select_onboarding_mode(member: &AgentTeamMember) -> OnboardingMode {
    // 1. 已纳管：保持侧车（由调用方决定是否改写，这里给出默认建议）
    if member.asset_id.is_some() {
        return OnboardingMode::Sidecar;
    }
    // 2. 引用自研工具 → SDK 注入
    if member.tools.iter().any(|tool| !tool.starts_with("mcp:")) {
        return OnboardingMode::SdkInjection;
    }
    // 3. 只调用模型 → 网关注册
    if !member.models.is_empty() && member.tools.is_empty() {
        return OnboardingMode::GatewayRegistration;
    }
    // 4. 有 MCP 工具 → 侧车代理
    if !member.tools.is_empty() {
        return OnboardingMode::Sidecar;
    }
    // 5. 无工具无模型 → 旁路观测
    OnboardingMode::ObserveOnly
}

/// Agent 是否"看起来像"商业 Coding Agent（辅助判断，用于纳管评审提示）。
#[must_use]
pub fn looks_like_ide_agent(member: &AgentTeamMember) -> bool {
    let normalized = member.name.to_ascii_lowercase().replace(['-', '_', ' '], "");
    AgentFlavor::all()
        .iter()
        .filter(|flavor| flavor.is_ide_agent())
        .any(|flavor| normalized.contains(&flavor.as_str().replace('-', "")))
}

/// 云 Role 名称到平台角色名称的评审提示；不验证角色 UUID，也不保存或授予权限。
///
/// 规则：优先使用云侧显式声明的 `mapped_platform_role`；否则按 `allowed_tools` 的危险度推断：
/// 含写/执行类工具 → `operator`；只读 → `viewer`；无工具 → `auditor`。
///
/// 这些名称仅是兼容旧调用方的提示。实际治理必须显式采用本租户真实角色记录，
/// 并将 Key 原 scopes 与已采用角色权限取交集；不能将这里的结果计为已授权映射。
#[must_use]
pub fn map_roles_to_platform(roles: &[AgentTeamRole]) -> Vec<(String, String)> {
    roles
        .iter()
        .map(|role| {
            let mapped = role.mapped_platform_role.clone().unwrap_or_else(|| {
                let dangerous = role.allowed_tools.iter().any(|tool| {
                    let tool = tool.to_ascii_lowercase();
                    tool.contains("write") || tool.contains("exec") || tool.contains("delete") || tool.contains("shell")
                });
                if dangerous {
                    "operator"
                } else if role.allowed_tools.is_empty() {
                    "auditor"
                } else {
                    "viewer"
                }
                .to_string()
            });
            (role.name.clone(), mapped)
        })
        .collect()
}

/// 解析团队列表响应（兼容一层嵌套与字符串/数字混用）。
#[must_use]
pub fn parse_teams(body: &serde_json::Value, tenant_id: TenantId) -> Vec<AgentTeam> {
    json_array(body, &["Team", "Teams"])
        .into_iter()
        .map(|item| {
            let cloud_team_id = json_str(item, "TeamId").or_else(|| json_str(item, "Id")).unwrap_or_default();
            let agents = string_array(item, "Agents")
                .iter()
                .map(|agent| AgentTeamMember {
                    cloud_agent_id: json_str(agent, "AgentId").unwrap_or_default(),
                    name: json_str(agent, "Name").unwrap_or_default(),
                    models: string_list(agent, "Models"),
                    tools: string_list(agent, "Tools"),
                    role_names: string_list(agent, "Roles"),
                    asset_id: json_str(agent, "AssetId").and_then(|raw| Id::parse(&raw).ok()),
                    status: json_str(agent, "Status").unwrap_or_else(|| "unknown".to_string()),
                })
                .collect::<Vec<_>>();
            let roles = string_array(item, "Roles")
                .iter()
                .map(|role| AgentTeamRole {
                    name: json_str(role, "Name").unwrap_or_default(),
                    description: json_str(role, "Description").unwrap_or_default(),
                    allowed_tools: string_list(role, "AllowedTools"),
                    mapped_platform_role: json_str(role, "MappedPlatformRole"),
                })
                .collect::<Vec<_>>();
            let nodes = item
                .get("Orchestration")
                .or_else(|| item.get("Nodes"))
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let orchestration = nodes
                .iter()
                .map(|node| OrchestrationNode {
                    node_id: json_str(node, "NodeId").unwrap_or_default(),
                    name: json_str(node, "Name").unwrap_or_default(),
                    agent_ids: string_list(node, "AgentIds"),
                    depends_on: string_list(node, "DependsOn"),
                    trigger: json_str(node, "Trigger").unwrap_or_else(|| "manual".to_string()),
                    cron: json_str(node, "Cron"),
                })
                .collect::<Vec<_>>();
            AgentTeam {
                id: deterministic_id(NS_TEAM, &cloud_team_id),
                tenant_id,
                cloud_team_id,
                name: json_str(item, "Name").unwrap_or_default(),
                description: json_str(item, "Description").unwrap_or_default(),
                agents,
                roles,
                orchestration,
                onboarding: OnboardingMode::Sidecar,
                synced: false,
                cloud_updated_at: json_i64(item, "UpdatedAt").and_then(|ms| Timestamp::from_unix_millis(ms).ok()),
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            }
        })
        .collect()
}

/// 解析跨 Team 调用链响应。
#[must_use]
pub fn parse_cross_team_calls(body: &serde_json::Value, tenant_id: TenantId) -> Vec<CrossTeamCall> {
    json_array(body, &["Call", "Calls"])
        .into_iter()
        .map(|item| {
            let key = format!(
                "{}:{}:{}",
                json_str(item, "FromTeamId").unwrap_or_default(),
                json_str(item, "ToTeamId").unwrap_or_default(),
                json_i64(item, "Timestamp").unwrap_or_default()
            );
            CrossTeamCall {
                id: deterministic_id("aiguardfabric.alicloud.agentteams.call", &key),
                tenant_id,
                from_team_id: json_str(item, "FromTeamId").unwrap_or_default(),
                from_agent_id: json_str(item, "FromAgentId").unwrap_or_default(),
                to_team_id: json_str(item, "ToTeamId").unwrap_or_default(),
                to_agent_id: json_str(item, "ToAgentId").unwrap_or_default(),
                call_kind: json_str(item, "CallKind").unwrap_or_else(|| "a2a".to_string()),
                cross_account: item.get("CrossAccount").and_then(serde_json::Value::as_bool).unwrap_or(false),
                blocked: item.get("Blocked").and_then(serde_json::Value::as_bool).unwrap_or(false),
                latency_ms: json_i64(item, "LatencyMs").unwrap_or(0).max(0).unsigned_abs(),
                at: json_i64(item, "Timestamp")
                    .and_then(|ms| Timestamp::from_unix_millis(ms).ok())
                    .unwrap_or_else(Timestamp::now),
            }
        })
        .collect()
}

/// 取对象数组字段（兼容 `Key` 与 `Keys.Key` 两种形态）。
pub(crate) fn string_array<'a>(value: &'a serde_json::Value, key: &str) -> Vec<&'a serde_json::Value> {
    if let Some(array) = value.get(key).and_then(serde_json::Value::as_array) {
        return array.iter().collect();
    }
    json_array(value, &[key])
}

/// 取字符串数组字段。
pub(crate) fn string_list(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|list| list.iter().filter_map(|item| item.as_str().map(ToString::to_string)).collect())
        .unwrap_or_default()
}

/// 把团队聚合为"纳管率"摘要（控制台首页用）：`(已纳管数, 总数, 比率)`。
#[must_use]
pub fn managed_summary(teams: &[AgentTeam]) -> (usize, usize, f32) {
    let total: usize = teams.iter().map(|team| team.agents.len()).sum();
    let managed: usize = teams.iter().map(|team| team.agents.iter().filter(|a| a.asset_id.is_some()).count()).sum();
    #[allow(clippy::cast_precision_loss)]
    let ratio = if total == 0 { 0.0 } else { managed as f32 / total as f32 };
    (managed, total, ratio)
}

/// 从团队清单提取"未纳管 Agent"列表（控制台纳管任务列表用）。
#[must_use]
pub fn unmanaged_members(teams: &[AgentTeam]) -> Vec<(String, String, OnboardingMode)> {
    teams
        .iter()
        .flat_map(|team| {
            team.agents
                .iter()
                .filter(|agent| agent.asset_id.is_none())
                .map(|agent| (team.cloud_team_id.clone(), agent.cloud_agent_id.clone(), select_onboarding_mode(agent)))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// 把团队成员转为平台资产（免改造纳管后登记，`asset_id` 回填用）。
#[must_use]
pub fn member_fingerprint(team_id: &str, member: &AgentTeamMember) -> String {
    format!("agentteams://{team_id}/{}", member.cloud_agent_id)
}

/// 团队成员资产指纹的确定性 id。
#[must_use]
pub fn member_asset_id(team_id: &str, member: &AgentTeamMember) -> Id {
    deterministic_id(NS_AGENT, &member_fingerprint(team_id, member))
}

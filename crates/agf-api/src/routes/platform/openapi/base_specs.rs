//! Base route metadata; specialized contracts extend this list in the parent.
use super::EndpointSpec;

pub(super) fn endpoint_specs() -> Vec<EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{self, Delete, Get, Patch, Post, Put};
    let mut specs: Vec<EndpointSpec> = Vec::new();
    let mut push = |path: &'static str,
                    method: HttpMethod,
                    id: &'static str,
                    summary: &'static str,
                    tag: &'static str,
                    implemented: bool| {
        specs.push(EndpointSpec { path, method, id, summary, tag, implemented });
    };

    push("/healthz", Get, "healthz", "存活探针（不查依赖）", "health", true);
    push("/readyz", Get, "readyz", "就绪探针（离线模式标注 degraded）", "health", true);
    push("/metrics", Get, "metrics", "Prometheus 文本指标", "health", true);

    push(
        "/api/v1/auth/login",
        Post,
        "authLogin",
        "登录（首登返回 must_change_password 且不签发可用令牌）",
        "auth",
        true,
    );
    push("/api/v1/auth/change-password", Post, "authChangePassword", "修改口令（首登强制）", "auth", true);
    push("/api/v1/auth/refresh", Post, "authRefresh", "刷新令牌（轮换并吊销旧令牌）", "auth", true);
    push("/api/v1/auth/logout", Post, "authLogout", "登出（吊销刷新令牌）", "auth", true);
    push("/api/v1/auth/me", Get, "authMe", "当前主体与有效权限", "auth", true);

    push("/api/v1/assets", Get, "listAssets", "资产列表（分页/过滤/排序/字段裁剪）", "assets", true);
    push("/api/v1/assets/stats", Get, "assetStats", "资产盘点统计", "assets", true);
    push("/api/v1/assets/discovery", Post, "ingestDiscovery", "发现批次导入（按指纹幂等归并）", "assets", true);
    push("/api/v1/assets/drift", Post, "assetDrift", "生成快照并计算漂移", "assets", true);
    push("/api/v1/assets/{id}", Get, "getAsset", "资产详情与变更台账", "assets", true);
    push("/api/v1/assets/{id}", Patch, "updateAssetMetadata", "按资产版本更正名称、归属和分级", "assets", true);
    push(
        "/api/v1/assets/{id}",
        Delete,
        "removeAsset",
        "归档或拒绝后，按版本从当前资产台账移除并保留历史",
        "assets",
        true,
    );
    push("/api/v1/assets/{id}/transition", Post, "transitionAsset", "生命周期流转", "assets", true);
    push("/api/v1/assets/{id}/edr-host", Put, "bindAssetEdrHost", "按资产版本绑定 EDR 主机编号", "assets", true);
    push("/api/v1/assets/{id}/scim-user", Put, "bindAssetScimUser", "按资产版本绑定 SCIM 用户编号", "assets", true);

    push("/api/v1/findings", Get, "listFindings", "风险发现列表", "findings", true);
    push("/api/v1/findings/stats", Get, "findingStats", "发现统计", "findings", true);
    push("/api/v1/findings/{id}", Get, "getFinding", "发现详情", "findings", true);
    push("/api/v1/findings/{id}/state", Post, "setFindingState", "发现状态流转", "findings", true);

    // §4.11 资源组：agents / mcps / skills / models（只读，数据源为资产台账，见 routes::ai_assets）
    push("/api/v1/agents", Get, "listAgents", "Agent 列表（台账按 kind=agent 投影）", "agents", true);
    push("/api/v1/agents/{id}", Get, "getAgent", "Agent 详情", "agents", true);
    // 别名：控制台 client.ts 调的是 /mcp-servers（PV-024），与 /mcps 同处理器
    push("/api/v1/mcp-servers", Get, "listMcpServers", "MCP Server 列表（/mcps 别名，前端路径）", "mcps", true);
    push("/api/v1/mcp-servers/{id}", Get, "getMcpServer", "MCP Server 详情（/mcps 别名）", "mcps", true);
    push("/api/v1/skills", Get, "listSkills", "Skill 列表（含审批状态）", "skills", true);
    push("/api/v1/skills/{id}", Get, "getSkill", "Skill 详情", "skills", true);
    push("/api/v1/models/endpoints", Get, "listModelEndpoints", "模型端点列表", "models", true);
    push("/api/v1/models/endpoints/{id}", Get, "getModelEndpoint", "模型端点详情", "models", true);

    push("/api/v1/rules", Post, "publishRule", "校验样本并发布规则", "rules", true);
    push("/api/v1/rules/{key}", Patch, "patchRule", "规则启停与灰度", "rules", true);
    push("/api/v1/rules/{key}/versions", Get, "ruleVersions", "规则版本历史", "rules", true);
    push("/api/v1/rules/{key}/versions/{version}/restore", Post, "restoreRule", "恢复历史规则", "rules", true);
    push("/api/v1/rules", Get, "listRules", "规则库列表", "rules", true);
    push("/api/v1/rules/summary", Get, "rulesSummary", "规则库覆盖概览", "rules", true);
    push("/api/v1/rules/{key}", Get, "getRule", "规则详情", "rules", true);
    push("/api/v1/rules/{key}/regression", Post, "runRegression", "正负样本回归", "rules", true);

    push("/api/v1/scans", Get, "listScans", "扫描任务列表", "scans", true);
    push("/api/v1/scans", Post, "createScan", "发起扫描（返回 task_id）", "scans", true);
    push("/api/v1/scans/{task_id}", Get, "getScan", "查询扫描任务状态", "scans", true);
    push("/api/v1/scans/{task_id}/cancel", Post, "cancelScan", "取消扫描任务", "scans", true);

    push("/api/v1/policies", Get, "listPolicies", "策略列表", "policies", true);
    push("/api/v1/policies", Post, "createPolicy", "新建策略", "policies", true);
    push("/api/v1/policies/dry-run", Post, "dryRunAdhoc", "临时策略求值", "policies", true);
    push("/api/v1/policies/reload", Post, "reloadPolicies", "策略热重载", "policies", true);
    push("/api/v1/policies/{id}", Get, "getPolicy", "策略详情", "policies", true);
    push("/api/v1/policies/{id}", Put, "updatePolicy", "更新策略", "policies", true);
    push("/api/v1/policies/{id}", Delete, "deletePolicy", "删除策略", "policies", true);
    push("/api/v1/policies/{id}/dry-run", Post, "dryRunPolicy", "单条策略求值", "policies", true);

    push("/api/v1/alerts", Get, "listAlerts", "告警列表", "alerts", true);
    push("/api/v1/alerts", Post, "createAlert", "登记/合并告警", "alerts", true);
    push("/api/v1/alerts/{id}", Get, "getAlert", "告警详情", "alerts", true);
    push("/api/v1/alerts/{id}/state", Post, "setAlertState", "告警状态流转", "alerts", true);
    push(
        "/api/v1/alerts/aggregate",
        Post,
        "alertAggregate",
        "告警聚合（agf-correlate 真实聚簇/去重/抑制）",
        "alerts",
        true,
    );
    push(
        "/api/v1/alerts/sla-refresh",
        Post,
        "alertSlaRefresh",
        "告警 SLA 刷新（三档目标/逾期/升级阶梯，实时计算）",
        "alerts",
        true,
    );
    push(
        "/api/v1/alerts/{id}/escalate",
        Post,
        "escalateAlert",
        "告警升级（SLA 阶梯判定 + Mock 渠道派发）",
        "alerts",
        true,
    );

    push("/api/v1/cases", Get, "listCases", "案件列表", "cases", true);
    push("/api/v1/cases", Post, "createCase", "新建案件", "cases", true);
    push("/api/v1/cases/{id}", Get, "getCase", "案件详情", "cases", true);
    push("/api/v1/cases/{id}/state", Post, "setCaseState", "案件状态流转", "cases", true);
    push("/api/v1/cases/{id}/timeline", Get, "caseTimeline", "案件时间线", "cases", true);
    push("/api/v1/cases/{id}/timeline", Post, "appendCaseTimeline", "追加案件时间线", "cases", true);
    push("/api/v1/cases/{id}/sla", Get, "caseSla", "案件 SLA（案件时间线推里程碑 + 三档判定）", "cases", true);
    push("/api/v1/cases/{id}/playbook", Post, "casePlaybook", "剧本执行（PlaybookEngine + Mock 注入）", "cases", true);
    push(
        "/api/v1/notifications/send",
        Post,
        "notifySend",
        "通知派发（渠道路由/去重/限流/重试；渠道为 Mock）",
        "cases",
        true,
    );

    // 控制台的自动响应配置与通知页也使用这些真实路由。
    push("/api/v1/soar/automations", Get, "listSoarAutomations", "自动响应列表", "soar", true);
    push("/api/v1/soar/automations", Post, "createSoarAutomation", "创建自动响应", "soar", true);
    push("/api/v1/soar/automations/templates", Get, "soarTemplates", "自动响应模板", "soar", true);
    push("/api/v1/soar/automations/preview", Post, "previewSoarAutomation", "预览触发条件", "soar", true);
    push("/api/v1/soar/automations/{id}", Get, "getSoarAutomation", "自动响应详情", "soar", true);
    push("/api/v1/soar/automations/{id}", Put, "updateSoarAutomation", "更新自动响应", "soar", true);
    push("/api/v1/soar/automations/{id}/deliveries", Get, "soarDeliveries", "自动响应投递记录", "soar", true);
    push(
        "/api/v1/soar/automations/{id}/deliveries/{delivery}/retry",
        Post,
        "retrySoarDelivery",
        "重试投递",
        "soar",
        true,
    );
    push("/api/v1/notifications/history", Get, "notificationHistory", "通知投递历史", "notifications", true);
    push("/api/v1/notifications/{id}/retry", Post, "retryNotification", "重试通知投递", "notifications", true);
    push("/api/v1/settings/notifications", Get, "notificationSettings", "通知渠道配置", "notifications", true);
    push(
        "/api/v1/settings/notifications/{kind}",
        Put,
        "saveNotificationSettings",
        "保存通知渠道",
        "notifications",
        true,
    );
    push(
        "/api/v1/settings/notifications/{kind}/test",
        Post,
        "testNotificationSettings",
        "测试通知渠道",
        "notifications",
        true,
    );

    push("/api/v1/quotas", Get, "listQuotas", "配额列表", "quotas", true);
    push("/api/v1/quotas", Post, "upsertQuota", "新增/更新配额", "quotas", true);
    push("/api/v1/quotas/snapshot", Get, "quotaSnapshot", "配额快照", "quotas", true);

    push("/api/v1/sources", Get, "listSources", "接入面清单", "sources", true);
    push("/api/v1/sources/capabilities", Get, "sourceCapabilities", "接收器能力矩阵", "sources", true);
    push("/api/v1/sources/{id}", Get, "getSource", "单个接入源", "sources", true);
    push("/api/v1/parsers", Get, "listParsers", "解析器列表", "parsers", true);
    push("/api/v1/parsers/stats", Get, "parserStats", "解析器统计", "parsers", true);
    push("/api/v1/parsers/engine-matrix", Get, "engineMatrix", "解析引擎支持矩阵", "parsers", true);
    push("/api/v1/parsers/{id}", Get, "getParser", "解析器详情", "parsers", true);
    push("/api/v1/parsers/{id}/preview", Get, "previewParser", "解析器真实样本与模板", "parsers", true);
    push("/api/v1/parsers/{id}/test", Post, "testParserSample", "解析器样本试解析", "parsers", true);

    push("/api/v1/redteam/cases", Get, "listRedteamCases", "红队用例库", "redteam", true);
    push("/api/v1/redteam/agent-targets", Get, "listAgentTargets", "已配置 Agent 红队目标", "redteam", true);
    push("/api/v1/redteam/agent-targets", Post, "saveAgentTarget", "创建或更新 Agent 红队目标", "redteam", true);
    push("/api/v1/redteam/agent-targets/{id}", Get, "getAgentTarget", "Agent 红队目标详情", "redteam", true);
    push("/api/v1/redteam/agent-targets/{id}", Delete, "deleteAgentTarget", "删除 Agent 红队目标", "redteam", true);
    push("/api/v1/redteam/mcp-targets", Get, "listMcpTargets", "已配置 MCP 红队目标", "redteam", true);
    push("/api/v1/redteam/mcp-targets", Post, "saveMcpTarget", "创建或更新 MCP 红队目标", "redteam", true);
    push("/api/v1/redteam/mcp-targets/{id}", Get, "getMcpTarget", "MCP 红队目标详情", "redteam", true);
    push("/api/v1/redteam/mcp-targets/{id}/usage", Get, "getMcpTargetUsage", "MCP 红队工具用量", "redteam", true);
    push("/api/v1/redteam/mcp-targets/{id}", Delete, "deleteMcpTarget", "删除 MCP 红队目标", "redteam", true);
    push("/api/v1/redteam/stats", Get, "redteamStats", "红队统计", "redteam", true);
    push("/api/v1/redteam/campaigns", Get, "listCampaigns", "战役列表", "redteam", true);
    push("/api/v1/redteam/campaigns", Post, "launchCampaign", "发起战役", "redteam", true);
    push("/api/v1/redteam/campaigns/{id}", Get, "getCampaign", "战役详情", "redteam", true);
    push("/api/v1/redteam/campaigns/{id}/report", Get, "campaignReport", "战役报告", "redteam", true);
    push("/api/v1/redteam/campaigns/{id}/evidence", Get, "campaignEvidence", "战役证据", "redteam", true);
    push("/api/v1/redteam/campaigns/{id}/cancel", Post, "cancelCampaign", "取消战役", "redteam", true);
    push("/api/v1/redteam/campaigns/{id}/retest", Post, "retestCampaign", "原用例复测", "redteam", true);

    push("/api/v1/integrations", Get, "listIntegrations", "集成适配器总览", "integrations", true);
    push("/api/v1/integrations/health", Get, "integrationsHealth", "适配器健康", "integrations", true);
    push("/api/v1/integrations/{name}", Get, "getIntegration", "单个适配器", "integrations", true);
    push("/api/v1/alicloud/services", Get, "alicloudServices", "阿里云服务适配器", "alicloud", true);
    push("/api/v1/alicloud/connections", Get, "cloudConnections", "云连接配置摘要", "alicloud", true);
    push("/api/v1/alicloud/connections/{name}", Get, "getCloudConnection", "云连接详情（凭据隐藏）", "alicloud", true);
    push("/api/v1/alicloud/connections/{name}", Put, "saveCloudConnection", "保存云连接配置", "alicloud", true);
    push(
        "/api/v1/alicloud/connections/{name}/operations",
        Get,
        "cloudOperationHistory",
        "云操作回执",
        "alicloud",
        true,
    );
    push(
        "/api/v1/alicloud/connections/{name}/operations",
        Post,
        "executeCloudOperation",
        "执行云操作",
        "alicloud",
        true,
    );
    push(
        "/api/v1/alicloud/connections/{name}/operations/{id}",
        Get,
        "cloudOperationReceipt",
        "云操作详情",
        "alicloud",
        true,
    );
    push("/api/v1/alicloud/connections/{name}/probe", Post, "probeCloudConnection", "连接自检", "alicloud", true);
    push("/api/v1/alicloud/agentteams/sync", Post, "syncAgentTeams", "同步团队、Worker 与任务台账", "alicloud", true);
    push(
        "/api/v1/alicloud/agentteams/audit-sources",
        Get,
        "listAgentTeamsAuditSources",
        "审计绑定与接入状态",
        "alicloud",
        true,
    );
    push(
        "/api/v1/alicloud/agentteams/audit-sources/{id}",
        Put,
        "bindAgentTeamsAuditSource",
        "绑定或停用完整盘点的日志源",
        "alicloud",
        true,
    );
    push(
        "/api/v1/alicloud/agentteams/audit-sources/{id}/events",
        Post,
        "ingestAgentTeamsAudit",
        "认证上报团队调用和消息",
        "sources",
        true,
    );
    push(
        "/api/v1/alicloud/agentteams/audit-events",
        Get,
        "listAgentTeamsAuditEvents",
        "分页读取消息与调用审计",
        "alicloud",
        true,
    );
    push("/api/v1/alicloud/selfcheck", Get, "alicloudSelfcheck", "云环境自检", "alicloud", true);
    push(
        "/api/v1/alicloud/selfcheck/markdown",
        Get,
        "alicloudSelfcheckMarkdown",
        "云环境自检（Markdown）",
        "alicloud",
        true,
    );

    push("/api/v1/audit", Get, "listAudit", "审计列表", "audit", true);
    push("/api/v1/audit/verify", Get, "verifyAuditChain", "审计哈希链校验报告", "audit", true);
    push("/api/v1/audit/stats", Get, "auditStats", "审计链统计", "audit", true);

    push("/api/v1/reports", Get, "listReports", "报表列表", "reports", true);
    push("/api/v1/reports", Post, "generateReport", "生成多格式报表", "reports", true);
    push("/api/v1/reports/schedules", Get, "reportSchedules", "周期报表执行状态（UTC）", "reports", true);
    push(
        "/api/v1/reports/schedules",
        Post,
        "createReportSchedule",
        "创建周期报表计划（主服务自动执行）",
        "reports",
        true,
    );
    push(
        "/api/v1/reports/schedules/{id}",
        Patch,
        "updateReportSchedule",
        "按 expected_version 编辑或启停报表计划",
        "reports",
        true,
    );
    push(
        "/api/v1/reports/schedules/{id}",
        Delete,
        "deleteReportSchedule",
        "按 expected_version 查询参数删除报表计划",
        "reports",
        true,
    );
    push("/api/v1/reports/schedules/{id}/run", Post, "runReportSchedule", "立即生成计划报表", "reports", true);
    push("/api/v1/reports/{id}", Get, "getReport", "报表详情", "reports", true);
    push("/api/v1/reports/{id}/download", Get, "downloadReport", "报表下载", "reports", true);

    push("/api/v1/settings", Get, "settingsSnapshot", "配置快照（敏感值掩码）", "settings", true);
    push("/api/v1/settings/tenant", Put, "saveTenantSettings", "按版本保存租户资料", "settings", true);
    push("/api/v1/settings/quotas", Put, "saveQuotaSettings", "按版本保存网关配额", "settings", true);
    push("/api/v1/settings/api-keys", Get, "listApiKeys", "API Key 列表", "settings", true);
    push("/api/v1/settings/api-keys", Post, "createApiKey", "签发 API Key", "settings", true);
    push("/api/v1/openapi.json", Get, "openapiSpec", "OpenAPI 3.1 规范", "settings", true);
    push("/graphql", Post, "graphql", "GraphQL 查询（assets/findings/alerts）", "graphql", true);
    push("/api/v1/alerts/escalation-config", Get, "getEscalationConfig", "升级策略、版本和运行状态", "alerts", true);
    push("/api/v1/alerts/escalation-config", Put, "saveEscalationConfig", "按版本保存升级策略", "alerts", true);
    push("/api/v1/alerts/escalation-history", Get, "escalationHistory", "升级入队与通知回执", "alerts", true);
    push("/api/v1/redteam/cases/{key}", Get, "getRedteamCase", "只读用例定义（不执行）", "redteam", true);
    push("/api/v1/notifications/inbox", Get, "notificationInbox", "按资源权限读取最近 100 条站内消息", "alerts", true);
    push("/api/v1/notifications/inbox/read", Post, "markNotificationRead", "个人已读标记（持久化）", "alerts", true);
    push("/ws", Get, "websocket", "WebSocket 事件订阅（含心跳）", "ws", true);

    // 控制台补齐的两批端点各自导出自己的清单（避免在多个文件里手工维护同一份路径表），
    // 这里统一并入。约定：所有 spec 的 `path` 都是**完整路径**（带 `/api/v1` 前缀），
    // 与上面手写的条目一致——新增模块时务必照此办理，否则 OpenAPI 会漏掉它们。
    push("/v1/messages", Post, "anthropicMessages", "Messages 文本、图片、工具调用与流式入口", "models", true);
    push("/api/v1/settings/identity/oidc", Get, "oidcSettings", "当前租户 OIDC 配置（不返回密钥）", "settings", true);
    push("/api/v1/settings/identity/oidc", Put, "saveOidcSettings", "保存并验证企业身份配置", "settings", true);
    push("/api/v1/auth/oidc/start", Post, "startOidc", "创建浏览器绑定的授权码 PKCE 事务", "auth", true);
    push("/api/v1/auth/oidc/exchange", Post, "exchangeOidc", "一次性交换授权码并验证身份", "auth", true);
    push("/api/v1/auth/oidc/complete", Post, "completeOidc", "完成 MFA 并签发本平台会话", "auth", true);
    push(
        "/api/v1/settings/identity/ldap",
        Get,
        "ldapSettings",
        "读取当前租户 LDAP/AD 目录配置（不返回服务账号口令）",
        "settings",
        true,
    );
    push("/api/v1/settings/identity/ldap", Put, "saveLdapSettings", "按版本保存当前租户目录配置", "settings", true);
    push("/api/v1/auth/ldap/login", Post, "ldapLogin", "验证 LDAP/AD 口令与本平台 MFA 后签发会话", "auth", true);
    push("/v1/messages/count_tokens", Post, "estimateMessageTokens", "输入 token 估算（非计费用量）", "models", true);
    push("/v1/chat/completions", Post, "openaiChat", "OpenAI 兼容聊天与流式入口", "models", true);
    push("/api/v1/chat/completions", Post, "apiChatCompletions", "控制台模型调用入口", "models", true);
    push("/v1/models", Get, "sdkModels", "当前租户已启用模型", "models", true);
    push("/api/v1/gateway/endpoints", Get, "listGatewayEndpoints", "已登记模型端点", "models", true);
    push("/api/v1/gateway/providers", Get, "listGatewayProviders", "模型厂商配置建议", "models", true);
    push("/api/v1/gateway/endpoints", Post, "createGatewayEndpoint", "登记并加密保存模型端点", "models", true);
    push("/api/v1/gateway/endpoints/{id}", Put, "updateGatewayEndpoint", "更新模型端点", "models", true);
    push("/api/v1/gateway/endpoints/{id}", Delete, "removeGatewayEndpoint", "移除模型端点", "models", true);
    specs
}

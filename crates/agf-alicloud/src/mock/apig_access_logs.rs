//! 由 `mock.rs` 拆分：`apig_access_logs` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

/// Mock：APIG 访问日志（2 条，含 1 条被内容安全阻断）。
#[must_use]
pub fn apig_access_logs() -> Vec<serde_json::Value> {
    let now = Timestamp::now();
    vec![
        serde_json::json!({
            "request_id": "log-mock-001",
            "gateway_id": "gw-mock-001",
            "route_id": "route-mock-001",
            "client_ip": "10.20.30.40",
            "model": "qwen-max",
            "prompt_tokens": 512,
            "completion_tokens": 128,
            "status": 200,
            "at": now.offset_secs(-120).to_rfc3339(),
        }),
        serde_json::json!({
            "request_id": "log-mock-002",
            "gateway_id": "gw-mock-001",
            "route_id": "route-mock-002",
            "client_ip": "10.20.30.41",
            "model": "qwen-plus",
            "prompt_tokens": 2048,
            "completion_tokens": 0,
            "status": 403,
            "blocked_reason": "prompt_attack",
            "at": now.offset_secs(-60).to_rfc3339(),
        }),
    ]
}

/// Mock：MSE 集群（1 个）。
#[must_use]
pub fn mse_clusters() -> Vec<MseCluster> {
    vec![MseCluster {
        cluster_id: "mse-mock-001".to_string(),
        name: "agf-nacos-prod".to_string(),
        cluster_type: "Nacos".to_string(),
        version: "2.3.2".to_string(),
        instance_count: 3,
        vpc_id: "vpc-mock-001".to_string(),
        status: "Running".to_string(),
    }]
}

/// Mock：Nacos 服务清单（4 条：2 个 MCP Server、1 个 Agent、1 个模型端点）。
#[must_use]
pub fn mse_services() -> Vec<MseService> {
    let service =
        |namespace: &str, group: &str, name: &str, instances: u32, healthy: u32, pairs: &[(&str, &str)]| MseService {
            namespace: namespace.to_string(),
            group_name: group.to_string(),
            service_name: name.to_string(),
            cluster_id: "mse-mock-001".to_string(),
            instance_count: instances,
            healthy_count: healthy,
            metadata: pairs.iter().map(|(k, v)| ((*k).to_string(), serde_json::Value::from(*v))).collect(),
        };
    vec![
        service(
            "public",
            "DEFAULT_GROUP",
            "mcp-file-server",
            2,
            2,
            &[("kind", "mcp-server"), ("protocol", "mcp-http"), ("endpoint", "10.20.30.11:8080"), ("vendor", "自研")],
        ),
        service(
            "public",
            "DEFAULT_GROUP",
            "mcp-db-server",
            1,
            1,
            &[("kind", "mcp-server"), ("protocol", "mcp-sse"), ("endpoint", "10.20.30.12:8081")],
        ),
        service(
            "ai",
            "AGENTS",
            "risk-analyst-agent",
            1,
            0,
            &[("kind", "agent"), ("protocol", "a2a"), ("version", "1.4.0"), ("endpoint", "10.20.30.21:9000")],
        ),
        service(
            "ai",
            "MODELS",
            "qwen-max-endpoint",
            2,
            2,
            &[
                ("kind", "model-endpoint"),
                ("protocol", "openai-compat"),
                ("endpoint", "10.20.30.31:11434"),
                ("data_class", "confidential"),
            ],
        ),
    ]
}

/// Mock：MSE 配置（2 条）。
#[must_use]
pub fn mse_configs() -> Vec<MseConfig> {
    let config = |data_id: &str, content: &str| MseConfig {
        data_id: data_id.to_string(),
        group_name: "AGF".to_string(),
        namespace: "public".to_string(),
        content: content.to_string(),
        md5: agf_core::secret::content_hash(content),
    };
    vec![
        config("agf-policy.json", "{\"version\":1,\"mode\":\"enforce\"}"),
        config("agf-quota.json", "{\"tokens\":1000000}"),
    ]
}

/// Mock：MSE 云原生网关（1 个，承载管理面流量）。
#[must_use]
pub fn mse_gateways() -> Vec<crate::mse::MseGateway> {
    vec![crate::mse::MseGateway {
        gateway_id: "mse-gw-mock-001".to_string(),
        name: "agf-management-plane".to_string(),
        version: "2.1.0".to_string(),
        traffic_kind: "management-plane".to_string(),
        status: "Running".to_string(),
    }]
}

/// Mock：PrivateLink 终端节点（2 个，其中 1 个安全组白名单过大）。
#[must_use]
pub fn privatelink_endpoints() -> Vec<PrivatelinkEndpoint> {
    vec![
        PrivatelinkEndpoint {
            endpoint_id: "ep-mock-001".to_string(),
            name: "agf-collector-ep".to_string(),
            service_name: "com.aliyuncs.privatelink.cn-hangzhou.oss".to_string(),
            vpc_id: "vpc-mock-001".to_string(),
            zone_ids: vec!["cn-hangzhou-h".to_string(), "cn-hangzhou-i".to_string()],
            status: "Active".to_string(),
            bandwidth_mbps: 200,
            security_groups: vec!["sg-mock-tight".to_string()],
            connection_status: "Connected".to_string(),
        },
        PrivatelinkEndpoint {
            endpoint_id: "ep-mock-002".to_string(),
            name: "agf-legacy-ep".to_string(),
            service_name: "com.aliyuncs.privatelink.cn-hangzhou.rds".to_string(),
            vpc_id: "vpc-mock-001".to_string(),
            zone_ids: vec!["cn-hangzhou-h".to_string()],
            status: "Active".to_string(),
            bandwidth_mbps: 1_024,
            security_groups: vec![
                "sg-mock-wide".to_string(),
                "sg-mock-extra".to_string(),
                "sg-mock-legacy".to_string(),
            ],
            connection_status: "Connected".to_string(),
        },
    ]
}

/// Mock：私网连通性探测（确定性；目标名含 `missing` 时判定不可达）。
#[must_use]
pub fn privatelink_probe(target: &str) -> PrivatelinkProbe {
    PrivatelinkProbe {
        target: target.to_string(),
        reachable: !target.contains("missing"),
        latency_ms: 12,
        endpoint_id: "ep-mock-001".to_string(),
        resolved_ip: "10.20.30.100".to_string(),
        detail: "Mock 探测（AGF_MOCK_MODE）：未发起真实 TCP 连接，返回确定性结果".to_string(),
        at: Timestamp::now(),
    }
}

/// Mock：安全组白名单（键 = 安全组 id，值 = 允许来源 CIDR）。
#[must_use]
pub fn privatelink_security_groups() -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    map.insert("sg-mock-tight".to_string(), vec!["10.20.30.0/24".to_string()]);
    map.insert(
        "sg-mock-wide".to_string(),
        vec!["0.0.0.0/0".to_string(), "10.20.30.0/24".to_string(), "172.16.0.0/12".to_string()],
    );
    map.insert("sg-mock-extra".to_string(), vec!["192.168.0.0/16".to_string()]);
    map.insert("sg-mock-legacy".to_string(), vec!["0.0.0.0/0".to_string()]);
    map
}

/// Mock：SchedulerX3 平台默认任务（6 个）。
#[must_use]
pub fn schedulerx3_jobs(tenant_id: TenantId) -> Vec<SchedulerX3Job> {
    SchedulerX3Job::platform_defaults(tenant_id)
}

/// Mock：SchedulerX3 执行历史（2 条）。
#[must_use]
pub fn schedulerx3_executions() -> Vec<SchedulerX3Execution> {
    let now = Timestamp::now();
    vec![
        SchedulerX3Execution {
            job_id: "job-asset-inventory".to_string(),
            execution_id: "exec-mock-001".to_string(),
            shard_index: Some(0),
            status: "SUCCESS".to_string(),
            at: Some(now.offset_secs(-3_600)),
            scheduled_at_raw: None,
            duration_ms: Some(4_200),
            duration_native: None,
            result: "发现资产 128 项".to_string(),
        },
        SchedulerX3Execution {
            job_id: "job-log-pull".to_string(),
            execution_id: "exec-mock-002".to_string(),
            shard_index: Some(1),
            status: "FAILED".to_string(),
            at: Some(now.offset_secs(-1_800)),
            scheduled_at_raw: None,
            duration_ms: Some(900),
            duration_native: None,
            result: "SLS 项目不存在".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Mock 构造器（与真实适配器同一类型、同一签名）
// ---------------------------------------------------------------------------

/// 构造 Mock 模式的 CMS 适配器（不触网）。
#[must_use]
pub fn mock_cms() -> CmsAdapter {
    CmsAdapter::mocked()
}

/// 构造 Mock 模式的 APIG 适配器（不触网）。
#[must_use]
pub fn mock_apig() -> ApigAdapter {
    ApigAdapter::mocked()
}

/// 构造 Mock 模式的 MSE 适配器（不触网）。
#[must_use]
pub fn mock_mse() -> MseAdapter {
    MseAdapter::mocked()
}

/// 构造 Mock 模式的 PrivateLink 适配器（不触网）。
#[must_use]
pub fn mock_privatelink() -> PrivatelinkAdapter {
    PrivatelinkAdapter::mocked()
}

/// 构造 Mock 模式的 SchedulerX3 适配器（不触网）。
#[must_use]
pub fn mock_schedulerx3() -> SchedulerX3Adapter {
    SchedulerX3Adapter::mocked()
}

/// 构造 Mock 模式的 AgentTeams 适配器（不触网）。
#[must_use]
pub fn mock_agentteams() -> AgentTeamsAdapter {
    AgentTeamsAdapter::mocked()
}

/// Mock 全链路烟测：六个适配器初始化 → 拉取 → 健康 → 关闭（**零网络**）。
///
/// 返回每个服务的 `(Mock 拉取条目数, 健康状态)`。
///
/// # Errors
/// 任一适配器初始化或拉取失败。
#[cfg(test)]
pub async fn smoke_test_all() -> DomainResult<Vec<(AliCloudService, usize, HealthState)>> {
    use crate::agentteams::AgentTeamsApi;
    use crate::apig::ApigApi;
    use crate::cms::CmsApi;
    use crate::mse::MseApi;
    use crate::privatelink::PrivatelinkApi;
    use crate::schedulerx3::SchedulerX3Api;
    use agf_core::adapter::Adapter;

    let mut rows = Vec::new();

    let mut cms = mock_cms();
    cms.init(&crate::test_support::fixture_config(AliCloudService::Cms, true)).await?;
    rows.push((
        AliCloudService::Cms,
        cms.pull_alarm_histories(&PullRequest::default()).await?.len(),
        cms.health().await?.state,
    ));
    cms.shutdown().await?;

    let mut apig = mock_apig();
    apig.init(&crate::test_support::fixture_config(AliCloudService::Apig, true)).await?;
    rows.push((AliCloudService::Apig, apig.pull_gateways().await?.len(), apig.health().await?.state));
    apig.shutdown().await?;

    let mut mse = mock_mse();
    mse.init(&crate::test_support::fixture_config(AliCloudService::Mse, true)).await?;
    rows.push((AliCloudService::Mse, mse.pull_services().await?.len(), mse.health().await?.state));
    mse.shutdown().await?;

    let mut privatelink = mock_privatelink();
    privatelink.init(&crate::test_support::fixture_config(AliCloudService::Privatelink, true)).await?;
    rows.push((
        AliCloudService::Privatelink,
        privatelink.pull_endpoints().await?.len(),
        privatelink.health().await?.state,
    ));
    privatelink.shutdown().await?;

    let mut scheduler = mock_schedulerx3();
    scheduler.init(&crate::test_support::fixture_config(AliCloudService::SchedulerX3, true)).await?;
    rows.push((AliCloudService::SchedulerX3, scheduler.pull_jobs().await?.len(), scheduler.health().await?.state));
    scheduler.shutdown().await?;

    let mut agentteams = mock_agentteams();
    agentteams.init(&crate::test_support::fixture_config(AliCloudService::AgentTeams, true)).await?;
    rows.push((AliCloudService::AgentTeams, agentteams.pull_teams().await?.len(), agentteams.health().await?.state));
    agentteams.shutdown().await?;

    Ok(rows)
}

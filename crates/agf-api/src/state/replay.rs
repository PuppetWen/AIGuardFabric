//! 演示原始日志与回放灌库辅助（自 `state.rs` 拆出）。

use super::*;

/// 演示原始日志 `(origin，协议，载荷)`。
///
/// 载荷是**合成样例**（不含任何真实客户数据），但解析/回放/差分全部走 `agf_ingest` 的真实实现；
/// `origin` 同时是 `/api/v1/ingest/replay?source_id=` 的过滤值（见 `routes::ingest`）。
const DEMO_RAW_LOGS: [(&str, IngestProtocol, &str); 2] = [
    (
        "demo-src-wazuh-json",
        IngestProtocol::Webhook,
        r#"{"timestamp":"2026-03-02T10:00:00.000Z","rule":{"level":10,"description":"sshd: authentication failed","id":"5710"},"agent":{"name":"web-01","ip":"10.0.0.21"},"data":{"srcip":"203.0.113.9","srcuser":"root","protocol":"ssh"},"location":"/var/log/auth.log","full_log":"Failed password for root from 203.0.113.9 port 51234 ssh2"}"#,
    ),
    (
        "demo-src-aliyun-waf",
        IngestProtocol::Webhook,
        r#"{"time":"2026-03-02 10:05:00","host":"api.corp.example","real_client_ip":"198.51.100.7","request_method":"POST","request_uri":"/v1/chat","http_user_agent":"python-requests/2.31.0","rule_id":"waf-sqli-0001","acl_action":"block","status":403,"region":"cn-hangzhou","trace_id":"trace-demo-0001"}"#,
    ),
];

/// 原始日志 id 命名空间（确定性 id：同一演示样例重复灌库不产生新条目）。
const NS_REPLAY_SOURCE: &str = "aiguardfabric.api.replay_source";

/// 确保演示原始日志存在于回放仓储，返回处理的样例条数。
///
/// `agf_ingest::replay::Replayer` 只回放 `parsed=false` 的原始日志，所以这里如实置
/// 首次写入时置 `parsed=false` 并给出一条 `parse_error`。再次启动时按确定性 id
/// 保留已有记录及其解析状态，不重新排队已经回放的样例。
///
/// ## 为什么用 `block_on`
/// `Sink::put_raw` 是 async，而 `AppState::build` 是同步函数（与 `crate::seed` 的剧本执行同一处理）；
/// `InMemorySink::put_raw` 内部只有 `std::sync::Mutex`，**不含 IO、定时器或 reactor 依赖**，
/// 因此在同步上下文里跑它是安全的（不会 panic "no reactor running"）。
///
/// # Errors
/// 仓储写入失败（锁中毒等）。
pub(super) fn seed_replay_raw_logs(sink: &Arc<dyn Sink>, tenant: TenantId) -> DomainResult<usize> {
    if sink.backend() != "memory" {
        return Ok(0);
    }
    futures::executor::block_on(seed_replay_raw_logs_async(sink, tenant))
}

pub(super) async fn seed_replay_raw_logs_async(sink: &Arc<dyn Sink>, tenant: TenantId) -> DomainResult<usize> {
    let mut written = 0_usize;
    for (origin, protocol, payload) in DEMO_RAW_LOGS {
        let raw = RawLog {
            id: agf_core::ids::deterministic_id(NS_REPLAY_SOURCE, &format!("{tenant}:{origin}")),
            tenant_id: tenant,
            source_id: agf_core::ids::deterministic_id(NS_REPLAY_SOURCE, &format!("{tenant}:{origin}:source")),
            received_at: Timestamp::now(),
            protocol,
            payload_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload),
            payload_hash: agf_core::secret::content_hash(payload),
            bytes: payload.len(),
            origin: origin.to_string(),
            parsed: false,
            parse_error: Some("演示原始日志（合成样例）：等待回放重新解析".to_string()),
            event_id: None,
        };
        sink.put_raw(&raw).await?;
        written = written.saturating_add(1);
    }
    Ok(written)
}

impl AppState {
    /// 在数据库启动后异步插入回放样本；不阻塞运行时线程。
    pub async fn seed_replay_samples(&self) -> DomainResult<usize> {
        seed_replay_raw_logs_async(&self.ingest_sink, self.default_tenant).await
    }
}

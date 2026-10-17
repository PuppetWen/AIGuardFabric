//! `pulsar_native_live*.rs` 共用的环境读取与夹具装配（**不是**独立的测试目标：
//! `tests/` 下的**子目录**不会被 Cargo 当成测试二进制，因此这些辅助只会被显式引入的用例编译一次）。
//!
//! 之所以要拆出来：`tests/pulsar_native_live.rs` 会被仓库的**单文件 500 行**门禁卡住
//! （`scripts/check-file-size.ps1`），把"环境变量 + LogSource/流水线夹具 + admin 统计读取"
//! 这一段共享出来，各用例文件只留断言逻辑。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::pulsar::{PulsarInitialPosition, PulsarNativeConfig, PulsarSubscriptionType};
use agf_ingest::registry::ParserRegistry;

/// 原生协议地址（如 `pulsar://127.0.0.1:26650`）。
pub(crate) const ENV_URL: &str = "AGF_E2E_PULSAR_URL";
/// Pulsar web/admin 地址（如 `http://127.0.0.1:28080`）——用来读 `msgBacklog` 证明确实 ack 了。
pub(crate) const ENV_ADMIN: &str = "AGF_E2E_PULSAR_ADMIN";
/// 被测 topic（默认 `persistent://public/default/agf-native`）。
pub(crate) const ENV_TOPIC: &str = "AGF_E2E_PULSAR_TOPIC";
/// 期望消费条数（默认 5）。
pub(crate) const ENV_EXPECT: &str = "AGF_E2E_PULSAR_EXPECT";
/// token（第 2 轮鉴权用；未设置 = 明文第 1 轮）。
pub(crate) const ENV_TOKEN: &str = "AGF_E2E_PULSAR_TOKEN";
/// 第二个 topic（Shared 两副本用例用；默认 `<topic>-shared`）。
pub(crate) const ENV_TOPIC_SHARED: &str = "AGF_E2E_PULSAR_TOPIC_SHARED";

/// 装一个最小 tracing subscriber（只装一次）：真机用例要**贴出退避重连日志**作为证据。
pub(crate) fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "agf_ingest::pulsar=info".to_string()),
            ))
            .with_target(false)
            .try_init();
    });
}

/// 读字符串型环境变量（空白视为未设置）。
pub(crate) fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// `AGF_E2E_PULSAR_URL`（未设置 ⇒ `None`，用例直接跳过）。
pub(crate) fn url() -> Option<String> {
    std::env::var(ENV_URL).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

/// 被测 topic。
pub(crate) fn topic() -> String {
    env_or(ENV_TOPIC, "persistent://public/default/agf-native")
}

/// 期望消费条数。
pub(crate) fn expect_count() -> usize {
    env_or(ENV_EXPECT, "5").parse().unwrap_or(5)
}

/// 每次运行都换一个订阅名：真机上残留游标会让"从 Earliest 重放"的用例不稳定。
pub(crate) fn unique_subscription(prefix: &str) -> String {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    format!("{prefix}-{stamp}")
}

/// 从环境变量拼配置（URL/topic/订阅类型 + token + TLS 信任锚）。
pub(crate) fn config(topic: &str, subscription: &str, sub_type: PulsarSubscriptionType) -> PulsarNativeConfig {
    let base = url().expect("AGF_E2E_PULSAR_URL");
    let mut config = PulsarNativeConfig::new(&base, topic).expect("配置构造");
    config.subscription = subscription.to_string();
    config.subscription_type = sub_type;
    config.initial_position = PulsarInitialPosition::Earliest;
    config.receiver_queue_size = 32;
    config.token = std::env::var(ENV_TOKEN).ok().filter(|value| !value.trim().is_empty());
    // `pulsar+ssl://` 的信任锚 / mTLS / 排障开关（与 `AGF_INGEST_PULSAR_TLS_*` 同名规则）
    config.tls_ca = path_env("AGF_E2E_PULSAR_TLS_CA");
    config.tls_cert = path_env("AGF_E2E_PULSAR_TLS_CERT");
    config.tls_key = path_env("AGF_E2E_PULSAR_TLS_KEY");
    config.tls_insecure_skip_verify =
        std::env::var("AGF_E2E_PULSAR_TLS_INSECURE").is_ok_and(|value| matches!(value.trim(), "1" | "true" | "yes"));
    config.validate().expect("配置校验（TLS 证书/私钥必须成对）");
    config
}

/// 读路径型环境变量。
pub(crate) fn path_env(key: &str) -> Option<std::path::PathBuf> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

/// 造一个接入用的日志源。
pub(crate) fn log_source(name: &str) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: name.to_string(),
        protocol: IngestProtocol::Pulsar,
        vendor: "apache".to_string(),
        product: "pulsar".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Pull,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec!["pulsar-native".to_string()],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

/// 内存落库 + 流水线（真机用例只看"落库了几条/内容对不对"）。
pub(crate) fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 等 broker 侧 `msgBacklog`/`unackedMessages` 归零（**必须轮询**）。
///
/// 为什么不能只看一次：ack 发出去之后，broker 侧的 mark-delete 是**异步**落 metadata store 的，
/// 紧接着读 stats 可能还会看到旧的 backlog（实测：同一份代码在明文轮读到 0、在 TLS 轮读到 2，
/// 3 秒后同为 0）。轮询到 0 才是"ack 真的生效"的稳定证据。
pub(crate) async fn wait_for_backlog_zero(
    topic_full: &str,
    subscription: &str,
    timeout: Duration,
) -> Option<(i64, i64)> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last = None;
    loop {
        if let Some(pair) = admin_subscription_stats(topic_full, subscription).await {
            last = Some(pair);
            if pair == (0, 0) {
                return last;
            }
        }
        if std::time::Instant::now() >= deadline {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// 读某订阅的 `(msgBacklog, unackedMessages)`——**ack 真发了**的最强证据（空实现会一直挂着）。
pub(crate) async fn admin_subscription_stats(topic_full: &str, subscription: &str) -> Option<(i64, i64)> {
    let stats = admin_get(topic_full).await?;
    let stats = stats.get("subscriptions")?.get(subscription)?;
    let backlog = stats.get("msgBacklog").and_then(serde_json::Value::as_i64).unwrap_or(-1);
    let unacked = stats.get("unackedMessages").and_then(serde_json::Value::as_i64).unwrap_or(-1);
    Some((backlog, unacked))
}

/// 该订阅当前挂着的消费者数量（`subscriptions[sub].consumers` 的长度）。
///
/// 用来证明"**两个副本确实同时挂在同一个 Shared 订阅上**"——只看客户端计数是不够的。
pub(crate) async fn admin_consumer_count(topic_full: &str, subscription: &str) -> Option<usize> {
    let stats = admin_get(topic_full).await?;
    let consumers = stats.get("subscriptions")?.get(subscription)?.get("consumers")?.as_array()?;
    Some(consumers.len())
}

/// `GET /admin/v2/persistent/{tenant}/{ns}/{topic}/stats` 的原始 JSON。
///
/// **必须带 `authoritative=true`**：Pulsar 的 `/stats` 默认返回**缓存快照**
/// （`statsUpdateFrequencyInSecs` 默认 60s 才刷新一次），拿它做断言会得到"同一份代码
/// 这次读到 0、下次读到 2"的伪随机结果（实测踩过：消费者计数 3 次里失败 1 次、
/// backlog 归零在明文轮与 TLS 轮读出不同值）。`authoritative=true` 让 broker 现算一份，
/// 断言因此是**确定性**的。
pub(crate) async fn admin_get(topic_full: &str) -> Option<serde_json::Value> {
    let admin = std::env::var(ENV_ADMIN).ok()?.trim().to_string();
    if admin.is_empty() {
        return None;
    }
    let path = topic_full.replace("persistent://", "");
    let url = format!("{}/admin/v2/persistent/{path}/stats?authoritative=true", admin.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let mut request = client.get(&url).timeout(Duration::from_secs(5));
    if let Ok(token) = std::env::var(ENV_TOKEN) {
        if !token.trim().is_empty() {
            request = request.bearer_auth(token.trim());
        }
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json().await.ok()
}

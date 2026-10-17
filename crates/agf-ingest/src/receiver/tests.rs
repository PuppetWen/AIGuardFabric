//! 接收器单元测试：常量时间比较、Webhook、文件采集、HTTP Pull 与 KoP 解析（Pulsar/能力矩阵与上行用例见子模块）。

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use axum::body::Body;
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;

const SYSLOG: &[u8] =
    b"<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2";

fn log_source(protocol: IngestProtocol) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "test-source".to_string(),
        protocol,
        vendor: "generic".to_string(),
        product: "syslog".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: Some(5),
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

#[test]
fn constant_time_eq_behaves_like_equality() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn webhook_bearer_verification() {
    let (pipeline, _sink) = pipeline_and_sink();
    let no_token = WebhookReceiver::new(pipeline, log_source(IngestProtocol::Webhook), "/ingest/webhook");
    assert!(no_token.verify_bearer(None), "未配置令牌时放行");
    assert!(no_token.token().is_none());
    assert!(no_token.authorize(None).is_ok());

    let (pipeline, _sink) = pipeline_and_sink();
    let secured = WebhookReceiver::new(pipeline, log_source(IngestProtocol::Webhook), "/ingest/webhook")
        .with_token("s3cr3t-token-value");
    assert!(secured.verify_bearer(Some("Bearer s3cr3t-token-value")));
    assert!(secured.verify_bearer(Some("s3cr3t-token-value")));
    assert!(!secured.verify_bearer(Some("Bearer wrong-token-value")));
    assert!(!secured.verify_bearer(None));
    assert!(matches!(secured.authorize(Some("nope")), Err(DomainError::Unauthenticated(_))));
    assert!(secured.authorize(Some("Bearer s3cr3t-token-value")).is_ok());
    assert_eq!(secured.path(), "/ingest/webhook");
    assert_eq!(secured.describe().status, ReceiverStatus::Ready);
    assert!(secured.describe().note.contains("Bearer"));
}

#[test]
fn webhook_split_payloads_handles_shapes() {
    assert_eq!(WebhookReceiver::split_payloads(b"", 10).len(), 0);
    let single = br#"{"a":1}"#;
    assert_eq!(WebhookReceiver::split_payloads(single, 10).len(), 1);
    let array = br#"[{"a":1},{"b":2},{"c":3}]"#;
    assert_eq!(WebhookReceiver::split_payloads(array, 10).len(), 3);
    assert_eq!(WebhookReceiver::split_payloads(array, 2).len(), 2, "max_batch 生效");
    let ndjson = b"{\"a\":1}\n{\"b\":2}\n";
    assert_eq!(WebhookReceiver::split_payloads(ndjson, 10).len(), 2);
    let pretty = b"{\n  \"a\": 1\n}";
    assert_eq!(WebhookReceiver::split_payloads(pretty, 10).len(), 3, "多行 JSON 按行拆分（调用方应送单行或数组）");
}

#[tokio::test]
async fn webhook_router_accepts_and_rejects() {
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = Arc::new(
        WebhookReceiver::new(Arc::clone(&pipeline), log_source(IngestProtocol::Webhook), "/ingest/webhook")
            .with_token("token-abc-123456"),
    );
    let app = webhook_router(Arc::clone(&receiver));

    let unauthorized =
        axum::http::Request::builder().method("POST").uri("/ingest/webhook").body(Body::from(SYSLOG.to_vec()));
    assert!(unauthorized.is_ok());
    let Ok(request) = unauthorized else { return };
    let response = app.clone().oneshot(request).await;
    assert!(response.is_ok());
    // oneshot 的 Err 类型是 Infallible：`Ok` 模式在此不可反驳，无需 else 分支
    let Ok(response) = response;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let authorized = axum::http::Request::builder()
        .method("POST")
        .uri("/ingest/webhook")
        .header("authorization", "Bearer token-abc-123456")
        .body(Body::from(SYSLOG.to_vec()));
    assert!(authorized.is_ok());
    let Ok(request) = authorized else { return };
    let response = app.clone().oneshot(request).await;
    assert!(response.is_ok());
    let Ok(response) = response;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));

    let empty = axum::http::Request::builder()
        .method("POST")
        .uri("/ingest/webhook")
        .header("authorization", "Bearer token-abc-123456")
        .body(Body::from(Vec::new()));
    assert!(empty.is_ok());
    let Ok(request) = empty else { return };
    let response = app.oneshot(request).await;
    assert!(response.is_ok());
    let Ok(response) = response;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// webhook 响应必须**如实**给出解析命中数（修复前只有 `accepted`，命中与否不可观测）。
#[tokio::test]
async fn webhook_response_reports_matched_unmatched_and_parsers() {
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver =
        Arc::new(WebhookReceiver::new(Arc::clone(&pipeline), log_source(IngestProtocol::Webhook), "/ingest/webhook"));
    let app = webhook_router(Arc::clone(&receiver));
    // 一条可命中（内置 syslog 模板）+ 一条无模板可命中的自由文本
    let payloads = vec![String::from_utf8_lossy(SYSLOG).to_string(), "完全无法识别的自由文本".to_string()];
    let body = serde_json::to_string(&payloads).unwrap_or_default();
    let request = axum::http::Request::builder().method("POST").uri("/ingest/webhook").body(Body::from(body));
    assert!(request.is_ok());
    let Ok(request) = request else { return };
    let response = app.oneshot(request).await;
    assert!(response.is_ok());
    let Ok(response) = response;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap_or_default();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(json.get("total").and_then(Value::as_u64), Some(2), "{json}");
    assert_eq!(json.get("matched").and_then(Value::as_u64), Some(1), "响应必须给出命中数: {json}");
    assert_eq!(json.get("unmatched").and_then(Value::as_u64), Some(1), "未命中必须如实计数: {json}");
    // accepted = 已落库条数（含未命中模板的载荷）：这正是"accepted 不能说明命中的原因"，
    // 因此 matched/unmatched 必须并列给出（修复前只有 accepted，命中率不可观测）。
    assert_eq!(json.get("accepted").and_then(Value::as_u64), Some(2), "accepted 是落库条数: {json}");
    let parsers = json.get("parsers").and_then(Value::as_object);
    assert_eq!(parsers.map(serde_json::Map::len), Some(1), "命中模板分布必须可见: {json}");
    assert!(parsers.is_some_and(|m| m.values().all(|v| v.as_u64() == Some(1))), "{json}");
    // 进程内计数与响应一致（apps/ingest 的 /metrics 直接读它）
    assert_eq!(receiver.counters().matched(), 1);
    assert_eq!(receiver.counters().unmatched(), 1);
}

#[tokio::test]
async fn webhook_ingest_batch_splits_array() {
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = WebhookReceiver::new(pipeline, log_source(IngestProtocol::Webhook), "/ingest/webhook");
    let body = format!("[\"{}\",\"{}\"]", String::from_utf8_lossy(SYSLOG), String::from_utf8_lossy(SYSLOG));
    let outcomes = receiver.ingest(body.as_bytes(), "1.2.3.4").await;
    assert!(outcomes.is_ok(), "{outcomes:?}");
    let Ok(outcomes) = outcomes else { return };
    assert_eq!(outcomes.len(), 2);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1), "同内容同时间去重后只剩 1 条");
}

#[tokio::test]
async fn file_tail_reads_only_new_complete_lines() {
    let dir = std::env::temp_dir().join(format!("agf-tail-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(&dir).is_ok());
    let path = dir.join("app.log");
    assert!(std::fs::write(&path, "<13>line one\n<13>line two\n<13>half").is_ok());
    let receiver = FileTailReceiver::new(&path);
    let first = receiver.read_new_lines().await.unwrap_or_default();
    assert_eq!(first.len(), 2, "半行不应被消费: {first:?}");
    assert!(first.first().map(|l| l.contains("line one")).unwrap_or(false));
    assert!(receiver.offset() > 0);

    let second = receiver.read_new_lines().await.unwrap_or_default();
    assert!(second.is_empty(), "无新内容时不应重复读取");

    let file = tokio::fs::OpenOptions::new().append(true).open(&path).await;
    assert!(file.is_ok());
    let Ok(mut file) = file else { return };
    assert!(file.write_all(b" line\n<13>line three\n").await.is_ok());
    assert!(file.flush().await.is_ok());
    let third = receiver.read_new_lines().await.unwrap_or_default();
    assert_eq!(third.len(), 2);
    assert!(third.first().map(|l| l.ends_with("half line")).unwrap_or(false));
    assert!(third.get(1).map(|l| l.contains("line three")).unwrap_or(false));

    // 文件被轮转/截断：偏移归零后重读
    assert!(std::fs::write(&path, "<13>fresh\n").is_ok());
    let fourth = receiver.read_new_lines().await.unwrap_or_default();
    assert_eq!(fourth, vec!["<13>fresh".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn file_tail_poll_once_feeds_pipeline() {
    let dir = std::env::temp_dir().join(format!("agf-tail2-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(&dir).is_ok());
    let path = dir.join("app.log");
    assert!(std::fs::write(&path, "<13>alpha\n<13>beta\n").is_ok());
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = FileTailReceiver::new(&path);
    let source = log_source(IngestProtocol::File);
    let count = receiver.poll_once(Arc::clone(&pipeline), source, 10).await;
    assert_eq!(count.ok(), Some(2));
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));
    assert_eq!(receiver.protocol(), IngestProtocol::File);
    assert!(receiver.describe().todo.unwrap_or_default().contains("TODO ingest-notify-watch"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_tail_from_source_requires_path() {
    let mut source = log_source(IngestProtocol::File);
    assert!(FileTailReceiver::from_source(&source).is_err());
    source.connection.file_path = Some("logs/app.log".to_string());
    let receiver = FileTailReceiver::from_source(&source);
    assert!(receiver.is_ok());
    assert_eq!(receiver.ok().map(|r| r.path().to_string_lossy().to_string()), Some("logs/app.log".to_string()));
}

#[tokio::test]
async fn http_pull_with_injected_fetcher() {
    #[derive(Debug)]
    struct StaticFetcher(Vec<u8>);
    #[async_trait]
    impl HttpFetcher for StaticFetcher {
        async fn fetch(&self, _url: &str, _headers: &BTreeMap<String, String>) -> DomainResult<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    let body = b"{\"time\":\"2026-02-21T10:23:45Z\",\"host\":\"a\",\"real_client_ip\":\"203.0.113.9\",\"rule_id\":\"R1\",\"acl_action\":\"block\"}\n{\"time\":\"2026-02-21T10:23:46Z\",\"host\":\"b\",\"real_client_ip\":\"203.0.113.10\",\"rule_id\":\"R2\",\"acl_action\":\"block\"}\n".to_vec();
    let receiver =
        HttpPullReceiver::new("https://siem.example.com/api/logs", BTreeMap::new(), Arc::new(StaticFetcher(body)));
    assert_eq!(receiver.endpoint(), "https://siem.example.com/api/logs");
    assert!(receiver.cursor().is_none());
    receiver.set_cursor(Some("2026-02-21T10:23:46Z".to_string()));
    assert_eq!(receiver.cursor().as_deref(), Some("2026-02-21T10:23:46Z"));

    let (pipeline, sink) = pipeline_and_sink();
    let count = receiver.poll_once(Arc::clone(&pipeline), log_source(IngestProtocol::HttpPull), 10).await;
    assert_eq!(count.ok(), Some(2), "NDJSON 两行应各自接入");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));
    assert_eq!(receiver.protocol(), IngestProtocol::HttpPull);
    assert!(receiver.describe().todo.is_none());
}

#[test]
fn http_pull_requires_endpoint_and_splits_records() {
    let source = log_source(IngestProtocol::HttpPull);
    let fetcher: Arc<dyn HttpFetcher> = Arc::new(fallback_fetcher());
    assert!(HttpPullReceiver::from_source(&source, Arc::clone(&fetcher)).is_err());
    assert_eq!(HttpPullReceiver::split_records(b"", 10).len(), 0);
    assert_eq!(HttpPullReceiver::split_records(br#"[{"a":1},{"b":2}]"#, 10).len(), 2);
    assert_eq!(HttpPullReceiver::split_records(b"{\"a\":1}", 10).len(), 1);
    assert_eq!(HttpPullReceiver::split_records(b"{\"a\":1}\n{\"b\":2}\n", 10).len(), 2);
    // reqwest 客户端构造不需要网络
    assert!(ReqwestFetcher::with_limits(1, 1_024).is_ok());
}

/// 测试用的平凡 fetcher（不发起任何请求）。
fn fallback_fetcher() -> ReqwestFetcher {
    ReqwestFetcher { client: reqwest::Client::new(), max_bytes: 1 }
}

/// KoP 端点解析：Kafka 协议地址接受，**Pulsar 原生端口必须被显式拒绝**（不静默降级）。
#[test]
fn kop_endpoint_parsing_rejects_native_protocol() {
    let ok = parse_kop_endpoint("kafka://kop-1:9092,kop-2:9092");
    assert!(ok.is_ok(), "{ok:?}");
    let Ok(ok) = ok else { return };
    assert_eq!(ok.brokers, vec!["kop-1:9092".to_string(), "kop-2:9092".to_string()]);
    assert!(ok.note.is_empty());
    // 直接 host:port / plaintext:// 同样接受
    assert_eq!(
        parse_kop_endpoint("127.0.0.1:19092").ok().map(|k| k.brokers),
        Some(vec!["127.0.0.1:19092".to_string()])
    );
    assert!(parse_kop_endpoint("plaintext://kop:9092").is_ok());
    // 原生协议端口：明确拒绝（并说明经 KoP 复用才是已实现路径）
    let native = parse_kop_endpoint("pulsar://pulsar-1:6650");
    assert!(matches!(native, Err(DomainError::Config(_))), "{native:?}");
    let message = native.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains("原生协议"), "{message}");
    assert!(message.contains("KoP"), "{message}");
    assert!(parse_kop_endpoint("pulsar+ssl://pulsar-1:6651").is_err());
    // 写了 pulsar:// 但不是原生端口：按 KoP 地址解析并给出提示
    let odd = parse_kop_endpoint("pulsar://pulsar-1:19092");
    assert!(odd.is_ok(), "{odd:?}");
    assert!(odd.map(|k| k.note.contains("KoP")).unwrap_or(false), "必须提示已按 KoP 解析");
    // 其它错误
    assert!(parse_kop_endpoint("").is_err());
    assert!(parse_kop_endpoint("kop").is_err(), "缺端口必须报错");
    assert!(parse_kop_endpoint("amqp://kop:9092").is_err(), "未知 scheme 必须报错");
}

/// KoP topic → Kafka topic 名（末段）+ tenant/namespace。
#[test]
fn kop_topic_name_maps_pulsar_topic_to_kafka_topic() {
    assert_eq!(kop_topic_name("agf-ingest-test"), ("agf-ingest-test".to_string(), None));
    assert_eq!(
        kop_topic_name("persistent://public/default/agf-ingest-test"),
        ("agf-ingest-test".to_string(), Some("public/default".to_string()))
    );
    assert_eq!(
        kop_topic_name("persistent://agf-tenant/ns1/sec-logs"),
        ("sec-logs".to_string(), Some("agf-tenant/ns1".to_string()))
    );
}

/// KoP PLAIN 口令必须补成 `<authMethod>:<authData>`（裸 token 会被 KoP 拒绝）。
#[test]
fn kop_plain_password_prefixes_auth_method() {
    assert_eq!(kop_plain_password("eyJhbGciOiJIUzI1NiJ9.abc.def"), "token:eyJhbGciOiJIUzI1NiJ9.abc.def");
    assert_eq!(kop_plain_password("  eyJx.y.z  "), "token:eyJx.y.z", "首尾空白必须去掉");
    assert_eq!(kop_plain_password("token:eyJx.y.z"), "token:eyJx.y.z", "已带前缀就原样使用");
    assert_eq!(kop_plain_password("other:data"), "other:data", "支持其它 authMethod 前缀");
}

/// KoP SASL/PLAIN 的 username 必须是被授权角色：从 JWT 的 `sub` 取，取不到才回退 `token`。
#[test]
fn kop_plain_username_uses_jwt_subject() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    // 用 Pulsar 真实 token 的编码方式（base64url，无填充）：{"sub":"agf-ingest"}
    let header = B64URL.encode(br#"{"alg":"HS256"}"#);
    let payload = B64URL.encode(br#"{"sub":"agf-ingest"}"#);
    let token = format!("{header}.{payload}.signature");
    assert_eq!(kop_plain_username(&token), "agf-ingest");
    // 已带 authMethod 前缀的写法同样能取到 sub
    assert_eq!(kop_plain_username(&format!("token:{token}")), "agf-ingest");
    // 解析失败/缺 sub ⇒ 回退文档默认值（不 panic）
    assert_eq!(kop_plain_username("not-a-jwt"), "token");
    assert_eq!(kop_plain_username("a.!!!.c"), "token");
    let no_sub = format!("{header}.{}.sig", B64URL.encode(br#"{"iss":"x"}"#));
    assert_eq!(kop_plain_username(&no_sub), "token");
}

mod pulsar;
mod uplink;

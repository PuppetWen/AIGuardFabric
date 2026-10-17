//! 回放单元测试：配置解读、差分计算与报告渲染。

use super::*;
use crate::pipeline::{InMemorySink, Sink};
use agf_core::enums::{IngestProtocol, Severity};
use agf_core::event::{EventAction, EventCategory, RawLog};
use agf_core::time::Timestamp;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// 先无法解析（无模板）的样本：JSON 键名与所有内置模板都不同。
const ODD_JSON: &str =
    r#"{"zzz_client":"203.0.113.42","zzz_level":"high","zzz_detail":"异常登录","zzz_action":"block"}"#;

fn raw_log(id: Id, tenant: TenantId, source_id: Id, payload: &str, parsed: bool, event_id: Option<Id>) -> RawLog {
    RawLog {
        id,
        tenant_id: tenant,
        source_id,
        received_at: Timestamp::now(),
        protocol: IngestProtocol::Webhook,
        payload_b64: B64.encode(payload),
        payload_hash: agf_core::secret::content_hash(payload),
        bytes: payload.len(),
        origin: "replay-fixture".to_string(),
        parsed,
        parse_error: if parsed { None } else { Some("无模板命中".to_string()) },
        event_id,
    }
}

fn ai_template() -> agf_core::parser::ParserDefinition {
    use agf_core::parser::{FieldMapping, ParserEngine};
    let mapping = FieldMapping {
        map: BTreeMap::from([
            ("zzz_client".to_string(), "source.ip".to_string()),
            ("zzz_detail".to_string(), "message".to_string()),
        ]),
        severity_field: Some("zzz_level".to_string()),
        severity_map: BTreeMap::from([("high".to_string(), Severity::High)]),
        action_field: Some("zzz_action".to_string()),
        ..FieldMapping::default()
    };
    agf_core::parser::ParserDefinition {
        key: "zzz-custom-webhook".to_string(),
        name: "自研 Webhook".to_string(),
        vendor: "自研".to_string(),
        product: "Webhook".to_string(),
        protocols: vec![IngestProtocol::Webhook],
        engine: ParserEngine::JsonPath,
        pattern: [
            "zzz_client=$.zzz_client",
            "zzz_level=$.zzz_level",
            "zzz_detail=$.zzz_detail",
            "zzz_action=$.zzz_action",
        ]
        .join("\n"),
        fallback_patterns: vec![],
        mapping,
        derived: BTreeMap::new(),
        required_fields: vec![],
        version: 1,
        builtin: false,
        ai_inferred: false,
        description: "回放测试模板".to_string(),
        sample_fixture: String::new(),
    }
}

#[tokio::test]
async fn replay_reports_failure_when_no_template_matches() {
    let sink = Arc::new(InMemorySink::new());
    let raw_id = Id::new();
    let raw = raw_log(raw_id, TenantId::default_tenant(), Id::new(), ODD_JSON, false, None);
    assert!(sink.put_raw(&raw).await.is_ok());
    let registry = Arc::new(Mutex::new(ParserRegistry::with_builtins()));
    let replayer = Replayer::plain(Arc::clone(&sink) as Arc<dyn Sink>, registry, ReplayConfig::default());
    let report = replayer.replay(10).await;
    assert!(report.is_ok(), "{report:?}");
    let Ok(report) = report else { return };
    assert_eq!(report.replayed, 1);
    assert_eq!(report.newly_parsed, 0);
    assert_eq!(report.failed, 1);
    assert!(report.is_noop());
    assert!(!report.failures.is_empty());
    assert_eq!(sink.unparsed_raw(TenantId::default_tenant(), 10).await.unwrap_or_default().len(), 1);
}

#[tokio::test]
async fn replay_parses_after_template_is_added_and_diffs_against_previous_event() {
    let tenant = TenantId::default_tenant();
    let sink = Arc::new(InMemorySink::new());
    let source_id = Id::new();
    // 既有事件（当初无模板，判为 Other/Info）
    let mut previous = Event::new(tenant, source_id, IngestProtocol::Webhook);
    previous.message = ODD_JSON.to_string();
    previous.raw_hash = agf_core::secret::content_hash(ODD_JSON);
    previous.category = EventCategory::Other;
    previous.action = EventAction::Unknown;
    assert!(sink.put_event(&previous).await.is_ok());
    let raw_id = Id::new();
    let raw = raw_log(raw_id, tenant, source_id, ODD_JSON, false, Some(previous.id));
    assert!(sink.put_raw(&raw).await.is_ok());

    let registry = Arc::new(Mutex::new(ParserRegistry::with_builtins()));
    let replayer = Replayer::plain(Arc::clone(&sink) as Arc<dyn Sink>, Arc::clone(&registry), ReplayConfig::default());
    let before = replayer.replay(10).await.unwrap_or_default();
    assert_eq!(before.newly_parsed, 0, "模板未就绪时不应解析成功");

    // 补上模板后再次回放
    {
        let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(guard.register(ai_template(), 5_000).is_ok());
    }
    let after = replayer.replay(10).await;
    assert!(after.is_ok(), "{after:?}");
    let Ok(after) = after else { return };
    assert_eq!(after.replayed, 1);
    assert_eq!(after.newly_parsed, 1);
    assert_eq!(after.failed, 0);
    assert_eq!(after.parser_used.get("zzz-custom-webhook"), Some(&1));
    assert_eq!(after.diffs.len(), 1);
    let diff = after.diffs.first();
    assert_eq!(diff.and_then(|d| d.previous_event), Some(previous.id));
    let changes = diff.map(|d| d.changes.clone()).unwrap_or_default();
    let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
    assert!(paths.contains(&"event.severity"), "等级应从 info 变为 high: {paths:?}");
    assert!(paths.contains(&"event.category"), "类别应被重新判定: {paths:?}");
    assert!(paths.contains(&"network.source_ip"));
    assert!(paths.contains(&"parser_name"));

    // 原始日志被标记为已解析，事件总数 +1
    let unparsed = sink.unparsed_raw(tenant, 10).await.unwrap_or_default();
    assert!(unparsed.is_empty());
    assert_eq!(sink.event_count(tenant).await.ok(), Some(2));
}

#[tokio::test]
async fn replay_can_skip_marking_and_respects_limit() {
    let tenant = TenantId::default_tenant();
    let sink = Arc::new(InMemorySink::new());
    for _ in 0..3 {
        let raw = raw_log(Id::new(), tenant, Id::new(), ODD_JSON, false, None);
        assert!(sink.put_raw(&raw).await.is_ok());
    }
    let registry = Arc::new(Mutex::new(ParserRegistry::with_builtins()));
    {
        let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(guard.register(ai_template(), 5_000).is_ok());
    }
    let config = ReplayConfig { mark_parsed: false, ..ReplayConfig::default() };
    let replayer = Replayer::plain(Arc::clone(&sink) as Arc<dyn Sink>, registry, config);
    let report = replayer.replay(2).await.unwrap_or_default();
    assert_eq!(report.replayed, 2, "limit 生效");
    assert_eq!(report.newly_parsed, 2);
    assert_eq!(
        sink.unparsed_raw(tenant, 10).await.unwrap_or_default().len(),
        3,
        "mark_parsed=false 不应改变原始日志状态"
    );
}

#[tokio::test]
async fn replay_reports_decode_failure() {
    let tenant = TenantId::default_tenant();
    let sink = Arc::new(InMemorySink::new());
    let mut raw = raw_log(Id::new(), tenant, Id::new(), "x", false, None);
    raw.payload_b64 = "!!!!".to_string();
    assert!(sink.put_raw(&raw).await.is_ok());
    let registry = Arc::new(Mutex::new(ParserRegistry::with_builtins()));
    let replayer = Replayer::plain(Arc::clone(&sink) as Arc<dyn Sink>, registry, ReplayConfig::default());
    let report = replayer.replay(10).await.unwrap_or_default();
    assert_eq!(report.failed, 1);
    assert!(report.failures.first().map(|f| f.reason.contains("base64")).unwrap_or(false));
}

#[test]
fn diff_detects_and_ignores_fields() {
    let tenant = TenantId::default_tenant();
    let mut a = Event::new(tenant, Id::new(), IngestProtocol::Syslog);
    a.severity = Severity::Info;
    a.message = "m".to_string();
    let mut b = a.clone();
    assert!(diff_events(&a, &b).is_empty(), "完全相同不应有差分");
    b.severity = Severity::Critical;
    b.category = EventCategory::Intrusion;
    let changes = diff_events(&a, &b);
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert!(changes.iter().any(|c| c.path == "event.severity"));
    assert_eq!(
        changes.iter().find(|c| c.path == "event.severity").and_then(|c| c.after.clone()),
        Some(Value::from("critical"))
    );
}

#[test]
fn comparable_fields_covers_core_paths() {
    let mut e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Webhook);
    e.host.name = Some("h1".to_string());
    e.network.source_ip = Some("10.0.0.1".to_string());
    e.user.name = Some("alice".to_string());
    e.action_raw = "block".to_string();
    let fields = comparable_fields(&e);
    for path in [
        "event.time",
        "event.severity",
        "event.category",
        "event.action",
        "host.name",
        "network.source_ip",
        "user.name",
        "message",
    ] {
        assert!(fields.contains_key(path), "缺少 {path}");
    }
}

#[test]
fn report_renders_markdown() {
    let mut report = ReplayReport { replayed: 2, newly_parsed: 1, failed: 1, ..ReplayReport::default() };
    report.parser_used.insert("p1".to_string(), 1);
    report.failures.push(ReplayFailure { raw_id: Id::new(), reason: "无模板".to_string() });
    report.diffs.push(ReplayDiff {
        raw_id: Id::new(),
        parser_key: Some("p1".to_string()),
        previous_event: Some(Id::new()),
        new_event: Some(Id::new()),
        changes: vec![FieldDiff {
            path: "event.severity".to_string(),
            before: Some(Value::from("info")),
            after: Some(Value::from("high")),
        }],
    });
    let md = render_report(&report);
    assert!(md.contains("# 原始日志回放报告"));
    assert!(md.contains("解析器使用"));
    assert!(md.contains("失败明细"));
    assert!(md.contains("event.severity"));
}

#[test]
fn protocol_label_is_stable() {
    assert_eq!(protocol_label(IngestProtocol::Syslog), "syslog");
    assert_eq!(protocol_label(IngestProtocol::HttpPull), "http-pull");
}

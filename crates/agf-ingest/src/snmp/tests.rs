//! SNMP 单元测试：BER/Trap 构造夹具与 v1/v2c/接收器用例（v3/USM 用例见 `v3` 子模块）。

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use agf_core::time::Timestamp;

// ---- BER 编码器（复用库里的 encode 模块：与 tools/simulators/snmp_v3_trap.py 同构） ----

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    encode::tlv(tag, value)
}

fn ber_int(value: i64) -> Vec<u8> {
    encode::integer(value)
}

fn ber_octet(text: &str) -> Vec<u8> {
    encode::octet_string(text.as_bytes())
}

/// OID 编码（首两段合并为 40*X+Y）。
fn ber_oid(parts: &[u64]) -> Vec<u8> {
    encode::oid(parts)
}

fn varbind(oid: &[u64], value: &[u8]) -> Vec<u8> {
    let mut body = ber_oid(oid);
    body.extend_from_slice(value);
    tlv(ber::TAG_SEQUENCE, &body)
}

fn unsigned_tlv(tag: u8, value: u64) -> Vec<u8> {
    encode::unsigned(tag, value)
}

/// 构造标准 v2c Trap：3 个 varbind（字符串 / Counter32 / TimeTicks）。
fn v2c_trap(community: &str) -> Vec<u8> {
    let mut varbinds = Vec::new();
    varbinds.extend_from_slice(&varbind(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0], &ber_oid(&[1, 3, 6, 1, 4, 1, 8072, 0, 1])));
    varbinds.extend_from_slice(&varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], &unsigned_tlv(ber::TAG_TIMETICKS, 12_345_678)));
    varbinds.extend_from_slice(&varbind(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1], &ber_octet("eth0")));
    varbinds.extend_from_slice(&varbind(
        &[1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1],
        &unsigned_tlv(ber::TAG_COUNTER32, 4_294_967_295),
    ));
    varbinds.extend_from_slice(&varbind(&[1, 3, 6, 1, 4, 1, 9999, 1], &tlv(ber::TAG_IP_ADDRESS, &[203, 0, 113, 77])));

    let mut pdu = ber_int(1_048_576);
    pdu.extend_from_slice(&ber_int(0));
    pdu.extend_from_slice(&ber_int(0));
    pdu.extend_from_slice(&tlv(ber::TAG_SEQUENCE, &varbinds));

    let mut message = ber_int(1); // version = v2c
    message.extend_from_slice(&ber_octet(community));
    message.extend_from_slice(&tlv(ber::TAG_TRAP_V2, &pdu));
    tlv(ber::TAG_SEQUENCE, &message)
}

/// 构造 v1 Trap（Enterprise + agent-addr + generic/specific）。
fn v1_trap(community: &str) -> Vec<u8> {
    let mut varbinds = Vec::new();
    varbinds.extend_from_slice(&varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], &unsigned_tlv(ber::TAG_TIMETICKS, 1_234_500)));
    let mut pdu = ber_oid(&[1, 3, 6, 1, 4, 1, 9]);
    pdu.extend_from_slice(&tlv(ber::TAG_IP_ADDRESS, &[192, 168, 1, 5]));
    pdu.extend_from_slice(&ber_int(6)); // generic-trap = enterpriseSpecific
    pdu.extend_from_slice(&ber_int(42)); // specific-trap
    pdu.extend_from_slice(&unsigned_tlv(ber::TAG_TIMETICKS, 1_234_500));
    pdu.extend_from_slice(&tlv(ber::TAG_SEQUENCE, &varbinds));

    let mut message = ber_int(0); // version = v1
    message.extend_from_slice(&ber_octet(community));
    message.extend_from_slice(&tlv(ber::TAG_TRAP_V1, &pdu));
    tlv(ber::TAG_SEQUENCE, &message)
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "snmp-test".to_string(),
        protocol: IngestProtocol::SnmpTrap,
        vendor: "generic".to_string(),
        product: "snmp".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
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

fn receiver() -> SnmpTrapReceiver {
    let (pipeline, _sink) = pipeline_and_sink();
    SnmpTrapReceiver {
        pipeline,
        source: log_source(),
        listen: "127.0.0.1:0".to_string(),
        community: Some("public".to_string()),
        version: "v2c".to_string(),
        usm: None,
        usm_stats: Arc::new(UsmStats::new()),
        engine_clock: EngineClock::new(),
        max_datagram_bytes: 65_535,
        counters: Arc::new(ReceiverCounters::new()),
    }
}

fn v3_receiver(usm: UsmConfig) -> (SnmpTrapReceiver, Arc<InMemorySink>) {
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = SnmpTrapReceiver {
        pipeline,
        source: log_source(),
        listen: "127.0.0.1:0".to_string(),
        community: None,
        version: "v3".to_string(),
        usm: Some(usm),
        usm_stats: Arc::new(UsmStats::new()),
        engine_clock: EngineClock::new(),
        max_datagram_bytes: 65_535,
        counters: Arc::new(ReceiverCounters::new()),
    };
    (receiver, sink)
}

#[test]
fn ber_primitives_decode_correctly() {
    assert_eq!(ber::decode_integer(&[0x00]), 0);
    assert_eq!(ber::decode_integer(&[0x7f]), 127);
    assert_eq!(ber::decode_integer(&[0x00, 0x80]), 128);
    assert_eq!(ber::decode_integer(&[0xff]), -1);
    assert_eq!(ber::decode_integer(&[0xff, 0x7f]), -129);
    assert_eq!(ber::decode_unsigned(&[0xff, 0xff]), 65_535);
    assert_eq!(ber::decode_oid(&[0x2b, 0x06, 0x01, 0x04]).ok().as_deref(), Some("1.3.6.1.4"));
    assert!(ber::decode_oid(&[]).is_err());
    assert_eq!(ber::format_timeticks(0), "0 days, 00:00:00.00");
    assert_eq!(ber::format_timeticks(12_345_678), "1 day, 10:17:36.78");
    assert_eq!(ber::format_timeticks(100), "0 days, 00:00:01.00");
    assert_eq!(ber::render_bytes(b"eth0"), "eth0");
    assert_eq!(ber::render_bytes(&[0x00, 0x01]), "0001");
}

#[test]
fn v2c_trap_parses_all_varbind_syntaxes() {
    let trap = parse_trap(&v2c_trap("public"), Some("public"));
    assert!(trap.is_ok(), "{trap:?}");
    let Ok(trap) = trap else { return };
    assert_eq!(trap.version, "v2c");
    assert_eq!(trap.community, "public");
    assert_eq!(trap.pdu_type, "trap");
    assert_eq!(trap.request_id, Some(1_048_576));
    assert_eq!(trap.varbinds.len(), 5);
    assert_eq!(trap.trap_oid().as_deref(), Some("1.3.6.1.4.1.8072.0.1"));
    assert_eq!(trap.uptime_ticks(), Some(12_345_678));
    let syntaxes: Vec<&str> = trap.varbinds.iter().map(|vb| vb.syntax.as_str()).collect();
    assert_eq!(syntaxes, vec!["OID", "TimeTicks", "OCTET STRING", "Counter32", "IpAddress"]);
    assert_eq!(trap.varbinds.get(2).map(|vb| vb.value.as_str()), Some("eth0"));
    assert_eq!(trap.varbinds.get(3).map(|vb| vb.value.as_str()), Some("4294967295"));
    assert_eq!(trap.varbinds.get(4).map(|vb| vb.value.as_str()), Some("203.0.113.77"));
    assert!(trap.varbinds.get(1).is_some_and(|vb| vb.value.contains("1 day,")), "{:?}", trap.varbinds.get(1));
    let payload = String::from_utf8_lossy(&trap.to_payload()).to_string();
    assert!(payload.contains("1.3.6.1.4.1.8072.0.1"), "{payload}");
    assert!(payload.contains("varbinds"), "{payload}");
}

#[test]
fn v1_trap_and_pdu_dispatch() {
    let trap = parse_trap(&v1_trap("public"), Some("public"));
    assert!(trap.is_ok(), "{trap:?}");
    let Ok(trap) = trap else { return };
    assert_eq!(trap.version, "v1");
    assert_eq!(trap.enterprise.as_deref(), Some("1.3.6.1.4.1.9"));
    assert_eq!(trap.agent_address.as_deref(), Some("192.168.1.5"));
    assert_eq!(trap.generic_trap, Some(6));
    assert_eq!(trap.specific_trap, Some(42));
    assert_eq!(
        trap.trap_oid().as_deref(),
        Some("1.3.6.1.4.1.9.0.42"),
        "v1 无 snmpTrapOID 时按 enterprise.0.specific 合成"
    );
    assert_eq!(trap.request_id, None);
}

#[test]
fn community_version_and_malformed_inputs_are_rejected() {
    let wrong = parse_trap(&v2c_trap("private"), Some("public"));
    assert!(matches!(wrong, Err(DomainError::Unauthenticated(_))), "{wrong:?}");
    // 不校验 community 时照常解析
    assert!(parse_trap(&v2c_trap("private"), None).is_ok());

    // v3 报文走 parse_trap（无 USM 上下文）时必须显式报告而不是静默按 v2c 解析
    let spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    let v3_message = encode::v3_trap(&spec).unwrap_or_default();
    let result = parse_trap(&v3_message, Some("public"));
    assert!(matches!(result, Err(DomainError::NotImplemented(_))), "{result:?}");
    // parse_message 且无 USM 配置 ⇒ 同样显式拒绝
    let no_usm = parse_message(&v3_message, None, None);
    assert!(matches!(no_usm, Err(DomainError::NotImplemented(_))), "{no_usm:?}");

    // 截断 / 越界长度 / 不定长 / 非 SEQUENCE 顶层
    assert!(parse_trap(&[0x30, 0x05, 0x02], None).is_err(), "长度越界必须报错");
    assert!(parse_trap(&[0x30, 0x80, 0x02, 0x01, 0x01], None).is_err(), "不定长必须报错");
    assert!(parse_trap(&[0x02, 0x01, 0x01], None).is_err(), "顶层非 SEQUENCE 必须报错");
    assert!(parse_trap(&[], None).is_err());
    // 只有 Trap 类 PDU 被接受（GetRequest 0xa0 必须拒绝）
    let mut get = ber_int(1);
    get.extend_from_slice(&ber_octet("public"));
    get.extend_from_slice(&tlv(0xa0, &ber_int(1)));
    let get_message = tlv(ber::TAG_SEQUENCE, &get);
    assert!(matches!(parse_trap(&get_message, None), Err(DomainError::Parse(_))));
}

#[tokio::test]
async fn receiver_ingests_trap_into_pipeline_and_counts() {
    let (pipeline, sink) = pipeline_and_sink();
    let counters = Arc::new(ReceiverCounters::new());
    let Ok(receiver) = SnmpTrapReceiver::new(Arc::clone(&pipeline), log_source(), "127.0.0.1:0", "public", "v2c")
        .map(|r| r.with_counters(Arc::clone(&counters)))
    else {
        return;
    };
    assert_eq!(receiver.listen(), "127.0.0.1:0");
    assert_eq!(receiver.community(), Some("public"));
    let persisted = receiver.ingest_datagram(&v2c_trap("public"), "203.0.113.9:40123").await;
    assert_eq!(persisted.ok(), Some(1));
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.received, 1);
    assert_eq!(snapshot.dropped, 0);

    // community 不匹配 ⇒ 拒绝 + 计数（不落库）
    let rejected = receiver.ingest_datagram(&v2c_trap("private"), "203.0.113.9:40123").await;
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))), "{rejected:?}");
    assert_eq!(counters.snapshot().dropped, 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
}

#[tokio::test]
async fn receiver_binds_udp_socket_and_serves_real_datagram() {
    use tokio::net::UdpSocket;
    let (pipeline, sink) = pipeline_and_sink();
    let Ok(receiver) = SnmpTrapReceiver::new(pipeline, log_source(), "127.0.0.1:0", "public", "v2c") else {
        return;
    };
    let socket = receiver.bind().await;
    assert!(socket.is_ok(), "{socket:?}");
    let Ok(socket) = socket else { return };
    let Ok(local) = socket.local_addr() else { return };
    let serve = tokio::spawn(async move {
        let _ = receiver.serve(socket).await;
    });
    let Ok(client) = UdpSocket::bind("127.0.0.1:0").await else { return };
    let _ = client.send_to(&v2c_trap("public"), local).await;
    let mut landed = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if sink.event_count(TenantId::default_tenant()).await.ok() == Some(1) {
            landed = true;
            break;
        }
    }
    serve.abort();
    assert!(landed, "真实 UDP 收包必须落库");
}

#[test]
fn describe_is_ready_and_reports_true_capability() {
    let receiver = receiver();
    let descriptor = receiver.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert_eq!(descriptor.protocol, IngestProtocol::SnmpTrap);
    assert!(descriptor.note.contains("v2c"), "{}", descriptor.note);
    let todo = descriptor.todo.unwrap_or_default();
    assert!(todo.contains("authPriv（DES/AES）**已实现**"), "必须如实写清 authPriv 已实现：{todo}");
    assert!(todo.contains("ingest-snmp-inform-ack"), "剩余 TODO 锚点必须如实：{todo}");
    assert!(!todo.contains("authPriv 未实现"), "不得再声称 authPriv 未实现：{todo}");
    assert_eq!(receiver.protocol(), IngestProtocol::SnmpTrap);
    // v3 现在是**受支持**的版本：构造成功且默认 noAuthNoPriv
    let (pipeline, _sink) = pipeline_and_sink();
    let v3 = SnmpTrapReceiver::new(pipeline, log_source(), "127.0.0.1:0", "public", "v3");
    assert!(v3.is_ok(), "{v3:?}");
    let Ok(v3) = v3 else { return };
    assert_eq!(v3.version(), "v3");
    assert_eq!(v3.community(), None, "v3 不用 community");
    assert_eq!(v3.usm_config().map(|u| u.level), Some(V3SecurityLevel::NoAuthNoPriv));
    // 未知版本照旧报错
    let (pipeline, _sink) = pipeline_and_sink();
    assert!(SnmpTrapReceiver::new(pipeline, log_source(), "127.0.0.1:0", "public", "v9").is_err());
    // v3 的 describe 必须写明 USM 详情
    let descriptor = v3.describe();
    assert!(descriptor.note.contains("USM v3/noAuthNoPriv"), "{}", descriptor.note);
}

mod privacy;
mod v3;

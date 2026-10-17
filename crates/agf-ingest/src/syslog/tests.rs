//! Syslog 单元测试：RFC5424/3164 解析、PRI、分帧与 TCP 监听器（TLS/UDP 监听器用例见 `listener` 子模块）。

use super::*;

const RFC5424_SD: &str = "<165>1 2026-02-21T10:23:45.123456+08:00 web-prod-01 nginx 2311 ID47 \
        [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] \
        BOM 检测到 SQL 注入尝试";

#[test]
fn rfc5424_full_header_parses() {
    let msg = parse_rfc5424(RFC5424_SD);
    assert!(msg.is_ok(), "解析失败: {msg:?}");
    let Ok(msg) = msg else { return };
    assert_eq!(msg.rfc, SyslogRfc::Rfc5424);
    assert_eq!(msg.version, Some(1));
    assert_eq!(msg.facility, 20);
    assert_eq!(msg.facility_name(), "local4");
    assert_eq!(msg.severity_code, 5);
    assert_eq!(msg.severity, Severity::Low);
    assert_eq!(msg.hostname.as_deref(), Some("web-prod-01"));
    assert_eq!(msg.app_name.as_deref(), Some("nginx"));
    assert_eq!(msg.proc_id.as_deref(), Some("2311"));
    assert_eq!(msg.msg_id.as_deref(), Some("ID47"));
    assert_eq!(msg.sd_param("exampleSDID@32473", "eventID"), Some("1011"));
    assert_eq!(msg.sd_param("examplePriority@32473", "class"), Some("high"));
    assert!(msg.msg.contains("SQL 注入"));
    assert!(msg.timestamp.is_some());
}

#[test]
fn rfc5424_nilvalue_everywhere() {
    let msg = parse_rfc5424("<10>- - - - - - - 无时间戳报文");
    assert!(msg.is_ok());
    let Ok(msg) = msg else { return };
    assert_eq!(msg.version, None, "VERSION 为 - 时应视为缺失");
    assert_eq!(msg.hostname, None);
    assert_eq!(msg.app_name, None);
    assert_eq!(msg.proc_id, None);
    assert_eq!(msg.msg_id, None);
    assert!(msg.structured_data.is_empty());
    assert!(msg.timestamp.is_none());
    assert_eq!(msg.msg, "无时间戳报文");
    assert_eq!(msg.facility, 1);
    assert_eq!(msg.severity, Severity::Critical);
}

#[test]
fn rfc5424_nil_structured_data_with_msg() {
    let msg = parse_rfc5424("<34>1 2026-02-21T10:23:45Z host app 1 - - 消息体");
    assert!(msg.is_ok());
    let Ok(msg) = msg else { return };
    assert!(msg.structured_data.is_empty());
    assert_eq!(msg.msg, "消息体");
    assert_eq!(msg.msg_id, None);
}

#[test]
fn rfc5424_escaped_sd_values() {
    let raw = r#"<190>1 2026-02-21T10:23:45Z h app 1 mid [meta@1 path="C:\\logs\"quoted\".txt" bracket="a\]b"] msg"#;
    let msg = parse_rfc5424(raw);
    assert!(msg.is_ok(), "{msg:?}");
    let Ok(msg) = msg else { return };
    assert_eq!(msg.sd_param("meta@1", "path"), Some(r#"C:\logs"quoted".txt"#));
    assert_eq!(msg.sd_param("meta@1", "bracket"), Some("a]b"));
}

#[test]
fn rfc5424_rejects_bad_version_and_pri() {
    assert_eq!(parse_rfc5424("<165>2 2026-02-21T10:23:45Z h a 1 - - m"), Err(SyslogParseError::UnsupportedVersion(2)));
    assert!(matches!(parse_rfc5424("<abc>1 - - - - - - m"), Err(SyslogParseError::InvalidPri(_))));
    assert_eq!(parse_rfc5424("<999>1 - - - - - - m"), Err(SyslogParseError::InvalidPri("999".to_string())));
    assert_eq!(parse_rfc5424("no pri here"), Err(SyslogParseError::MissingPri));
    assert_eq!(parse_rfc5424("<165>"), Err(SyslogParseError::Truncated("VERSION")));
    assert_eq!(parse_rfc5424("   "), Err(SyslogParseError::Empty));
    assert_eq!(parse_rfc5424("<165>1 2026-02-21T10:23:45Z"), Err(SyslogParseError::Truncated("HOSTNAME")));
}

#[test]
fn rfc5424_unclosed_structured_data_is_rejected() {
    let err = parse_rfc5424("<165>1 2026-02-21T10:23:45Z h a 1 - [meta@1 k=\"v\" msg");
    assert!(matches!(err, Err(SyslogParseError::MalformedStructuredData(_))), "{err:?}");
    let err2 = parse_rfc5424("<165>1 2026-02-21T10:23:45Z h a 1 - [meta@1 k=v] msg");
    assert!(matches!(err2, Err(SyslogParseError::MalformedStructuredData(_))));
}

#[test]
fn pri_math_maps_facility_and_severity() {
    // <0> = kern.emerg, <191> = local7.debug
    let low = parse_pri("<0>rest");
    assert_eq!(low.ok(), Some((0, 0, "rest")));
    let high = parse_pri("<191>rest");
    assert_eq!(high.ok(), Some((23, 7, "rest")));
    assert_eq!(severity_from_syslog(0), Severity::Critical);
    assert_eq!(severity_from_syslog(3), Severity::High);
    assert_eq!(severity_from_syslog(4), Severity::Medium);
    assert_eq!(severity_from_syslog(5), Severity::Low);
    assert_eq!(severity_from_syslog(6), Severity::Info);
    assert_eq!(severity_from_syslog(7), Severity::Info);
    assert_eq!(facility_name(4), "auth");
    assert_eq!(facility_name(99), "unknown");
}

#[test]
fn rfc3164_with_tag_and_pid() {
    let raw =
        "  <34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2"
            .trim_start();
    let msg = parse_rfc3164(raw);
    assert!(msg.is_ok(), "{msg:?}");
    let Ok(msg) = msg else { return };
    assert_eq!(msg.rfc, SyslogRfc::Rfc3164);
    assert_eq!(msg.facility, 4);
    assert_eq!(msg.severity_code, 2);
    assert_eq!(msg.severity, Severity::Critical);
    assert_eq!(msg.hostname.as_deref(), Some("web-prod-01"));
    assert_eq!(msg.app_name.as_deref(), Some("sshd"));
    assert_eq!(msg.proc_id.as_deref(), Some("2311"));
    assert!(msg.msg.contains("Failed password"));
    assert_eq!(msg.timestamp_raw.as_deref(), Some("Feb 21 10:23:45"));
}

#[test]
fn rfc3164_without_pid_and_without_hostname() {
    let tagged = parse_rfc3164("<13>Feb 21 10:23:45 kernel: eth0 link up");
    assert!(tagged.is_ok());
    let Ok(tagged) = tagged else { return };
    assert_eq!(tagged.app_name.as_deref(), Some("kernel"));
    assert_eq!(tagged.proc_id, None);
    assert_eq!(tagged.hostname, None);
    assert_eq!(tagged.msg, "eth0 link up");

    let plain = parse_rfc3164("<13>Feb 21 10:23:45 只有消息体");
    assert!(plain.is_ok());
    let Ok(plain) = plain else { return };
    assert_eq!(plain.app_name, None);
    assert_eq!(plain.msg, "只有消息体");
}

#[test]
fn rfc3164_with_year_variant() {
    let msg = parse_rfc3164("<13>2026-02-21T10:23:45 h1 auditd[9]: 配置被修改");
    assert!(msg.is_ok(), "{msg:?}");
    let Ok(msg) = msg else { return };
    assert_eq!(msg.rfc, SyslogRfc::Rfc3164);
    assert_eq!(msg.hostname.as_deref(), Some("h1"));
    assert_eq!(msg.timestamp.map(|t| t.to_rfc3339()), Some("2026-02-21T10:23:45.000Z".to_string()));
}

#[test]
fn rfc3164_year_rollover_uses_previous_year() {
    let now = Timestamp::parse_rfc3339("2026-01-01T00:10:00Z");
    assert!(now.is_ok());
    let Ok(now) = now else { return };
    let ts = parse_3164_timestamp("Dec 31 23:55:00", now);
    let Some(ts) = ts else { return };
    assert_eq!(ts.to_rfc3339(), "2025-12-31T23:55:00.000Z");
    let same_year = parse_3164_timestamp("Jan  1 00:05:00", now);
    assert_eq!(same_year.map(|t| t.to_rfc3339()), Some("2026-01-01T00:05:00.000Z".to_string()));
}

#[test]
fn rfc3164_malformed_input_rejected() {
    assert_eq!(parse_rfc3164(""), Err(SyslogParseError::Empty));
    assert_eq!(parse_rfc3164("<13>Feb 21"), Err(SyslogParseError::Truncated("TIMESTAMP")));
    let bad = parse_rfc3164("<13>Xxx 99 99:99:99 host app: msg");
    assert!(matches!(bad, Err(SyslogParseError::InvalidTimestamp(_))), "{bad:?}");
}

#[test]
fn auto_detect_picks_correct_rfc() {
    let four = parse_auto("<165>1 2026-02-21T10:23:45Z h a 1 - - m");
    assert_eq!(four.map(|m| m.rfc), Ok(SyslogRfc::Rfc5424));
    let three = parse_auto("<34>Feb 21 10:23:45 h sshd[1]: m");
    assert_eq!(three.map(|m| m.rfc), Ok(SyslogRfc::Rfc3164));
}

#[test]
fn to_fields_exposes_ecs_paths() {
    let msg = parse_rfc5424(RFC5424_SD);
    let Ok(msg) = msg else { return };
    let f = msg.to_fields();
    assert_eq!(f.get("host.name").and_then(serde_json::Value::as_str), Some("web-prod-01"));
    assert_eq!(f.get("event.severity").and_then(serde_json::Value::as_str), Some("low"));
    assert_eq!(f.get("syslog.facility_name").and_then(serde_json::Value::as_str), Some("local4"));
    assert_eq!(f.get("syslog.sd.exampleSDID@32473.eventID").and_then(serde_json::Value::as_str), Some("1011"));
    assert!(f.contains_key("message"));
}

#[test]
fn framing_detects_from_first_byte() {
    assert_eq!(SyslogFraming::detect(b"123 <34>msg"), Framing::OctetCounting);
    assert_eq!(SyslogFraming::detect(b"<34>msg\n"), Framing::NonTransparent);
    assert_eq!(SyslogFraming::detect(b""), Framing::NonTransparent);
    assert_eq!(Framing::OctetCounting.as_str(), "octet-counting");
}

#[test]
fn octet_counting_split_handles_partial_and_multiple() {
    let f1 = b"<34>Feb 21 10:23:45 h a: m1";
    let mut stream = SyslogFraming::encode_octet_counting(f1);
    let split1 = SyslogFraming::split(&stream, 65_536);
    assert_eq!(split1.frames.len(), 1);
    assert_eq!(split1.frames.first().map(Vec::as_slice), Some(f1.as_slice()));
    assert_eq!(split1.consumed, stream.len());
    assert_eq!(split1.dropped, 0);

    // 半帧：长度头已到但帧体未收全 → 不产出帧、不消费
    stream = SyslogFraming::encode_octet_counting(b"<13>need more bytes");
    let cut = stream.len() - 4;
    let head = stream.get(..cut).unwrap_or_default();
    let split2 = SyslogFraming::split(head, 65_536);
    assert!(split2.frames.is_empty());
    assert_eq!(split2.consumed, 0);

    // 拼接后一次切出两帧
    let mut both = SyslogFraming::encode_octet_counting(b"<13>one");
    both.extend_from_slice(&SyslogFraming::encode_octet_counting(b"<13>two"));
    let split3 = SyslogFraming::split(&both, 65_536);
    assert_eq!(split3.frames.len(), 2);
    assert_eq!(split3.frames.get(1).map(Vec::as_slice), Some(b"<13>two".as_slice()));
}

#[test]
fn octet_counting_drops_oversized_and_garbage() {
    let oversized = format!("{} {}", 100, "x".repeat(20)).into_bytes();
    let split = SyslogFraming::split(&oversized, 64);
    assert!(split.frames.is_empty());
    assert_eq!(split.dropped, 1);
    let garbage = b"12x <34>msg";
    let split2 = SyslogFraming::split(garbage, 65_536);
    assert_eq!(split2.dropped, 1);
    assert!(split2.frames.is_empty());
}

#[test]
fn non_transparent_split_handles_crlf_and_empty_lines() {
    let mut buf = SyslogFraming::encode_non_transparent(b"<13>first");
    buf.extend_from_slice(&SyslogFraming::encode_non_transparent(b"<13>second\r"));
    buf.extend_from_slice(b"\n\n");
    let split = SyslogFraming::split(&buf, 65_536);
    assert_eq!(split.frames.len(), 2);
    assert_eq!(split.frames.first().map(Vec::as_slice), Some(b"<13>first".as_slice()));
    assert_eq!(split.frames.get(1).map(Vec::as_slice), Some(b"<13>second".as_slice()));
    assert_eq!(split.consumed, buf.len());
}

#[test]
fn parse_bytes_trims_nul_and_crlf() {
    let raw = b"<34>Feb 21 10:23:45 host app: hi\x00\x00\x00";
    let msg = parse_bytes(raw);
    assert!(msg.is_ok(), "{msg:?}");
    assert_eq!(msg.map(|m| m.msg), Ok("hi".to_string()));
    assert_eq!(trim_nul(b"abc\0\0"), b"abc");
    assert_eq!(trim_nul(b"\0\0"), b"");
}

#[tokio::test]
async fn tcp_listener_reads_octet_counted_frames() {
    let listener = SyslogTcpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let sender = tokio::spawn(async move {
        if let Ok(mut client) = TcpStream::connect(addr).await {
            use tokio::io::AsyncWriteExt;
            let mut payload = SyslogFraming::encode_octet_counting(b"<34>Feb 21 10:23:45 h a: m1");
            payload.extend_from_slice(&SyslogFraming::encode_octet_counting(b"<13>m2"));
            let _ = client.write_all(&payload).await;
            let _ = client.flush().await;
            let _ = client.shutdown().await;
        }
    });
    let accepted = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        listener.accept_connection(65_536, 8, std::time::Duration::from_millis(500)),
    )
    .await;
    assert!(accepted.is_ok(), "接收超时");
    let Ok(Ok((mut conn, _peer))) = accepted else { return };
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut dropped = 0_usize;
    loop {
        let Ok(batch) = conn.read_batch().await else { break };
        dropped += batch.dropped;
        frames.extend(batch.frames);
        if batch.eof || batch.idle_timeout {
            break;
        }
    }
    assert_eq!(frames.len(), 2, "两条 octet-counting 帧必须都收到");
    assert_eq!(dropped, 0, "不应有丢弃");
    assert_eq!(frames.first().map(Vec::as_slice), Some(b"<34>Feb 21 10:23:45 h a: m1".as_slice()));
    let _ = sender.await;
}

/// 单次调用上限（`max_frames_per_read`）**不得**变成每连接上限。
///
/// 回归的是模拟器实测缺陷：单连接发 96 / 128 / 600 条时，接收侧只增加
/// 64 / 64 / 128 条，且第 65 帧起**静默丢弃**（不报错、不计 parse_failures）。
#[tokio::test]
async fn tcp_listener_streams_far_more_than_one_batch_over_a_single_connection() {
    const N: usize = 300;
    const BATCH: usize = 64; // 故意取小值：老实现会在此截断
    let listener = SyslogTcpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let sender = tokio::spawn(async move {
        let Ok(mut client) = TcpStream::connect(addr).await else { return };
        use tokio::io::AsyncWriteExt;
        for i in 0..N {
            let frame = format!("<34>Feb 21 10:23:45 h app: 第 {i} 条");
            let bytes = SyslogFraming::encode_octet_counting(frame.as_bytes());
            // 故意切成两段写：跨多次 read 的分片也必须正确重组
            let cut = bytes.len() / 2;
            let _ = client.write_all(bytes.get(..cut).unwrap_or_default()).await;
            let _ = client.flush().await;
            let _ = client.write_all(bytes.get(cut..).unwrap_or_default()).await;
        }
        let _ = client.flush().await;
        let _ = client.shutdown().await;
    });

    let accepted = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        listener.accept_connection(65_536, BATCH, std::time::Duration::from_millis(200)),
    )
    .await;
    assert!(accepted.is_ok(), "接收超时");
    let Ok(Ok((mut conn, _peer))) = accepted else { return };

    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut dropped = 0_usize;
    let mut batches = 0_usize;
    loop {
        let Ok(batch) = conn.read_batch().await else { break };
        batches += 1;
        dropped += batch.dropped;
        frames.extend(batch.frames);
        if batch.eof || batch.idle_timeout {
            break;
        }
        assert!(batches < 10_000, "读取批次异常膨胀，疑似死循环");
    }
    let _ = sender.await;
    assert_eq!(frames.len(), N, "单连接 {N} 帧必须全部收到（老实现只收 {BATCH} 帧）");
    assert_eq!(dropped, 0, "正常分片不应产生任何丢弃");
    assert_eq!(
        frames.last().map(|f| String::from_utf8_lossy(f).to_string()),
        Some(format!("<34>Feb 21 10:23:45 h app: 第 {} 条", N - 1))
    );
}

mod listener;

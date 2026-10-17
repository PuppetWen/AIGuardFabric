//! SNMP v3 / USM 用例：编码器往返、RFC3414 密钥本地化向量、安全级别与时间窗、真实 UDP 接入。

use super::*;

// -----------------------------------------------------------------------
// SNMP v3 / USM
// -----------------------------------------------------------------------

#[test]
fn v3_ber_encoders_roundtrip_through_the_reader() {
    // 编码器 ↔ 解析器自洽：整数最短编码 / 大长度域 / OID 变长段
    for value in [0_i64, 1, 127, 128, 1_048_576, -1, -129, i64::from(i32::MIN)] {
        let encoded = encode::integer(value);
        let mut reader = ber::Reader::new(&encoded);
        assert_eq!(reader.read_integer().ok(), Some(value), "整数往返失败: {value}");
    }
    assert_eq!(encode::integer(0), vec![0x02, 0x01, 0x00]);
    assert_eq!(encode::integer(127), vec![0x02, 0x01, 0x7f]);
    assert_eq!(encode::integer(128), vec![0x02, 0x02, 0x00, 0x80]);

    // 长度域：>= 0x80 走长形式（构造 200 字节载荷）
    let payload = vec![0x41_u8; 200];
    let encoded = encode::octet_string(&payload);
    assert_eq!(encoded.first().copied(), Some(ber::TAG_OCTET_STRING));
    assert_eq!(encoded.get(1).copied(), Some(0x81), "200 字节必须走 0x81 长形式");
    let mut reader = ber::Reader::new(&encoded);
    assert_eq!(reader.read_octet_string().ok().map(|v| v.len()), Some(200));

    // OID：点分文本与分段编码等价，且能解回原文
    for text in ["1.3.6.1.4.1.8072.0.1", "1.3.6.1.2.1.1.3.0", "1.3.6.1.6.3.15.1.1.5.0"] {
        let encoded = encode::oid_from_str(text);
        assert!(encoded.is_ok(), "{text}: {encoded:?}");
        let Ok(encoded) = encoded else { return };
        let mut reader = ber::Reader::new(&encoded);
        assert_eq!(reader.read_oid().ok().as_deref(), Some(text));
    }
    assert!(encode::oid_from_str("1").is_err(), "单段 OID 非法");
    assert!(encode::oid_from_str("1.x.3").is_err());
    // 无符号类型：Counter32 边界值
    let counter = encode::unsigned(ber::TAG_COUNTER32, 4_294_967_295);
    let mut reader = ber::Reader::new(&counter);
    let (tag, body) = reader.read_tlv().unwrap_or((0, &[]));
    assert_eq!(tag, ber::TAG_COUNTER32);
    assert_eq!(ber::decode_unsigned(body), 4_294_967_295);
}

#[test]
fn v3_key_localization_matches_rfc3414_appendix_a_vectors() {
    // RFC3414 §A.3.1 / §A.3.2 官方测试向量：password="maplesyrup"，engineID=000000000000000000000002
    let engine_id: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let ku_md5 = AuthProtocol::Md5.password_to_key(b"maplesyrup");
    assert_eq!(ku_md5.as_deref().map(hex_lower).as_deref(), Some("9faf3283884e92834ebc9847d8edd963"));
    let kul_md5 = AuthProtocol::Md5.localize_key("maplesyrup", &engine_id);
    assert_eq!(kul_md5.as_deref().map(hex_lower).as_deref(), Some("526f5eed9fcce26f8964c2930787d82b"));

    let ku_sha = AuthProtocol::Sha1.password_to_key(b"maplesyrup");
    assert_eq!(ku_sha.as_deref().map(hex_lower).as_deref(), Some("9fb5cc0381497b3793528939ff788d5d79145211"));
    let kul_sha = AuthProtocol::Sha1.localize_key("maplesyrup", &engine_id);
    assert_eq!(kul_sha.as_deref().map(hex_lower).as_deref(), Some("6695febc9288e36282235fc7151f128497b38f3f"));
    // 空口令无密钥；不同 engineID 得到不同 Kul（本地化确实绑定引擎）
    assert!(AuthProtocol::Md5.password_to_key(b"").is_none());
    assert_ne!(
        AuthProtocol::Md5.localize_key("maplesyrup", &engine_id),
        AuthProtocol::Md5.localize_key("maplesyrup", &[0x80, 0x01])
    );
    // 协议族名与 OID
    assert_eq!(AuthProtocol::parse("HMAC-SHA-96"), Some(AuthProtocol::Sha1));
    assert_eq!(AuthProtocol::parse("usmHMACMD5AuthProtocol"), Some(AuthProtocol::Md5));
    assert_eq!(AuthProtocol::parse("bogus"), None);
    assert_eq!(AuthProtocol::Md5.oid(), "1.3.6.1.6.3.10.1.1.1");
    assert_eq!(AuthProtocol::Sha1.digest_len(), USM_DIGEST_LEN);
}

#[test]
fn v3_msg_flags_map_to_security_levels() {
    assert_eq!(V3SecurityLevel::NoAuthNoPriv.msg_flags(), 0x00);
    assert_eq!(V3SecurityLevel::AuthNoPriv.msg_flags(), 0x01);
    assert_eq!(V3SecurityLevel::AuthPriv.msg_flags(), 0x03);
    assert_eq!(V3SecurityLevel::from_msg_flags(0x04), Some(V3SecurityLevel::NoAuthNoPriv));
    assert_eq!(V3SecurityLevel::from_msg_flags(0x05), Some(V3SecurityLevel::AuthNoPriv));
    assert_eq!(V3SecurityLevel::from_msg_flags(0x07), Some(V3SecurityLevel::AuthPriv));
    assert!(V3SecurityLevel::NoAuthNoPriv.is_implemented());
    assert!(V3SecurityLevel::AuthNoPriv.is_implemented());
    assert!(V3SecurityLevel::AuthPriv.is_implemented(), "authPriv（DES/AES）已实现");
    assert_eq!(V3SecurityLevel::parse("auth_no_priv"), Some(V3SecurityLevel::AuthNoPriv));
    assert_eq!(V3SecurityLevel::parse("AUTHPRIV"), Some(V3SecurityLevel::AuthPriv));
    assert_eq!(V3SecurityLevel::parse("??"), None);
    assert_eq!(V3SecurityLevel::default(), V3SecurityLevel::NoAuthNoPriv);
}

#[test]
fn v3_no_auth_no_priv_trap_parses_and_carries_usm_identity() {
    let mut spec = encode::V3TrapSpec::new("agf-readonly", V3SecurityLevel::NoAuthNoPriv);
    spec.engine_time = 4242;
    spec.engine_boots = 7;
    let message = encode::v3_trap(&spec);
    assert!(message.is_ok(), "{message:?}");
    let Ok(message) = message else { return };
    let stats = UsmStats::new();
    let trap = parse_v3_message(&message, &UsmConfig::no_auth(), &EngineClock::new(), &stats);
    assert!(trap.is_ok(), "{trap:?}");
    let Ok(trap) = trap else { return };
    assert_eq!(trap.version, "v3");
    assert_eq!(trap.user.as_deref(), Some("agf-readonly"));
    assert_eq!(trap.security_level.as_deref(), Some("noAuthNoPriv"));
    assert_eq!(trap.engine_id.as_deref(), Some("80001f8880000000000002"));
    assert_eq!(trap.request_id, Some(1_048_576));
    assert_eq!(trap.trap_oid().as_deref(), Some("1.3.6.1.4.1.8072.0.1"));
    assert_eq!(trap.uptime_ticks(), Some(12_345_678));
    assert_eq!(trap.varbinds.len(), 2, "snmpTrapOID.0 + sysUpTime.0");
    let payload = String::from_utf8_lossy(&trap.to_payload()).to_string();
    assert!(payload.contains("\"security_level\":\"noAuthNoPriv\""), "{payload}");
    assert!(payload.contains("80001f8880000000000002"), "{payload}");
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.accepted_noauth, 1);
    assert_eq!(snapshot.wrong_digests, 0);
}

#[test]
fn v3_auth_no_priv_accepts_correct_password_and_rejects_wrong_one() {
    let engine_id: Vec<u8> = vec![0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    let server = UsmConfig::auth_no_priv("agf", AuthProtocol::Md5, "maplesyrup");
    assert!(server.is_ok(), "{server:?}");
    let Ok(server) = server else { return };

    // (a) 正确口令 ⇒ 通过
    let mut spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    spec.engine_id = engine_id.clone();
    spec.auth_password = "maplesyrup".to_string();
    let good = encode::v3_trap(&spec).unwrap_or_default();
    let stats = UsmStats::new();
    let parsed = parse_v3_message(&good, &server, &EngineClock::new(), &stats);
    assert!(parsed.is_ok(), "{parsed:?}");
    assert_eq!(stats.snapshot().accepted_auth, 1);
    assert_eq!(stats.snapshot().wrong_digests, 0);

    // (b) 错口令 ⇒ 摘要不匹配 + usmStatsWrongDigests 计数（不落库、不静默）
    let mut bad_spec = spec.clone();
    bad_spec.auth_password = "wrongsecret".to_string();
    let bad = encode::v3_trap(&bad_spec).unwrap_or_default();
    let bad_stats = UsmStats::new();
    let rejected = parse_v3_message(&bad, &server, &EngineClock::new(), &bad_stats);
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))), "{rejected:?}");
    assert_eq!(bad_stats.snapshot().wrong_digests, 1);
    assert_eq!(bad_stats.snapshot().accepted_auth, 0);

    // (c) SHA-1 同样成立
    let server_sha = UsmConfig::auth_no_priv("agf", AuthProtocol::Sha1, "maplesyrup");
    assert!(server_sha.is_ok(), "{server_sha:?}");
    let Ok(server_sha) = server_sha else { return };
    let mut sha_spec = spec.clone();
    sha_spec.auth_protocol = AuthProtocol::Sha1;
    let sha_msg = encode::v3_trap(&sha_spec).unwrap_or_default();
    assert!(parse_v3_message(&sha_msg, &server_sha, &EngineClock::new(), &UsmStats::new()).is_ok());
    // MD5 报文送到只配 SHA 的接收侧 ⇒ 摘要不匹配
    assert!(matches!(
        parse_v3_message(&good, &server_sha, &EngineClock::new(), &UsmStats::new()),
        Err(DomainError::Unauthenticated(_))
    ));

    // (d) 篡改报文载荷 ⇒ 摘要失配
    let mut tampered = good.clone();
    if tampered.len() > 4 {
        let last = tampered.len() - 1;
        if let Some(byte) = tampered.get_mut(last) {
            *byte ^= 0xff;
        }
    }
    let tamper_stats = UsmStats::new();
    assert!(matches!(
        parse_v3_message(&tampered, &server, &EngineClock::new(), &tamper_stats),
        Err(DomainError::Unauthenticated(_))
    ));
    assert_eq!(tamper_stats.snapshot().wrong_digests, 1);

    // (e) 配置校验：短口令 / 缺口令 / authPriv 缺隐私口令都显式报错
    assert!(matches!(UsmConfig::auth_no_priv("agf", AuthProtocol::Md5, "short"), Err(DomainError::Config(_))));
    assert!(matches!(
        UsmConfig::from_parts(
            Some("agf".to_string()),
            V3SecurityLevel::AuthNoPriv,
            AuthProtocol::Md5,
            None,
            PrivProtocol::Aes,
            None
        ),
        Err(DomainError::Config(_))
    ));
    // authPriv 现在**已实现**：缺隐私口令才是配置错误（不再是 NotImplemented）
    assert!(matches!(
        UsmConfig::from_parts(
            Some("agf".to_string()),
            V3SecurityLevel::AuthPriv,
            AuthProtocol::Md5,
            Some("maplesyrup".to_string()),
            PrivProtocol::Aes,
            None
        ),
        Err(DomainError::Config(_))
    ));
    assert!(
        UsmConfig::from_parts(
            Some("agf".to_string()),
            V3SecurityLevel::AuthPriv,
            AuthProtocol::Md5,
            Some("maplesyrup".to_string()),
            PrivProtocol::Aes,
            Some("privsecret".to_string())
        )
        .is_ok()
    );
    assert_eq!(server.describe(), "v3/authNoPriv(user=agf, auth=md5)");
    assert!(!server.describe().contains("maplesyrup"), "描述绝不能带口令");
}

#[test]
fn v3_level_mismatch_and_bad_credentials_are_counted_not_silently_dropped() {
    let server = UsmConfig::auth_no_priv("agf", AuthProtocol::Md5, "maplesyrup").unwrap_or_default();

    // (a) 报文声明 authPriv（0x03）而服务端配置 authNoPriv ⇒ **级别不匹配**（unsupported），
    //     并且不尝试解密（解密只在自己配置为 authPriv 时发生）
    let mut spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    spec.flags_override = Some(0x07); // auth|priv|reportable
    let priv_message = encode::v3_trap(&spec).unwrap_or_default();
    let stats = UsmStats::new();
    let rejected = parse_v3_message(&priv_message, &server, &EngineClock::new(), &stats);
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))), "{rejected:?}");
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.unsupported_sec_levels, 1);
    assert_eq!(snapshot.decryption_errors, 0, "级别不符 ⇒ 不做解密，也就没有解密错误");
    assert_eq!(snapshot.priv_decrypt_ok, 0);
    assert_eq!(snapshot.accepted_priv, 0);

    // (b) 配置 authNoPriv、报文 noAuthNoPriv ⇒ 级别不匹配（unsupported 计数）
    let plain = encode::v3_trap(&encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv)).unwrap_or_default();
    let mismatch_stats = UsmStats::new();
    let mismatch = parse_v3_message(&plain, &server, &EngineClock::new(), &mismatch_stats);
    assert!(matches!(mismatch, Err(DomainError::Unauthenticated(_))), "{mismatch:?}");
    assert_eq!(mismatch_stats.snapshot().unsupported_sec_levels, 1);
    assert_eq!(mismatch_stats.snapshot().accepted_noauth, 0);

    // (c) 用户名不匹配 ⇒ usmStatsUnknownUserNames
    let mut wrong_user = encode::V3TrapSpec::new("intruder", V3SecurityLevel::AuthNoPriv);
    wrong_user.auth_password = "maplesyrup".to_string();
    let wrong_user_msg = encode::v3_trap(&wrong_user).unwrap_or_default();
    let user_stats = UsmStats::new();
    let user_rejected = parse_v3_message(&wrong_user_msg, &server, &EngineClock::new(), &user_stats);
    assert!(matches!(user_rejected, Err(DomainError::Unauthenticated(_))), "{user_rejected:?}");
    assert_eq!(user_stats.snapshot().unknown_user_names, 1);
    assert_eq!(user_stats.snapshot().wrong_digests, 0, "用户名先于摘要校验");

    // (d) 摘要被替换（长度正确但内容错）⇒ wrong_digests
    let mut short_spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    short_spec.auth_password = "maplesyrup".to_string();
    short_spec.digest_override = Some(vec![0xaa_u8; USM_DIGEST_LEN]);
    let short_msg = encode::v3_trap(&short_spec).unwrap_or_default();
    let short_stats = UsmStats::new();
    assert!(matches!(
        parse_v3_message(&short_msg, &server, &EngineClock::new(), &short_stats),
        Err(DomainError::Unauthenticated(_))
    ));
    assert_eq!(short_stats.snapshot().wrong_digests, 1);
    // 摘要覆盖长度非法 ⇒ 编码侧显式报错（不 panic、不静默截断）
    let mut bad_len = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    bad_len.auth_password = "maplesyrup".to_string();
    bad_len.digest_override = Some(vec![0_u8; 4]);
    assert!(matches!(encode::v3_trap(&bad_len), Err(DomainError::Internal(_))));

    // (e) usmStats OID 映射（RFC3414 §5）+ authPriv 细分指标族
    assert_eq!(UsmStatsKind::WrongDigests.oid(), "1.3.6.1.6.3.15.1.1.5.0");
    assert_eq!(UsmStatsKind::UnsupportedSecLevels.oid(), "1.3.6.1.6.3.15.1.1.1.0");
    assert_eq!(UsmStatsKind::DecryptionErrors.oid(), "1.3.6.1.6.3.15.1.1.6.0");
    assert_eq!(UsmStatsKind::all().len(), 6);
    let text = stats.prometheus("snmp-trap");
    assert!(text.contains("agf_ingest_snmp_usm_unsupported_sec_levels_total{receiver=\"snmp-trap\"} 1"), "{text}");
    assert!(text.contains("agf_ingest_snmp_usm_decryption_errors_total{receiver=\"snmp-trap\"} 0"), "{text}");
    assert!(text.contains("agf_ingest_snmp_usm_accepted_priv_total{receiver=\"snmp-trap\"} 0"), "{text}");
    assert!(text.contains("agf_ingest_snmp_usm_priv_decrypt_ok_total{receiver=\"snmp-trap\"} 0"), "{text}");
    assert!(text.contains("agf_ingest_snmp_usm_priv_padding_errors_total{receiver=\"snmp-trap\"} 0"), "{text}");
    assert!(text.contains("1.3.6.1.6.3.15.1.1.5.0"), "{text}");
}

#[test]
fn v3_time_window_rejects_replayed_engine_time() {
    let engine_id: Vec<u8> = vec![0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    let server = UsmConfig::auth_no_priv("agf", AuthProtocol::Md5, "maplesyrup").unwrap_or_default();
    let clock = EngineClock::new();
    let stats = UsmStats::new();

    // 首条报文总是被接受（等价于引擎发现）
    let mut first = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    first.engine_id = engine_id.clone();
    first.engine_time = 1_000;
    first.engine_boots = 3;
    first.auth_password = "maplesyrup".to_string();
    let ok = parse_v3_message(&encode::v3_trap(&first).unwrap_or_default(), &server, &clock, &stats);
    assert!(ok.is_ok(), "{ok:?}");

    // engineTime 大幅跳跃（>150s）⇒ 超窗拒绝 + 计数
    let mut jump = first.clone();
    jump.engine_time = 10_000;
    jump.msg_id = 2;
    let jumped = parse_v3_message(&encode::v3_trap(&jump).unwrap_or_default(), &server, &clock, &stats);
    assert!(matches!(jumped, Err(DomainError::Unauthenticated(_))), "{jumped:?}");
    assert_eq!(stats.snapshot().not_in_time_windows, 1);

    // engineBoots 回退 ⇒ 同样按超窗处理
    let mut rewind = first.clone();
    rewind.engine_boots = 1;
    rewind.msg_id = 3;
    let rewound = parse_v3_message(&encode::v3_trap(&rewind).unwrap_or_default(), &server, &clock, &stats);
    assert!(matches!(rewound, Err(DomainError::Unauthenticated(_))), "{rewound:?}");
    assert_eq!(stats.snapshot().not_in_time_windows, 2);

    // engineBoots 前进 ⇒ 接受（设备重启）
    let mut reboot = first.clone();
    reboot.engine_boots = 4;
    reboot.engine_time = 5;
    reboot.msg_id = 4;
    assert!(parse_v3_message(&encode::v3_trap(&reboot).unwrap_or_default(), &server, &clock, &stats).is_ok());
    assert_eq!(stats.snapshot().accepted_auth, 2);
}

#[test]
fn v3_malformed_messages_are_rejected_with_precise_errors() {
    let config = UsmConfig::no_auth();
    let clock = EngineClock::new();
    let stats = UsmStats::new();
    // 非 v3 版本号
    let v2c = v2c_trap("public");
    assert!(parse_v3_message(&v2c, &config, &clock, &stats).is_err());
    // 空/截断
    assert!(parse_v3_message(&[], &config, &clock, &stats).is_err());
    assert!(parse_v3_message(&[0x30, 0x03, 0x02, 0x01, 0x03], &config, &clock, &stats).is_err());
    // 顶层非 SEQUENCE
    assert!(parse_v3_message(&[0x02, 0x01, 0x03], &config, &clock, &stats).is_err());
    // msgFlags 长度非法
    let mut spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    spec.flags_override = Some(0x04);
    let message = encode::v3_trap(&spec).unwrap_or_default();
    assert!(parse_v3_message(&message, &config, &clock, &stats).is_ok());
    // 篡改 msgFlags 为保留值 0x02（priv 位无语义组合）
    let mut reserved = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    reserved.flags_override = Some(0x06);
    let reserved_msg = encode::v3_trap(&reserved).unwrap_or_default();
    // 0x06 & 0x03 == 0x02 ⇒ 解析不出安全级别
    assert!(parse_v3_message(&reserved_msg, &config, &clock, &stats).is_err());
    // 尾随字节
    let mut trailing = message.clone();
    trailing.push(0x00);
    assert!(parse_v3_message(&trailing, &config, &clock, &stats).is_err());
    // Report PDU（对端在报告 usmStats）：应被识别并带上 OID，而不是当成普通 Trap
    let mut report_pdu = encode::integer(1);
    report_pdu.extend_from_slice(&encode::integer(0));
    report_pdu.extend_from_slice(&encode::integer(0));
    let mut binds = encode::varbind_integer("1.3.6.1.6.3.15.1.1.5.0", 3).unwrap_or_default();
    let extra = encode::varbind_text("1.3.6.1.2.1.1.5.0", "edge-1").unwrap_or_default();
    binds.extend_from_slice(&extra);
    report_pdu.extend_from_slice(&encode::tlv(ber::TAG_SEQUENCE, &binds));
    let report_msg = v3_message_with_pdu(&message, ber::TAG_REPORT, &report_pdu);
    let report = parse_v3_message(&report_msg, &config, &clock, &stats);
    assert!(matches!(report, Err(DomainError::Parse(_))), "{report:?}");
    if let Err(DomainError::Parse(text)) = report {
        assert!(text.contains("1.3.6.1.6.3.15.1.1.5.0"), "{text}");
    }
}

/// 把已构造好的 v3 报文里的 ScopedPDU 换成指定 PDU（保留 HeaderData/USM 原样，测试用）。
fn v3_message_with_pdu(template: &[u8], pdu_tag: u8, pdu: &[u8]) -> Vec<u8> {
    let spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    // 重新拼装：version + header + 安全参数 + ScopedPDU(contextEngineID/contextName/自定义 PDU)
    let (_, body, body_offset) = match ber::Reader::new(template).read_tlv_at() {
        Ok(parts) => parts,
        Err(_) => return Vec::new(),
    };
    let mut reader = ber::Reader::with_base(body, body_offset);
    let version = reader.read_integer().unwrap_or(3);
    let Ok((_, header, _)) = reader.read_tlv_at() else { return Vec::new() };
    let Ok((_, params, _)) = reader.read_tlv_at() else { return Vec::new() };
    let mut scoped = encode::octet_string(&spec.engine_id);
    scoped.extend_from_slice(&encode::octet_string(&[]));
    scoped.extend_from_slice(&encode::tlv(pdu_tag, pdu));
    let mut message = encode::integer(version);
    message.extend_from_slice(&encode::tlv(ber::TAG_SEQUENCE, header));
    message.extend_from_slice(&encode::tlv(ber::TAG_OCTET_STRING, params));
    message.extend_from_slice(&encode::tlv(ber::TAG_SEQUENCE, &scoped));
    encode::tlv(ber::TAG_SEQUENCE, &message)
}

#[tokio::test]
async fn v3_receiver_ingests_over_real_udp_and_counts_usm_failures() {
    use tokio::net::UdpSocket;

    // ---- noAuthNoPriv：真实 UDP 收包 ⇒ 落库 ----
    let (receiver, sink) = v3_receiver(UsmConfig::no_auth());
    let socket = receiver.bind().await;
    assert!(socket.is_ok(), "{socket:?}");
    let Ok(socket) = socket else { return };
    let Ok(local) = socket.local_addr() else { return };
    let serve = tokio::spawn(async move {
        let _ = receiver.serve(socket).await;
    });
    let Ok(client) = UdpSocket::bind("127.0.0.1:0").await else { return };
    let plain = encode::v3_trap(&encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv));
    assert!(plain.is_ok(), "{plain:?}");
    let Ok(plain) = plain else { return };
    let _ = client.send_to(&plain, local).await;
    let mut landed = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if sink.event_count(TenantId::default_tenant()).await.ok() == Some(1) {
            landed = true;
            break;
        }
    }
    serve.abort();
    assert!(landed, "v3 noAuthNoPriv 真实 UDP 收包必须落库");

    // ---- authNoPriv：正确口令落库；错口令被拒并计入 usmStatsWrongDigests ----
    let server = UsmConfig::auth_no_priv("agf", AuthProtocol::Md5, "maplesyrup").unwrap_or_default();
    let (authed, authed_sink) = v3_receiver(server.clone());
    let counters = Arc::clone(authed.counters());
    let Ok(socket) = authed.bind().await else { return };
    let Ok(local) = socket.local_addr() else { return };
    let serve = tokio::spawn(async move {
        let _ = authed.serve(socket).await;
    });
    let mut good = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    good.auth_password = "maplesyrup".to_string();
    let good = encode::v3_trap(&good).unwrap_or_default();
    let _ = client.send_to(&good, local).await;
    let mut landed = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if authed_sink.event_count(TenantId::default_tenant()).await.ok() == Some(1) {
            landed = true;
            break;
        }
    }
    serve.abort();
    assert!(landed, "v3 authNoPriv 正确口令必须落库");

    // 直接喂错口令报文（不必再起 socket：ingest_datagram 走同一条解析路径）
    let (authed2, _sink2) = v3_receiver(server);
    let mut bad = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    bad.auth_password = "totallywrong".to_string();
    bad.msg_id = 9;
    let bad = encode::v3_trap(&bad).unwrap_or_default();
    let rejected = authed2.ingest_datagram(&bad, "203.0.113.7:41641").await;
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))), "{rejected:?}");
    assert_eq!(authed2.usm_stats().snapshot().wrong_digests, 1);
    assert_eq!(authed2.counters().snapshot().dropped, 1, "认证失败必须计入 dropped");
    assert_eq!(counters.snapshot().received, 1, "成功那条 UDP 报文必须计入 received");
}

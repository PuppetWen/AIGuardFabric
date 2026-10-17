//! SNMP v3 **authPriv** 用例：RFC3414 §A.3 隐私密钥向量、DES/AES 官方向量、补齐、错口令与分类计数。
//!
//! 夹具（`v2c_trap` / `pipeline_and_sink` / `v3_receiver`）来自父模块 `snmp::tests`。

use super::*;

/// RFC3414 §A.3.1 / §A.3.2 的 `kul` 向量：`privKey = Kul 前 16 字节`（MD5 恰好 16 字节，SHA-1 取前 16）。
#[test]
fn priv_key_localization_matches_rfc3414_appendix_a_vectors() {
    let engine_id: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    // MD5：kul 本身就是 16 字节 ⇒ privKey == kul
    let md5 = localized_priv_key(AuthProtocol::Md5, "maplesyrup", &engine_id);
    assert_eq!(md5.as_deref().map(hex_lower).as_deref(), Some("526f5eed9fcce26f8964c2930787d82b"));
    // SHA-1：kul 是 20 字节 ⇒ privKey 取前 16
    let sha = localized_priv_key(AuthProtocol::Sha1, "maplesyrup", &engine_id);
    assert_eq!(sha.as_deref().map(hex_lower).as_deref(), Some("6695febc9288e36282235fc7151f1284"));
    assert_eq!(sha.as_deref().map(<[u8]>::len), Some(PRIV_KEY_LEN));
    // 隐私口令为空 ⇒ 无密钥；不同 engineID ⇒ 不同 privKey（本地化确实绑定引擎）
    assert!(localized_priv_key(AuthProtocol::Md5, "", &engine_id).is_none());
    assert_ne!(md5, localized_priv_key(AuthProtocol::Md5, "maplesyrup", &[0x80, 0x01]));
    // 认证侧的 Kul 口径与隐私侧共用同一份实现（不是两套哈希）
    assert_eq!(AuthProtocol::Md5.localize_key("maplesyrup", &engine_id), md5);
}

/// DES-CBC：FIPS 46 已知答案 + 往返 + `IV = pre-IV XOR salt` 推导。
#[test]
fn des_cbc_matches_fips_known_answer_and_roundtrips() {
    // FIPS 已知答案：key=0123456789abcdef、IV=0 ⇒ "Now is t"(4e6f772069732074) → 3fa40e8a984d4815
    let key: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let pre_iv: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let salt: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]; // salt == pre-IV ⇒ IV = 0
    let mut priv_key = key.to_vec();
    priv_key.extend_from_slice(&pre_iv);
    assert_eq!(priv_key.len(), PRIV_KEY_LEN);

    let iv = privacy_iv(PrivProtocol::Des, &priv_key, &salt, 1, 100);
    assert_eq!(iv.ok(), Some(vec![0_u8; DES_BLOCK_LEN]), "IV = pre-IV XOR salt = 0");

    let plaintext = b"Now is t"; // 恰好 8 字节（无补齐）
    let ciphertext = encrypt(PrivProtocol::Des, &priv_key, &salt, 1, 100, plaintext);
    assert!(ciphertext.is_ok(), "{ciphertext:?}");
    let Ok(ciphertext) = ciphertext else { return };
    assert_eq!(hex_lower(&ciphertext), "3fa40e8a984d4815");
    let back = decrypt(PrivProtocol::Des, &priv_key, &salt, 1, 100, &ciphertext);
    assert_eq!(back.ok().as_deref(), Some(plaintext.as_slice()));

    // 换 salt ⇒ IV 变 ⇒ 密文变（DES 的 IV 确实吃 salt）
    let other_salt: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let other = encrypt(PrivProtocol::Des, &priv_key, &other_salt, 1, 100, plaintext).unwrap_or_default();
    assert_ne!(other, ciphertext);
    // salt 长度非法 / 密文长度不是 8 的倍数 ⇒ 显式报错（RFC3414 §8.3.2 第 1 步）
    assert!(privacy_iv(PrivProtocol::Des, &priv_key, &[0_u8; 7], 1, 100).is_err());
    assert!(decrypt(PrivProtocol::Des, &priv_key, &salt, 1, 100, &[0_u8; 9]).is_err());
}

/// AES-128-CFB128：NIST SP800-38A F.3.13 官方向量 + 末段不满 16 字节的往返 + IV 推导。
#[test]
fn aes_cfb128_matches_nist_vector_and_iv_derivation() {
    let key: [u8; 16] =
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    // RFC3826 §3.1.2.1：IV = engineBoots(4,BE) ‖ engineTime(4,BE) ‖ salt(8)
    let boots = 0x0001_0203_i64;
    let time = 0x0405_0607_i64;
    let salt: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let priv_key = key.to_vec();
    let iv = privacy_iv(PrivProtocol::Aes, &priv_key, &salt, boots, time);
    assert_eq!(
        iv.ok().map(|iv| hex_lower(&iv)),
        Some("000102030405060708090a0b0c0d0e0f".to_string()),
        "IV 必须等于 NIST 向量里的 000102030405060708090a0b0c0d0e0f"
    );

    let plaintext: Vec<u8> = [
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ]
    .iter()
    .filter_map(|hex| hex_decode(hex))
    .flatten()
    .collect();
    assert_eq!(plaintext.len(), 64);
    let ciphertext = encrypt(PrivProtocol::Aes, &priv_key, &salt, boots, time, &plaintext);
    assert!(ciphertext.is_ok(), "{ciphertext:?}");
    let Ok(ciphertext) = ciphertext else { return };
    let expected = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b\
                    26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";
    assert_eq!(hex_lower(&ciphertext), expected, "AES-CFB128 必须与 NIST SP800-38A 逐字节一致");
    assert_eq!(decrypt(PrivProtocol::Aes, &priv_key, &salt, boots, time, &ciphertext).ok(), Some(plaintext.clone()));

    // 末段不满 16 字节（流模式无需补齐）：23 字节往返
    let partial = plaintext.get(..23).unwrap_or_default().to_vec();
    let packed = encrypt(PrivProtocol::Aes, &priv_key, &salt, boots, time, &partial).unwrap_or_default();
    assert_eq!(packed.len(), 23, "CFB 是流模式，长度不变");
    assert_eq!(decrypt(PrivProtocol::Aes, &priv_key, &salt, boots, time, &packed).ok(), Some(partial));
    // engineBoots/engineTime 超出 32 bit ⇒ 显式报错（不静默截断）
    assert!(privacy_iv(PrivProtocol::Aes, &priv_key, &salt, i64::from(u32::MAX) + 1, 0).is_err());
}

/// DES 的补齐：加密侧补到 8 的整数倍，解密侧**按 BER 长度剥掉**（RFC3414 §8.1.1.3）。
#[test]
fn des_padding_is_added_on_encrypt_and_stripped_by_ber_length() {
    let mut priv_key =
        vec![0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0];
    priv_key.truncate(PRIV_KEY_LEN);
    let salt: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    // 一个 17 字节的 BER SEQUENCE（0x30 0x0f + 15 字节内容）⇒ 补齐到 24 字节
    let mut scoped: Vec<u8> = vec![ber::TAG_SEQUENCE, 0x0f];
    scoped.extend_from_slice(&[0x41_u8; 15]);
    assert_eq!(scoped.len(), 17);
    let ciphertext = encrypt(PrivProtocol::Des, &priv_key, &salt, 2, 30, &scoped);
    assert!(ciphertext.is_ok(), "{ciphertext:?}");
    let Ok(ciphertext) = ciphertext else { return };
    assert!(ciphertext.len().is_multiple_of(DES_BLOCK_LEN));
    assert_eq!(ciphertext.len(), 24, "17 字节必须补齐到 24 字节");
    let padded_plaintext = decrypt(PrivProtocol::Des, &priv_key, &salt, 2, 30, &ciphertext).unwrap_or_default();
    assert_eq!(padded_plaintext.len(), 24);
    assert_eq!(
        padded_plaintext.get(17..),
        Some([0_u8; 7].as_slice()),
        "补齐字节为 0（补齐值本身无关，但实现必须确定）"
    );
    let stripped = strip_padding(&padded_plaintext);
    assert!(stripped.is_ok(), "{stripped:?}");
    let Ok((tlv, padding)) = stripped else { return };
    assert_eq!(tlv, scoped.as_slice(), "剥补齐后必须还原出完整 ScopedPDU TLV");
    assert_eq!(padding, 7);

    // 明文长度恰好是 8 的整数倍 ⇒ 不补（padding = 0）
    let aligned: Vec<u8> = vec![ber::TAG_SEQUENCE, 0x0e].into_iter().chain([0x42_u8; 14]).collect();
    assert_eq!(aligned.len(), 16);
    let packed = encrypt(PrivProtocol::Des, &priv_key, &salt, 2, 30, &aligned).unwrap_or_default();
    assert_eq!(packed.len(), 16);
    let plaintext = decrypt(PrivProtocol::Des, &priv_key, &salt, 2, 30, &packed).unwrap_or_default();
    assert_eq!(strip_padding(&plaintext).ok(), Some((aligned.as_slice(), 0)));

    // 解密结果不是合法 BER（非 SEQUENCE / 长度越界）⇒ 显式报错，绝不返回半截数据
    assert!(strip_padding(&[0x02_u8; 8]).is_err(), "非 SEQUENCE 必须拒绝");
    assert!(strip_padding(&[ber::TAG_SEQUENCE, 0x7f, 0x01]).is_err(), "声明长度越界必须拒绝");
    assert!(strip_padding(&[]).is_err());
}

/// authPriv 端到端：编码器真实加密 ⇒ 解析器解密 ⇒ 字段/计数/DES 与 AES 两条都成立。
#[test]
fn auth_priv_trap_decrypts_for_des_and_aes() {
    for (protocol, label) in [(PrivProtocol::Des, "des"), (PrivProtocol::Aes, "aes")] {
        let server = UsmConfig::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", protocol, "privsecret");
        assert!(server.is_ok(), "{label}: {server:?}");
        let Ok(server) = server else { continue };
        let spec = encode::V3TrapSpec::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", protocol, "privsecret");
        let message = encode::v3_trap(&spec);
        assert!(message.is_ok(), "{label}: {message:?}");
        let Ok(message) = message else { continue };

        // 报文里 msgFlags 必须是 auth|priv|reportable = 0x07（密文由 msgData 的 OCTET STRING 承载）
        assert_eq!(msg_flags(&message), Some(0x07), "{label}: msgFlags 必须是 0x03|0x04");
        let (data_tag, _) = payload_tlv(&message);
        assert_eq!(data_tag, Some(ber::TAG_OCTET_STRING), "{label}: authPriv 的 msgData 必须是密文 OCTET STRING");
        let stats = UsmStats::new();
        let parsed = parse_v3_message(&message, &server, &EngineClock::new(), &stats);
        assert!(parsed.is_ok(), "{label}: {parsed:?}");
        let Ok(trap) = parsed else { continue };
        assert_eq!(trap.version, "v3");
        assert_eq!(trap.security_level.as_deref(), Some("authPriv"), "{label}");
        assert_eq!(trap.user.as_deref(), Some("agf"));
        assert_eq!(trap.trap_oid().as_deref(), Some("1.3.6.1.4.1.8072.0.1"), "{label} 解密后必须还原 varbind");
        assert_eq!(trap.varbinds.len(), 2);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.accepted_priv, 1, "{label}: {}", stats.prometheus("snmp-trap"));
        assert_eq!(snapshot.priv_decrypt_ok, 1, "{label}");
        assert_eq!(snapshot.decryption_errors, 0, "{label}");
        assert_eq!(snapshot.wrong_digests, 0, "{label}");
        assert_eq!(snapshot.accepted_auth, 0, "authPriv 不并入 authNoPriv 计数");
        // salt 必须是 8 字节，且落在 msgPrivacyParameters 段
        let offset = encode::priv_params_offset(&message);
        assert!(offset.is_ok(), "{label}: {offset:?}");
        let Ok(offset) = offset else { continue };
        assert_eq!(message.get(offset.saturating_sub(1)).copied(), Some(PRIV_SALT_LEN as u8), "{label}");
        // 负载确实是密文：明文 varbind 的 OID 编码不得出现在报文里（trap OID 的 BER 序列）
        let oid_bytes = encode::oid_from_str("1.3.6.1.4.1.8072.0.1").unwrap_or_default();
        assert!(!oid_bytes.is_empty());
        assert!(!contains_subslice(&message, &oid_bytes), "{label}: 明文 trap OID 不该出现在密文报文里");
        let payload = trap.to_payload();
        assert!(String::from_utf8_lossy(&payload).contains("authPriv"), "{label}"); // 同一条报文换个隐私协议配置 ⇒ 解不出来（计数到 decryption_errors）
        let wrong_protocol = if protocol == PrivProtocol::Des { PrivProtocol::Aes } else { PrivProtocol::Des };
        let other = UsmConfig::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", wrong_protocol, "privsecret")
            .unwrap_or_default();
        let other_stats = UsmStats::new();
        let rejected = parse_v3_message(&message, &other, &EngineClock::new(), &other_stats);
        assert!(rejected.is_err(), "{label}: 换协议后不该解出来");
        assert_eq!(other_stats.snapshot().decryption_errors, 1, "{label}");
    }
}

/// 错**隐私**口令：认证能过（摘要用认证口令算）但解密失败 ⇒ 分类计数，不静默丢弃。
#[test]
fn auth_priv_with_wrong_priv_password_is_rejected_and_counted() {
    for (protocol, salt) in [(PrivProtocol::Des, 0x11_u8), (PrivProtocol::Aes, 0x22_u8)] {
        let server =
            UsmConfig::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", protocol, "privsecret").unwrap_or_default();
        let mut spec =
            encode::V3TrapSpec::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", protocol, "wrong-priv-pass");
        // salt 固定 ⇒ 乱码确定（用例可复现）；判定标准是"拒绝 + 分类计数"
        spec.priv_salt = Some(vec![salt; PRIV_SALT_LEN]);
        let message = encode::v3_trap(&spec).unwrap_or_default();
        let stats = UsmStats::new();
        let rejected = parse_v3_message(&message, &server, &EngineClock::new(), &stats);
        // 乱码可能落在 ScopedPDU 外层（→ Unauthenticated）或已知标签的 PDU 字段上（→ Parse）；
        // 两种都属于"必须拒绝"，且都必须进 usmStats 计数
        assert!(
            matches!(rejected, Err(DomainError::Unauthenticated(_) | DomainError::Parse(_))),
            "{protocol:?}: {rejected:?}"
        );
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.wrong_digests, 0, "{protocol:?}: 认证口令是对的，摘要必须过");
        assert_eq!(snapshot.decryption_errors, 1, "{protocol:?}: 必须计入 usmStatsDecryptionErrors");
        assert_eq!(snapshot.accepted_priv, 0, "{protocol:?}");
        assert_eq!(snapshot.priv_decrypt_ok, 0, "{protocol:?}: 解出乱码不算解密成功");
        assert!(
            snapshot.priv_padding_errors + snapshot.priv_short_plaintext >= 1,
            "{protocol:?}: 必须细分到补齐/短明文：{snapshot:?}"
        );
        // 错误文本不得包含口令
        if let Err(error) = rejected {
            let text = error.to_string();
            assert!(!text.contains("wrong-priv-pass") && !text.contains("privsecret"), "{text}");
        }
    }
}

/// 错**认证**口令：摘要先失败 ⇒ 计入 wrongDigests，且**根本不进入解密**（RFC3414 §3.2 顺序）。
#[test]
fn auth_priv_wrong_auth_password_fails_before_decryption() {
    let server = UsmConfig::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", PrivProtocol::Aes, "privsecret")
        .unwrap_or_default();
    let spec = encode::V3TrapSpec::auth_priv("agf", AuthProtocol::Md5, "not-the-pass", PrivProtocol::Aes, "privsecret");
    let message = encode::v3_trap(&spec).unwrap_or_default();
    let stats = UsmStats::new();
    let rejected = parse_v3_message(&message, &server, &EngineClock::new(), &stats);
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))), "{rejected:?}");
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.wrong_digests, 1);
    assert_eq!(snapshot.decryption_errors, 0, "认证不通过就不该尝试解密");
    assert_eq!(snapshot.priv_decrypt_ok, 0);
    // 篡改密文同样被摘要挡住（整报文 HMAC 覆盖加密载荷）
    let mut tampered = encode::v3_trap(&encode::V3TrapSpec::auth_priv(
        "agf",
        AuthProtocol::Md5,
        "maplesyrup",
        PrivProtocol::Aes,
        "privsecret",
    ))
    .unwrap_or_default();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0x01;
    }
    let tamper_stats = UsmStats::new();
    assert!(parse_v3_message(&tampered, &server, &EngineClock::new(), &tamper_stats).is_err());
    assert_eq!(tamper_stats.snapshot().wrong_digests, 1, "密文被篡改 ⇒ 摘要失配");
}

/// 安全级别 / 协议分支的计数：级别不匹配、未实现级别组合、msgFlags 保留值。
#[test]
fn auth_priv_level_and_flag_branches_are_counted() {
    // (a) 配置 noAuthNoPriv、报文 msgFlags=0x03 ⇒ 级别不匹配（unsupported），不尝试解密
    let plain = UsmConfig::no_auth();
    let spec = encode::V3TrapSpec::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", PrivProtocol::Aes, "privsecret");
    let message = encode::v3_trap(&spec).unwrap_or_default();
    let stats = UsmStats::new();
    let rejected = parse_v3_message(&message, &plain, &EngineClock::new(), &stats);
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))), "{rejected:?}");
    assert_eq!(stats.snapshot().unsupported_sec_levels, 1);
    assert_eq!(stats.snapshot().decryption_errors, 0, "级别不符就不该解密");

    // (b) 配置 authPriv、报文 authNoPriv ⇒ 同样级别不匹配（不隐式降级）
    let priv_cfg = UsmConfig::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", PrivProtocol::Aes, "privsecret")
        .unwrap_or_default();
    let mut auth_spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    auth_spec.auth_password = "maplesyrup".to_string();
    let auth_message = encode::v3_trap(&auth_spec).unwrap_or_default();
    let mismatch = UsmStats::new();
    assert!(matches!(
        parse_v3_message(&auth_message, &priv_cfg, &EngineClock::new(), &mismatch),
        Err(DomainError::Unauthenticated(_))
    ));
    assert_eq!(mismatch.snapshot().unsupported_sec_levels, 1);
    assert_eq!(mismatch.snapshot().accepted_priv, 0);

    // (c) msgFlags 保留组合 0x06（priv 位 =1、auth 位 =0）⇒ 解不出级别
    let mut reserved = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    reserved.flags_override = Some(0x06);
    let reserved_msg = encode::v3_trap(&reserved).unwrap_or_default();
    assert!(matches!(
        parse_v3_message(&reserved_msg, &plain, &EngineClock::new(), &UsmStats::new()),
        Err(DomainError::Parse(_))
    ));
    // 三种级别的 msgFlags 映射与 is_implemented 如实（authPriv 已实现）
    assert_eq!(V3SecurityLevel::AuthPriv.msg_flags(), 0x03);
    assert!(V3SecurityLevel::AuthPriv.is_implemented());
    assert!(PrivProtocol::Des.is_implemented() && PrivProtocol::Aes.is_implemented());
}

/// 配置校验与凭据纪律：缺隐私口令显式报错、口令过短报错、`Debug`/描述**绝不回显口令**。
#[test]
fn priv_config_validation_and_credential_discipline() {
    let ok = UsmConfig::auth_priv("agf", AuthProtocol::Sha1, "maplesyrup", PrivProtocol::Des, "privsecret");
    assert!(ok.is_ok(), "{ok:?}");
    let Ok(config) = ok else { return };
    assert_eq!(config.describe(), "v3/authPriv(user=agf, auth=sha1, priv=des)");
    assert!(!config.describe().contains("maplesyrup") && !config.describe().contains("privsecret"));
    let debug = format!("{config:?}");
    assert!(!debug.contains("maplesyrup") && !debug.contains("privsecret"), "Debug 不得回显口令：{debug}");
    assert!(debug.contains("auth_password: \"<已配置，值不回显>\""), "{debug}");
    assert!(debug.contains("priv_password: \"<已配置，值不回显>\""), "{debug}");

    // 缺隐私口令 / 口令过短 / 隐私协议非法文本
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
    assert!(matches!(
        UsmConfig::auth_priv("agf", AuthProtocol::Md5, "maplesyrup", PrivProtocol::Aes, "short"),
        Err(DomainError::Config(_))
    ));
    assert!(matches!(
        UsmConfig::auth_priv("agf", AuthProtocol::Md5, "short", PrivProtocol::Aes, "privsecret"),
        Err(DomainError::Config(_))
    ));
    assert_eq!(PrivProtocol::parse("AES-128"), Some(PrivProtocol::Aes));
    assert_eq!(PrivProtocol::parse("usmDESPrivProtocol"), Some(PrivProtocol::Des));
    assert_eq!(PrivProtocol::parse("3des"), None);
    assert_eq!(PrivProtocol::default(), PrivProtocol::Aes, "默认隐私协议为 AES");
    assert_eq!(PrivProtocol::Aes.oid(), "1.3.6.1.6.3.10.1.2.4");
    assert_eq!(PrivProtocol::Des.oid(), "1.3.6.1.6.3.10.1.2.2");
    assert!(PrivProtocol::Des.needs_padding() && !PrivProtocol::Aes.needs_padding());
    assert_eq!(PrivProtocol::Des.block_len(), DES_BLOCK_LEN);
    // noAuthNoPriv 下即使带了隐私口令也不产出隐私密钥（不隐式升级）
    let plain = UsmConfig::from_parts(
        Some("agf".to_string()),
        V3SecurityLevel::NoAuthNoPriv,
        AuthProtocol::Md5,
        Some("maplesyrup".to_string()),
        PrivProtocol::Aes,
        Some("privsecret".to_string()),
    )
    .unwrap_or_default();
    assert!(plain.localized_priv_key(&[0x80, 0x01]).is_none());
    assert!(plain.localized_key(&[0x80, 0x01]).is_none());
}

/// salt 生成器：DES = `engineBoots‖计数器`（8 字节且唯一），AES = 64-bit 计数器（8 字节且唯一）。
#[test]
fn salt_generator_is_eight_bytes_and_unique() {
    let generator = SaltGenerator::new();
    for protocol in [PrivProtocol::Des, PrivProtocol::Aes] {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let salt = generator.next_salt(protocol, 7);
            assert!(salt.is_ok(), "{protocol:?}: {salt:?}");
            let Ok(salt) = salt else { continue };
            assert_eq!(salt.len(), PRIV_SALT_LEN);
            assert!(seen.insert(salt.clone()), "{protocol:?}: salt 必须唯一（同一密钥下 IV 不得重复）");
            if protocol == PrivProtocol::Des {
                assert_eq!(salt.get(..4), Some([0_u8, 0, 0, 7].as_slice()), "DES salt 前 4 字节必须是 engineBoots");
            }
        }
    }
    assert!(generator.next_salt(PrivProtocol::Des, i64::from(u32::MAX) + 1).is_err());
}

/// 真实 UDP：authPriv trap 落库；错隐私口令被拒且计入 dropped + usmStats（不静默）。
#[tokio::test]
async fn auth_priv_receiver_ingests_over_real_udp_and_counts_failures() {
    use tokio::net::UdpSocket;
    let server = UsmConfig::auth_priv("agf", AuthProtocol::Sha1, "maplesyrup", PrivProtocol::Aes, "privsecret")
        .unwrap_or_default();
    let (receiver, sink) = v3_receiver(server.clone());
    let counters = Arc::clone(receiver.counters());
    let Ok(socket) = receiver.bind().await else { return };
    let Ok(local) = socket.local_addr() else { return };
    let serve = tokio::spawn(async move {
        let _ = receiver.serve(socket).await;
    });
    let Ok(client) = UdpSocket::bind("127.0.0.1:0").await else { return };

    let good = encode::v3_trap(&encode::V3TrapSpec::auth_priv(
        "agf",
        AuthProtocol::Sha1,
        "maplesyrup",
        PrivProtocol::Aes,
        "privsecret",
    ))
    .unwrap_or_default();
    let _ = client.send_to(&good, local).await;
    let mut landed = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if sink.event_count(TenantId::default_tenant()).await.ok() == Some(1) {
            landed = true;
            break;
        }
    }
    serve.abort();
    assert!(landed, "authPriv（AES）真实 UDP 报文必须解密后落库");
    assert_eq!(counters.snapshot().received, 1);
    assert_eq!(counters.snapshot().dropped, 0);

    // 错隐私口令：拒绝 + dropped + usmStats 分类计数
    // （salt 固定 ⇒ 解出的乱码确定，用例可复现；判定标准是"拒绝 + 分类计数"，
    //   而不是"错误类型一定是哪一种"——乱码可能落在 ScopedPDU 外层、上下文或 PDU 字段上）
    let (strict, _strict_sink) = v3_receiver(server);
    let mut bad_spec =
        encode::V3TrapSpec::auth_priv("agf", AuthProtocol::Sha1, "maplesyrup", PrivProtocol::Aes, "totally-wrong");
    bad_spec.priv_salt = Some(vec![0x5a; PRIV_SALT_LEN]);
    let bad = encode::v3_trap(&bad_spec).unwrap_or_default();
    let rejected = strict.ingest_datagram(&bad, "203.0.113.9:40123").await;
    assert!(
        matches!(rejected, Err(DomainError::Unauthenticated(_) | DomainError::Parse(_))),
        "错隐私口令必须被拒绝：{rejected:?}"
    );
    assert!(rejected.is_err(), "错隐私口令绝不能落到落库路径");
    assert_eq!(strict.counters().snapshot().dropped, 1);
    let strict_stats = strict.usm_stats().snapshot();
    assert_eq!(strict_stats.decryption_errors, 1, "{strict_stats:?}");
    assert_eq!(strict_stats.accepted_priv, 0);
    assert!(
        strict_stats.priv_padding_errors + strict_stats.priv_short_plaintext >= 1,
        "必须细分到补齐/短明文：{strict_stats:?}"
    );
}

/// 十六进制解码（测试夹具用；非法输入返回 None）。
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = (pair.first().copied()? as char).to_digit(16)?;
        let low = (pair.get(1).copied()? as char).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(out)
}

/// 从报文的 HeaderData 里取出 `msgFlags` 字节（与解析同一套导航；测试断言用）。
fn msg_flags(message: &[u8]) -> Option<u8> {
    let (tag, body, body_offset) = ber::Reader::new(message).read_tlv_at().ok()?;
    if tag != ber::TAG_SEQUENCE {
        return None;
    }
    let mut reader = ber::Reader::with_base(body, body_offset);
    let _version = reader.read_integer().ok()?;
    let (header_tag, header, header_offset) = reader.read_tlv_at().ok()?;
    if header_tag != ber::TAG_SEQUENCE {
        return None;
    }
    let mut header_reader = ber::Reader::with_base(header, header_offset);
    let _msg_id = header_reader.read_integer().ok()?;
    let _max_size = header_reader.read_integer().ok()?;
    header_reader.read_octet_string().ok()?.first().copied()
}

/// 报文里 `msgData`（ScopedPDU）的 TLV 标签（明文是 `0x30`、authPriv 密文是 `0x04`）。
fn payload_tlv(message: &[u8]) -> (Option<u8>, usize) {
    let Some((tag, body, body_offset)) = ber::Reader::new(message).read_tlv_at().ok() else {
        return (None, 0);
    };
    if tag != ber::TAG_SEQUENCE {
        return (None, 0);
    }
    let mut reader = ber::Reader::with_base(body, body_offset);
    let _version = reader.read_integer().ok();
    let _header = reader.read_tlv_at().ok();
    let _params = reader.read_tlv_at().ok();
    match reader.read_tlv_at() {
        Ok((data_tag, data, _)) => (Some(data_tag), data.len()),
        Err(_) => (None, 0),
    }
}

/// 子串包含（密文断言用：明文 varbind 的 OID 不得出现在报文里）。
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

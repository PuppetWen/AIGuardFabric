//! SNMP v3 报文体解析：USM 参数读取、认证摘要校验、scoped PDU 与 varbind 取值渲染。

use super::*;

/// v3 解析主体：`message_reader` 已读过 version INTEGER，`whole` 是**完整报文**
/// （HMAC 必须在整报文上重算：`msgAuthenticationParameters` 段置 0 后取摘要）。
pub(super) fn v3_body(
    message_reader: &mut ber::Reader<'_>,
    whole: &[u8],
    config: &UsmConfig,
    clock: &EngineClock,
    stats: &UsmStats,
) -> DomainResult<SnmpTrap> {
    // ---- msgGlobalData（HeaderData）----
    let (header_tag, header, header_offset) = message_reader.read_tlv_at()?;
    if header_tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse(format!("SNMP v3 msgGlobalData 必须是 SEQUENCE，实际 0x{header_tag:02x}")));
    }
    let mut header_reader = ber::Reader::with_base(header, header_offset);
    let _msg_id = header_reader.read_integer()?;
    let msg_max_size = header_reader.read_integer()?;
    let flags = header_reader.read_octet_string()?;
    let security_model = header_reader.read_integer()?;
    let Some(flags_byte) = flags.first().copied() else {
        return Err(DomainError::Parse("SNMP v3 msgFlags 必须恰好 1 字节".to_string()));
    };
    if flags.len() != 1 {
        return Err(DomainError::Parse(format!("SNMP v3 msgFlags 长度 {} 非法（应为 1）", flags.len())));
    }
    if security_model != 3 {
        return Err(DomainError::Parse(format!(
            "SNMP v3 msgSecurityModel {security_model} 不是 USM(3)：本实现只支持 USM"
        )));
    }
    let Some(message_level) = V3SecurityLevel::from_msg_flags(flags_byte) else {
        return Err(DomainError::Parse(format!("SNMP v3 msgFlags 0x{flags_byte:02x} 无法解析安全级别")));
    };

    // ---- msgSecurityParameters（OCTET STRING 里套 USM SEQUENCE）----
    let (params_tag, params, params_offset) = message_reader.read_tlv_at()?;
    if params_tag != ber::TAG_OCTET_STRING {
        return Err(DomainError::Parse(format!(
            "SNMP v3 msgSecurityParameters 必须是 OCTET STRING，实际 0x{params_tag:02x}"
        )));
    }
    let mut params_reader = ber::Reader::with_base(params, params_offset);
    let (usm_tag, usm, usm_offset) = params_reader.read_tlv_at()?;
    if usm_tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse(format!("SNMP v3 USM 参数必须是 SEQUENCE，实际 0x{usm_tag:02x}")));
    }
    let mut usm_reader = ber::Reader::with_base(usm, usm_offset);
    let engine_id = usm_reader.read_octet_string()?;
    let engine_boots = usm_reader.read_integer()?;
    let engine_time = usm_reader.read_integer()?;
    let user_name = ber::render_bytes(&usm_reader.read_octet_string()?);
    let (auth_tag, auth_params, auth_offset) = usm_reader.read_tlv_at()?;
    if auth_tag != ber::TAG_OCTET_STRING {
        return Err(DomainError::Parse(format!(
            "SNMP v3 msgAuthenticationParameters 必须是 OCTET STRING，实际 0x{auth_tag:02x}"
        )));
    }
    // msgPrivacyParameters：authPriv 时是 8 字节 salt（DES/AES 的 IV 都由它参与推导）
    let priv_params = usm_reader.read_octet_string()?;
    let _ = msg_max_size; // msgMaxSize 仅用于应答分片，本接收器不回应答

    // ---- 安全级别校验（RFC3414 §3.2 步骤 3）----
    if message_level != config.level {
        stats.bump(UsmStatsKind::UnsupportedSecLevels);
        return Err(DomainError::Unauthenticated(format!(
            "SNMP v3 安全级别不匹配：配置 {}，报文 {}（本实现不隐式升降级）",
            config.level.as_str(),
            message_level.as_str()
        )));
    }

    // ---- 用户名校验（RFC3414 §3.2 步骤 6）----
    if let Some(expected) = config.user.as_deref().filter(|u| !u.is_empty()) {
        if !constant_time_eq(expected.as_bytes(), user_name.as_bytes()) {
            stats.bump(UsmStatsKind::UnknownUserNames);
            return Err(DomainError::Unauthenticated(format!(
                "SNMP v3 用户名不匹配（配置 {expected:?}，报文 {user_name:?}）"
            )));
        }
    }

    // ---- 时限窗口 + 摘要校验（RFC3414 §3.2 步骤 7.1 / 7.2）----
    // authPriv 也必须先认证（RFC3414 §1.4.3：用隐私就必须认证），摘要覆盖**整报文**——
    // 含加密后的 ScopedPDU 密文，因此解密前就能判定篡改。
    if message_level != V3SecurityLevel::NoAuthNoPriv {
        if !clock.check(&engine_id, engine_boots, engine_time) {
            stats.bump(UsmStatsKind::NotInTimeWindows);
            return Err(DomainError::Unauthenticated(format!(
                "SNMP v3 超出时限窗口（{USM_TIME_WINDOW_SECS}s）：engineBoots={engine_boots} engineTime={engine_time}"
            )));
        }
        let Some(key) = config.localized_key(&engine_id) else {
            return Err(DomainError::Config("SNMP v3 认证密钥本地化失败（口令为空？）".to_string()));
        };
        let Some(expected) = config.auth_protocol.authenticate(&key, whole, auth_offset, auth_params.len()) else {
            return Err(DomainError::Parse("SNMP v3 摘要计算失败（报文字段偏移越界）".to_string()));
        };
        if auth_params.len() != config.auth_protocol.digest_len() || !constant_time_eq(&expected, auth_params) {
            stats.bump(UsmStatsKind::WrongDigests);
            return Err(DomainError::Unauthenticated(format!(
                "SNMP v3 认证摘要不匹配（{}）：口令错误或报文被篡改",
                config.auth_protocol.as_str()
            )));
        }
    }

    // ---- msgData / ScopedPDU（authPriv 时是密文，先解密）----
    let (data_tag, data, data_offset) = message_reader.read_tlv_at()?;
    let mut trap = SnmpTrap {
        version: "v3".to_string(),
        community: String::new(),
        user: Some(user_name.clone()),
        security_level: Some(message_level.as_str().to_string()),
        engine_id: Some(hex_lower(&engine_id)),
        pdu_type: "trap".to_string(),
        request_id: None,
        enterprise: None,
        agent_address: None,
        generic_trap: None,
        specific_trap: None,
        varbinds: Vec::new(),
        source: String::new(),
    };
    // 解密后的 ScopedPDU 拥有权在本函数内（`decrypted`），明文路径直接借用报文切片。
    let decrypted = if message_level == V3SecurityLevel::AuthPriv {
        Some(decrypt_scoped_pdu(data_tag, data, config, &engine_id, engine_boots, engine_time, &priv_params, stats)?)
    } else {
        if data_tag != ber::TAG_SEQUENCE {
            return Err(DomainError::Parse(format!(
                "SNMP v3 未加密 msgData 必须是 SEQUENCE（ScopedPDU），实际 0x{data_tag:02x}"
            )));
        }
        None
    };
    let (scoped_body, scoped_offset) = match decrypted.as_deref() {
        Some(plaintext) => {
            // 解密载荷的**外层结构**（ScopedPDU SEQUENCE / 长度域）非法 ⇒ 只可能是隐私口令不符或密文被改，
            // 归为 `Unauthenticated`（报成 Parse 会让人误以为是报文格式问题，且会绕过 usmStats 计数）。
            let parsed = ber::Reader::new(plaintext).read_tlv_at();
            match parsed {
                Ok((tag, body, offset)) if tag == ber::TAG_SEQUENCE => (body, offset),
                Ok((tag, _, _)) => {
                    stats.bump(UsmStatsKind::DecryptionErrors);
                    stats.record_priv_padding_error();
                    return Err(DomainError::Unauthenticated(format!(
                        "SNMP v3 解密结果不是合法 ScopedPDU（应该是 SEQUENCE，实际 0x{tag:02x}）：隐私口令错误或密文被篡改"
                    )));
                }
                Err(error) => {
                    stats.bump(UsmStatsKind::DecryptionErrors);
                    stats.record_priv_padding_error();
                    return Err(DomainError::Unauthenticated(format!(
                        "SNMP v3 解密结果长度域非法（隐私口令错误或密文被篡改）：{error}"
                    )));
                }
            }
        }
        None => (data, data_offset),
    };
    let mut scoped = ber::Reader::with_base(scoped_body, scoped_offset);
    // 解密路径下"上下文字段解不出来"同样按解密失败归类（乱码的典型表现）
    let context = (|| -> DomainResult<()> {
        let _context_engine_id = scoped.read_octet_string()?;
        let _context_name = scoped.read_octet_string()?;
        Ok(())
    })();
    if let Err(error) = context {
        if decrypted.is_some() {
            stats.bump(UsmStatsKind::DecryptionErrors);
            stats.record_priv_padding_error();
            return Err(DomainError::Unauthenticated(format!(
                "SNMP v3 解密结果的上下文（contextEngineID/contextName）非法（隐私口令错误或密文被篡改）：{error}"
            )));
        }
        return Err(error);
    }
    let (pdu_tag, pdu) = scoped.read_tlv()?;
    // 解密路径：**未知 PDU 标签**是"密钥错"的强证据（正确的密钥+明文才会带合法标签）；
    // 已知标签（Trap/Inform/Report）下的字段级错误仍是真正的格式错误（例如 Report PDU 的显式报错）。
    if decrypted.is_some()
        && !matches!(pdu_tag, ber::TAG_TRAP_V2 | ber::TAG_INFORM | ber::TAG_TRAP_V1 | ber::TAG_REPORT)
    {
        stats.bump(UsmStatsKind::DecryptionErrors);
        stats.record_priv_padding_error();
        return Err(DomainError::Unauthenticated(format!(
            "SNMP v3 解密结果的 PDU 标签 0x{pdu_tag:02x} 未知（隐私口令错误或密文被篡改）"
        )));
    }
    apply_pdu(&mut trap, pdu_tag, pdu)?;
    // 全通过才计"接受"：认证（+解密）成功且 PDU 真的解析出来了（不把被拒报文算成接收成功）
    match message_level {
        V3SecurityLevel::AuthPriv => stats.accept_priv(),
        V3SecurityLevel::AuthNoPriv => stats.accept_auth(),
        V3SecurityLevel::NoAuthNoPriv => stats.accept_noauth(),
    }
    Ok(trap)
}

/// 解密 authPriv 的 `msgData` 并剥掉补齐，返回**明文 ScopedPDU TLV**。
///
/// 分类计数（RFC3414 §5 + 本实现的细分）：
/// * salt 长度非法 / 密文长度非法 / 密钥缺失 ⇒ `usmStatsDecryptionErrors`；
/// * 明文结构非法（非 SEQUENCE / 长度越界）⇒ `usmStatsDecryptionErrors` + `priv_padding_errors`；
/// * 明文过短（空）⇒ `usmStatsDecryptionErrors` + `priv_short_plaintext`。
fn decrypt_scoped_pdu(
    data_tag: u8,
    data: &[u8],
    config: &UsmConfig,
    engine_id: &[u8],
    engine_boots: i64,
    engine_time: i64,
    priv_params: &[u8],
    stats: &UsmStats,
) -> DomainResult<Vec<u8>> {
    if data_tag != ber::TAG_OCTET_STRING {
        stats.bump(UsmStatsKind::DecryptionErrors);
        return Err(DomainError::Parse(format!(
            "SNMP v3 authPriv 的 msgData 必须是 OCTET STRING（密文），实际 0x{data_tag:02x}"
        )));
    }
    let Some(key) = config.localized_priv_key(engine_id) else {
        stats.bump(UsmStatsKind::DecryptionErrors);
        return Err(DomainError::Config("SNMP v3 authPriv 隐私密钥本地化失败（隐私口令未配置？）".to_string()));
    };
    let plaintext = match privacy::decrypt(config.priv_protocol, &key, priv_params, engine_boots, engine_time, data) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            stats.bump(UsmStatsKind::DecryptionErrors);
            return Err(DomainError::Unauthenticated(format!(
                "SNMP v3 {} 解密失败：{error}",
                config.priv_protocol.as_str()
            )));
        }
    };
    match privacy::strip_padding(&plaintext) {
        Ok((tlv, padding)) => {
            // 只有**还原出合法 ScopedPDU** 才算"解密成功"：块密码跑通但解出乱码的报文
            // 计入 decryption_errors + padding/short 细分（不虚报成功）。
            stats.record_priv_decrypt();
            debug!(
                protocol = config.priv_protocol.as_str(),
                ciphertext = data.len(),
                plaintext = plaintext.len(),
                padding,
                "SNMP v3 authPriv 解密成功（补齐按 BER 长度剥离，RFC3414 §8.1.1.3）"
            );
            Ok(tlv.to_vec())
        }
        Err(error) => {
            stats.bump(UsmStatsKind::DecryptionErrors);
            if plaintext.len() < privacy::DES_BLOCK_LEN {
                stats.record_priv_short_plaintext();
            } else {
                stats.record_priv_padding_error();
            }
            Err(DomainError::Unauthenticated(format!(
                "SNMP v3 {} 解密后补齐/结构非法（隐私口令错误或密文被篡改）：{error}",
                config.priv_protocol.as_str()
            )))
        }
    }
}

/// 小写 hex（引擎 ID 展示）。
pub(super) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// 把一个 PDU 应用到 trap 上（v1 / v2c / v3 共用**同一份** PDU 解析）。
pub(super) fn apply_pdu(trap: &mut SnmpTrap, pdu_tag: u8, pdu: &[u8]) -> DomainResult<()> {
    match pdu_tag {
        ber::TAG_TRAP_V2 | ber::TAG_INFORM => {
            let mut pdu_reader = ber::Reader::new(pdu);
            trap.request_id = Some(pdu_reader.read_integer()?);
            // error-status / error-index：Trap 里恒为 0，读掉但不保留
            let _ = pdu_reader.read_integer()?;
            let _ = pdu_reader.read_integer()?;
            trap.varbinds = read_varbinds(&mut pdu_reader)?;
            if pdu_tag == ber::TAG_INFORM {
                trap.pdu_type = "inform".to_string();
            }
        }
        ber::TAG_TRAP_V1 => {
            let mut pdu_reader = ber::Reader::new(pdu);
            trap.enterprise = Some(pdu_reader.read_oid()?);
            let (addr_tag, addr) = pdu_reader.read_tlv()?;
            if addr_tag != ber::TAG_IP_ADDRESS || addr.len() != 4 {
                return Err(DomainError::Parse("SNMP v1 Trap 的 agent-addr 必须是 4 字节 IpAddress".to_string()));
            }
            trap.agent_address = Some(addr.iter().map(u8::to_string).collect::<Vec<_>>().join("."));
            trap.generic_trap = Some(pdu_reader.read_integer()?);
            trap.specific_trap = Some(pdu_reader.read_integer()?);
            let _timestamp = pdu_reader.read_tlv()?; // time-stamp（TimeTicks）
            trap.varbinds = read_varbinds(&mut pdu_reader)?;
        }
        ber::TAG_REPORT => {
            let mut pdu_reader = ber::Reader::new(pdu);
            let _request_id = pdu_reader.read_integer()?;
            let _ = pdu_reader.read_integer()?;
            let _ = pdu_reader.read_integer()?;
            let report = read_varbinds(&mut pdu_reader).ok();
            let oid = report
                .as_ref()
                .and_then(|binds| binds.first())
                .map(|bind| format!("{}={}", bind.oid, bind.value))
                .unwrap_or_else(|| "<无 varbind>".to_string());
            return Err(DomainError::Parse(format!("SNMP Report PDU（对端在报告 usmStats / 引擎发现信息）：{oid}")));
        }
        other => {
            return Err(DomainError::Parse(format!(
                "SNMP PDU 0x{other:02x} 不是 Trap（仅支持 v1 Trap 0xa4 / v2c Trap 0xa7 / Inform 0xa6）"
            )));
        }
    }
    Ok(())
}

/// 读 `VarBindList`。
fn read_varbinds(reader: &mut ber::Reader<'_>) -> DomainResult<Vec<SnmpVarBind>> {
    let mut out = Vec::new();
    let (tag, list) = reader.read_tlv()?;
    if tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse(format!("SNMP VarBindList 必须是 SEQUENCE，实际 0x{tag:02x}")));
    }
    let mut list_reader = ber::Reader::new(list);
    while !list_reader.eof() {
        let (bind_tag, bind) = list_reader.read_tlv()?;
        if bind_tag != ber::TAG_SEQUENCE {
            return Err(DomainError::Parse(format!("SNMP VarBind 必须是 SEQUENCE，实际 0x{bind_tag:02x}")));
        }
        let mut bind_reader = ber::Reader::new(bind);
        let oid = bind_reader.read_oid()?;
        let (value_tag, value) = bind_reader.read_tlv()?;
        let (syntax, rendered) = render_value(value_tag, value)?;
        out.push(SnmpVarBind { oid, value: rendered, syntax });
    }
    Ok(out)
}

/// 把 `ObjectSyntax` 渲染成 `(语法名, 文本)`。
fn render_value(tag: u8, value: &[u8]) -> DomainResult<(String, String)> {
    let (syntax, rendered) = match tag {
        ber::TAG_INTEGER => ("INTEGER", ber::decode_integer(value).to_string()),
        ber::TAG_OCTET_STRING => ("OCTET STRING", ber::render_bytes(value)),
        ber::TAG_NULL => ("NULL", String::new()),
        ber::TAG_OID => ("OID", ber::decode_oid(value)?),
        ber::TAG_IP_ADDRESS => {
            if value.len() == 4 {
                ("IpAddress", value.iter().map(u8::to_string).collect::<Vec<_>>().join("."))
            } else {
                ("IpAddress", ber::render_bytes(value))
            }
        }
        ber::TAG_COUNTER32 => ("Counter32", ber::decode_unsigned(value).to_string()),
        ber::TAG_GAUGE32 => ("Gauge32", ber::decode_unsigned(value).to_string()),
        ber::TAG_TIMETICKS => {
            let ticks = ber::decode_unsigned(value);
            ("TimeTicks", format!("{ticks} ({})", ber::format_timeticks(ticks)))
        }
        ber::TAG_OPAQUE => ("Opaque", ber::render_bytes(value)),
        ber::TAG_COUNTER64 => ("Counter64", ber::decode_unsigned(value).to_string()),
        ber::TAG_NSAP => ("NsapAddress", ber::render_bytes(value)),
        other => ("Unknown", format!("0x{other:02x}:{}", ber::render_bytes(value))),
    };
    Ok((syntax.to_string(), rendered))
}

// ---------------------------------------------------------------------------
// 报文构造（接收器本体只解析；编码器供单测/模拟器/审计复现使用）
// ---------------------------------------------------------------------------

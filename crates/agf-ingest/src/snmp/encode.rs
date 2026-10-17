//! BER 编码辅助与 SNMP 报文构造器。
//!
//! **为什么把编码器放在库里而不是只放在测试里**：手写协议最容易出错的地方是
//! "编码器与解析器对不上"。把编码器放在与解析器同一套类型常量下，单测就能直接证明两者自洽
//! （`ber_length`/`tlv`/`integer`/`oid` 与 `ber::Reader` 一一对应），
//! `tools/simulators/snmp_v3_trap.py` 也用同一套编码规则，便于双向对照。

// ---------------------------------------------------------------------------
// 报文构造（接收器本体只解析；编码器供单测/模拟器/审计复现使用）
// ---------------------------------------------------------------------------

use agf_core::error::{DomainError, DomainResult};

use super::ber;
use super::{
    AuthProtocol, PRIV_SALT_LEN, PrivProtocol, SaltGenerator, USM_DIGEST_LEN, V3SecurityLevel, encrypt,
    localized_priv_key,
};

/// 长度域（定长最小编码）。
pub fn ber_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0x7f));
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap_or(1));
        out.extend_from_slice(&bytes);
    }
}

/// 一个 TLV。
#[must_use]
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    ber_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// `INTEGER`（最短二补码）。
#[must_use]
pub fn integer(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let first = bytes.first().copied().unwrap_or(0);
        let second = bytes.get(1).copied().unwrap_or(0);
        let redundant = (first == 0x00 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0);
        if redundant {
            bytes.remove(0);
        } else {
            break;
        }
    }
    tlv(ber::TAG_INTEGER, &bytes)
}

/// `OCTET STRING`。
#[must_use]
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(ber::TAG_OCTET_STRING, bytes)
}

/// `OBJECT IDENTIFIER`（首两段合并为 `40*X + Y`，其余 base-128）。
#[must_use]
pub fn oid(parts: &[u64]) -> Vec<u8> {
    let mut body = Vec::new();
    if let (Some(first), Some(second)) = (parts.first(), parts.get(1)) {
        body.push(u8::try_from(first * 40 + second).unwrap_or(0));
    }
    for part in parts.iter().skip(2) {
        let mut chunk = Vec::new();
        let mut value = *part;
        loop {
            chunk.push(u8::try_from(value & 0x7f).unwrap_or(0));
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        chunk.reverse();
        let last = chunk.len().saturating_sub(1);
        for (index, byte) in chunk.iter().enumerate() {
            body.push(if index == last { *byte } else { *byte | 0x80 });
        }
    }
    tlv(ber::TAG_OID, &body)
}

/// 点分十进制 OID 文本 → BER。
///
/// # Errors
/// 段数不足或含非数字段。
pub fn oid_from_str(text: &str) -> DomainResult<Vec<u8>> {
    let mut parts = Vec::new();
    for piece in text.split('.') {
        let value = piece
            .trim()
            .parse::<u64>()
            .map_err(|e| DomainError::Parse(format!("OID {text:?} 的段 {piece:?} 非法: {e}")))?;
        parts.push(value);
    }
    if parts.len() < 2 {
        return Err(DomainError::Parse(format!("OID {text:?} 至少需要两段")));
    }
    Ok(oid(&parts))
}

/// 无符号应用类型（`Counter32` / `Gauge32` / `TimeTicks` / `Counter64`）。
#[must_use]
pub fn unsigned(tag: u8, value: u64) -> Vec<u8> {
    let raw = value.to_be_bytes();
    let trimmed: Vec<u8> = raw.iter().copied().skip_while(|b| *b == 0).collect();
    let body: &[u8] = if trimmed.is_empty() { &[0_u8] } else { &trimmed };
    tlv(tag, body)
}

fn varbind(oid_text: &str, value: &[u8]) -> DomainResult<Vec<u8>> {
    let mut body = oid_from_str(oid_text)?;
    body.extend_from_slice(value);
    Ok(tlv(ber::TAG_SEQUENCE, &body))
}

/// VarBind：值为 `OCTET STRING` 文本。
///
/// # Errors
/// OID 文本非法。
pub fn varbind_text(oid_text: &str, value: &str) -> DomainResult<Vec<u8>> {
    varbind(oid_text, &octet_string(value.as_bytes()))
}

/// VarBind：值为 `OBJECT IDENTIFIER`。
///
/// # Errors
/// OID 文本非法。
pub fn varbind_oid(oid_text: &str, value_oid: &str) -> DomainResult<Vec<u8>> {
    varbind(oid_text, &oid_from_str(value_oid)?)
}

/// VarBind：值为 `TimeTicks`。
///
/// # Errors
/// OID 文本非法。
pub fn varbind_ticks(oid_text: &str, ticks: u64) -> DomainResult<Vec<u8>> {
    varbind(oid_text, &unsigned(ber::TAG_TIMETICKS, ticks))
}

/// VarBind：值为 `INTEGER`。
///
/// # Errors
/// OID 文本非法。
pub fn varbind_integer(oid_text: &str, value: i64) -> DomainResult<Vec<u8>> {
    varbind(oid_text, &integer(value))
}

/// v3 Trap 构造规格。
#[derive(Debug, Clone)]
pub struct V3TrapSpec {
    /// `msgID`。
    pub msg_id: i64,
    /// `msgAuthoritativeEngineID`。
    pub engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots`。
    pub engine_boots: i64,
    /// `msgAuthoritativeEngineTime`。
    pub engine_time: i64,
    /// `msgUserName`。
    pub user: String,
    /// 安全级别（`AuthPriv` 时按 [`Self::priv_protocol`] 真实加密 ScopedPDU）。
    pub level: V3SecurityLevel,
    /// 认证协议。
    pub auth_protocol: AuthProtocol,
    /// 认证口令（`authNoPriv` / `authPriv` 用）。
    pub auth_password: String,
    /// 隐私协议（`authPriv` 用）。
    pub priv_protocol: PrivProtocol,
    /// 隐私口令（`authPriv` 用；**不落日志**）。
    pub priv_password: String,
    /// 覆盖 `msgPrivacyParameters`（salt；`None` = 由引擎时钟 + 计数器推导）。
    pub priv_salt: Option<Vec<u8>>,
    /// `request-id`。
    pub request_id: i64,
    /// `snmpTrapOID.0` 值。
    pub trap_oid: String,
    /// `sysUpTime.0`（TimeTicks）。
    pub uptime_ticks: u64,
    /// 覆盖 `msgFlags`（`None` = 由安全级别推导；用于构造非法级别对照）。
    pub flags_override: Option<u8>,
    /// 覆盖摘要字节（`None` = 正确计算；用于构造错密码/篡改对照）。
    pub digest_override: Option<Vec<u8>>,
}

impl V3TrapSpec {
    /// 以合理默认值构造（引擎 ID `80001f8880000000000002`、标准 trap OID、100 秒引擎时间）。
    #[must_use]
    pub fn new(user: impl Into<String>, level: V3SecurityLevel) -> Self {
        Self {
            msg_id: 1_048_576,
            engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
            engine_boots: 1,
            engine_time: 100,
            user: user.into(),
            level,
            auth_protocol: AuthProtocol::Md5,
            auth_password: String::new(),
            priv_protocol: PrivProtocol::default(),
            priv_password: String::new(),
            priv_salt: None,
            request_id: 1_048_576,
            trap_oid: "1.3.6.1.4.1.8072.0.1".to_string(),
            uptime_ticks: 12_345_678,
            flags_override: None,
            digest_override: None,
        }
    }

    /// 便捷构造 `authPriv` 规格（认证 + 隐私口令都给，隐私协议显式指定）。
    #[must_use]
    pub fn auth_priv(
        user: impl Into<String>,
        auth_protocol: AuthProtocol,
        auth_password: impl Into<String>,
        priv_protocol: PrivProtocol,
        priv_password: impl Into<String>,
    ) -> Self {
        let mut spec = Self::new(user, V3SecurityLevel::AuthPriv);
        spec.auth_protocol = auth_protocol;
        spec.auth_password = auth_password.into();
        spec.priv_protocol = priv_protocol;
        spec.priv_password = priv_password.into();
        spec
    }
}

/// 定位整报文里 `msgAuthenticationParameters` 的**绝对偏移**（与解析器同一套导航）。
///
/// # Errors
/// 报文结构与 v3 规范不符（被截断或类型错误）。
pub fn auth_offset(message: &[u8]) -> DomainResult<usize> {
    Ok(usm_segment_offsets(message)?.0)
}

/// 定位 `msgPrivacyParameters`（salt）在整报文里的绝对偏移（抓包复现/取证用：可直接取出 salt）。
///
/// # Errors
/// 报文结构与 v3 规范不符（被截断或类型错误）。
pub fn priv_params_offset(message: &[u8]) -> DomainResult<usize> {
    Ok(usm_segment_offsets(message)?.1)
}

/// 一次导航同时拿到 `(auth 值偏移, priv 值偏移)`——两段是 USM SEQUENCE 里相邻的两个 OCTET STRING。
fn usm_segment_offsets(message: &[u8]) -> DomainResult<(usize, usize)> {
    let mut outer = ber::Reader::new(message);
    let (tag, body, body_offset) = outer.read_tlv_at()?;
    if tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse("v3 报文顶层必须是 SEQUENCE".to_string()));
    }
    let mut reader = ber::Reader::with_base(body, body_offset);
    let _version = reader.read_integer()?;
    let _header = reader.read_tlv_at()?;
    let (params_tag, params, params_offset) = reader.read_tlv_at()?;
    if params_tag != ber::TAG_OCTET_STRING {
        return Err(DomainError::Parse("v3 msgSecurityParameters 必须是 OCTET STRING".to_string()));
    }
    let mut params_reader = ber::Reader::with_base(params, params_offset);
    let (usm_tag, usm, usm_offset) = params_reader.read_tlv_at()?;
    if usm_tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse("v3 USM 参数必须是 SEQUENCE".to_string()));
    }
    let mut usm_reader = ber::Reader::with_base(usm, usm_offset);
    let _engine_id = usm_reader.read_octet_string()?;
    let _boots = usm_reader.read_integer()?;
    let _time = usm_reader.read_integer()?;
    let _user = usm_reader.read_octet_string()?;
    let (auth_tag, _auth, auth_offset) = usm_reader.read_tlv_at()?;
    if auth_tag != ber::TAG_OCTET_STRING {
        return Err(DomainError::Parse("v3 msgAuthenticationParameters 必须是 OCTET STRING".to_string()));
    }
    let (priv_tag, _priv, priv_offset) = usm_reader.read_tlv_at()?;
    if priv_tag != ber::TAG_OCTET_STRING {
        return Err(DomainError::Parse("v3 msgPrivacyParameters 必须是 OCTET STRING".to_string()));
    }
    Ok((auth_offset, priv_offset))
}

/// 构造完整的 SNMP v3 Trap 报文（`msgFlags` 由安全级别推导；`authNoPriv`/`authPriv` 都写入真实摘要，
/// `authPriv` 还会**真实加密** ScopedPDU）。
///
/// # Errors
/// OID 文本非法、口令为空（`authNoPriv`/`authPriv`）、salt/密钥推导失败或报文结构异常。
pub fn v3_trap(spec: &V3TrapSpec) -> DomainResult<Vec<u8>> {
    // VarBindList：snmpTrapOID.0 + sysUpTime.0
    let mut varbinds = varbind_oid(super::SNMP_TRAP_OID, &spec.trap_oid)?;
    varbinds.extend_from_slice(&varbind_ticks(super::SYS_UPTIME_OID, spec.uptime_ticks)?);

    // SNMPv2-Trap-PDU（0xa7）
    let mut pdu = integer(spec.request_id);
    pdu.extend_from_slice(&integer(0));
    pdu.extend_from_slice(&integer(0));
    pdu.extend_from_slice(&tlv(ber::TAG_SEQUENCE, &varbinds));

    // ScopedPDU（明文）
    let mut scoped = octet_string(&spec.engine_id);
    scoped.extend_from_slice(&octet_string(&[]));
    scoped.extend_from_slice(&tlv(ber::TAG_TRAP_V2, &pdu));
    let scoped = tlv(ber::TAG_SEQUENCE, &scoped);

    // ---- authPriv：按 RFC 加密 ScopedPDU，msgPrivacyParameters = salt ----
    let auth_used = spec.level != V3SecurityLevel::NoAuthNoPriv;
    let priv_params: Vec<u8> = if spec.level == V3SecurityLevel::AuthPriv {
        match &spec.priv_salt {
            Some(salt) => {
                if salt.len() != PRIV_SALT_LEN {
                    return Err(DomainError::Internal(format!(
                        "v3 authPriv salt 覆盖长度 {} 非法（应为 {PRIV_SALT_LEN}）",
                        salt.len()
                    )));
                }
                salt.clone()
            }
            None => SaltGenerator::new().next_salt(spec.priv_protocol, spec.engine_boots)?,
        }
    } else {
        Vec::new()
    };
    let msg_data: Vec<u8> = if spec.level == V3SecurityLevel::AuthPriv {
        let key = localized_priv_key(spec.auth_protocol, &spec.priv_password, &spec.engine_id)
            .ok_or_else(|| DomainError::Config("v3 authPriv 隐私口令为空（无法本地化隐私密钥）".to_string()))?;
        let ciphertext = encrypt(spec.priv_protocol, &key, &priv_params, spec.engine_boots, spec.engine_time, &scoped)?;
        octet_string(&ciphertext)
    } else {
        scoped.clone()
    };

    // USM 安全参数（auth 段先填占位）
    let auth_len = if auth_used { USM_DIGEST_LEN } else { 0 };
    let mut usm = octet_string(&spec.engine_id);
    usm.extend_from_slice(&integer(spec.engine_boots));
    usm.extend_from_slice(&integer(spec.engine_time));
    usm.extend_from_slice(&octet_string(spec.user.as_bytes()));
    usm.extend_from_slice(&octet_string(&vec![0_u8; auth_len]));
    usm.extend_from_slice(&octet_string(&priv_params));
    let usm = tlv(ber::TAG_SEQUENCE, &usm);

    // HeaderData（msgFlags：安全位 + reportable）
    let flags = spec.flags_override.unwrap_or_else(|| spec.level.msg_flags() | 0x04);
    let mut header = integer(spec.msg_id);
    header.extend_from_slice(&integer(65_507));
    header.extend_from_slice(&tlv(ber::TAG_OCTET_STRING, &[flags]));
    header.extend_from_slice(&integer(3));
    let header = tlv(ber::TAG_SEQUENCE, &header);

    let mut message = integer(3);
    message.extend_from_slice(&header);
    message.extend_from_slice(&tlv(ber::TAG_OCTET_STRING, &usm));
    message.extend_from_slice(&msg_data);
    let mut message = tlv(ber::TAG_SEQUENCE, &message);

    if auth_used {
        let offset = auth_offset(&message)?;
        let digest = match &spec.digest_override {
            Some(wrong) => {
                if wrong.len() != USM_DIGEST_LEN {
                    return Err(DomainError::Internal(format!(
                        "v3 摘要覆盖长度 {} 非法（应为 {USM_DIGEST_LEN}）",
                        wrong.len()
                    )));
                }
                wrong.clone()
            }
            None => {
                let key = spec
                    .auth_protocol
                    .localize_key(&spec.auth_password, &spec.engine_id)
                    .ok_or_else(|| DomainError::Config("v3 认证口令为空".to_string()))?;
                spec.auth_protocol
                    .authenticate(&key, &message, offset, USM_DIGEST_LEN)
                    .ok_or_else(|| DomainError::Internal("v3 摘要计算失败".to_string()))?
            }
        };
        let end = offset.saturating_add(USM_DIGEST_LEN);
        if end > message.len() {
            return Err(DomainError::Internal("v3 摘要写入越界".to_string()));
        }
        message
            .get_mut(offset..end)
            .map(|slot| slot.copy_from_slice(&digest))
            .ok_or_else(|| DomainError::Internal("v3 摘要写入失败".to_string()))?;
    }
    Ok(message)
}

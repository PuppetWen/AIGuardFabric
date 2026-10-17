//! SNMP 报文模型与解析入口：varbind、Trap 结构，以及 v1/v2c/v3 解码分发与 PDU 应用。

// ---------------------------------------------------------------------------
// Trap 模型
// ---------------------------------------------------------------------------

use super::*;

/// 一个 VarBind（OID + 值 + 语法名）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpVarBind {
    /// 变量 OID。
    pub oid: String,
    /// 值的文本渲染（数字/字符串/hex）。
    pub value: String,
    /// 值的 SNMP 语法名（`INTEGER` / `OCTET STRING` / `TimeTicks` …）。
    pub syntax: String,
}

/// `snmpTrapOID.0`：v2c Trap 的"这是哪个 Trap"。
pub const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";
/// `sysUpTime.0`：代理运行时长。
pub const SYS_UPTIME_OID: &str = "1.3.6.1.2.1.1.3.0";

/// 解析后的 Trap。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpTrap {
    /// `v1` / `v2c` / `v3`。
    pub version: String,
    /// community 原文（**接入后仅用于来源判定，不写进事件正文**；v3 恒为空串）。
    pub community: String,
    /// v3：USM 用户名（v1/v2c 为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// v3：安全级别（`noAuthNoPriv` / `authNoPriv`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_level: Option<String>,
    /// v3：权威引擎 ID（hex；**不是**凭据，明文保留便于排障）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    /// PDU 类型（`trap` / `inform`）。
    pub pdu_type: String,
    /// `request-id`（v1 无）。
    pub request_id: Option<i64>,
    /// v1：`enterprise`。
    pub enterprise: Option<String>,
    /// v1：`agent-addr`。
    pub agent_address: Option<String>,
    /// v1：`generic-trap`。
    pub generic_trap: Option<i64>,
    /// v1：`specific-trap`。
    pub specific_trap: Option<i64>,
    /// 变量绑定。
    pub varbinds: Vec<SnmpVarBind>,
    /// 来源（`ip:port`，由接收器回填）。
    pub source: String,
}

impl SnmpTrap {
    /// trap OID：优先 varbind 里的 `snmpTrapOID.0`，其次 v1 的 `enterprise.0.specific`。
    #[must_use]
    pub fn trap_oid(&self) -> Option<String> {
        if let Some(found) = self.varbinds.iter().find(|vb| vb.oid == SNMP_TRAP_OID) {
            return Some(found.value.clone());
        }
        match (&self.enterprise, self.specific_trap) {
            (Some(enterprise), Some(specific)) => Some(format!("{enterprise}.0.{specific}")),
            (Some(enterprise), None) => Some(enterprise.clone()),
            _ => None,
        }
    }

    /// 代理运行时长（`sysUpTime.0`），单位百分之一秒。
    ///
    /// `TimeTicks` 的 `value` 文本形如 `"12345678 (1 day, 10:17:36.78)"`
    /// （裸值 + 人类可读形式），这里只取首个数字词元。
    #[must_use]
    pub fn uptime_ticks(&self) -> Option<u64> {
        self.varbinds
            .iter()
            .find(|vb| vb.oid == SYS_UPTIME_OID)
            .and_then(|vb| vb.value.split_whitespace().next())
            .and_then(|raw| raw.parse::<u64>().ok())
    }

    /// 归一化载荷（JSON；交给既有解析流水线）。
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let varbinds: Vec<serde_json::Value> = self
            .varbinds
            .iter()
            .map(|vb| serde_json::json!({"oid": vb.oid, "value": vb.value, "syntax": vb.syntax}))
            .collect();
        let trap_oid = self.trap_oid();
        let message = match &trap_oid {
            Some(oid) => {
                format!("SNMP {} trap {oid} from {}（{} 个 varbind）", self.version, self.source, self.varbinds.len())
            }
            None => format!("SNMP {} trap from {}（{} 个 varbind）", self.version, self.source, self.varbinds.len()),
        };
        serde_json::json!({
            "message": message,
            "snmp": {
                "version": self.version,
                "pdu_type": self.pdu_type,
                "request_id": self.request_id,
                "trap_oid": trap_oid,
                "enterprise": self.enterprise,
                "agent_address": self.agent_address,
                "generic_trap": self.generic_trap,
                "specific_trap": self.specific_trap,
                "uptime_ticks": self.uptime_ticks(),
                // v3（USM）：用户名 / 安全级别 / 权威引擎 ID；v1/v2c 为 null
                "user": self.user,
                "security_level": self.security_level,
                "engine_id": self.engine_id,
            },
            "varbinds": varbinds,
        })
        .to_string()
        .into_bytes()
    }
}

/// 版本无关入口：v1/v2c 走 community 校验，v3 走 USM（`usm` 为 `None` 时 v3 报文被明确拒绝）。
///
/// # Errors
/// BER 非法、版本非法、community/摘要/时限校验失败、PDU 不是 Trap。
pub fn parse_message(
    bytes: &[u8],
    expected_community: Option<&str>,
    usm: Option<(&UsmConfig, &EngineClock, &UsmStats)>,
) -> DomainResult<SnmpTrap> {
    let mut reader = ber::Reader::new(bytes);
    let (tag, message) = reader.read_tlv()?;
    if tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse(format!("SNMP 报文顶层必须是 SEQUENCE，实际 0x{tag:02x}")));
    }
    if !reader.eof() {
        return Err(DomainError::Parse(format!("SNMP 报文尾随 {} 字节未消费", reader.remaining())));
    }
    let mut probe = ber::Reader::new(message);
    let version_number = probe.read_integer()?;
    if version_number == 3 {
        let Some((config, clock, stats)) = usm else {
            return Err(DomainError::NotImplemented(
                "收到 SNMP v3 报文但未配置 USM（AGF_INGEST_SNMP_V3_*）：请把 AGF_INGEST_SNMP_VERSION 设为 v3 并配置用户名/安全级别"
                    .to_string(),
            ));
        };
        return parse_v3_message(bytes, config, clock, stats);
    }
    parse_v1_v2c_body(message, expected_community)
}

/// 解析一个 SNMP Trap 报文（v1 / v2c）。
///
/// `expected_community` 为 `Some` 时做常量时间比对；不匹配 ⇒ [`DomainError::Unauthenticated`]。
///
/// **v3 请走 [`parse_v3_trap`]**：本入口没有 USM 上下文（用户名/口令/时限状态），
/// 因此对 v3 报文**显式报未实现**而不是静默按 v2c 解析。
///
/// # Errors
/// BER 非法、版本不支持（v3）、community 不匹配、PDU 不是 Trap。
pub fn parse_trap(bytes: &[u8], expected_community: Option<&str>) -> DomainResult<SnmpTrap> {
    parse_message(bytes, expected_community, None)
}

/// 解析 v1 / v2c 报文体（`message` 为顶层 SEQUENCE 的内容）。
fn parse_v1_v2c_body(message: &[u8], expected_community: Option<&str>) -> DomainResult<SnmpTrap> {
    let mut message_reader = ber::Reader::new(message);
    let version_number = message_reader.read_integer()?;
    let version = match version_number {
        0 => "v1",
        1 => "v2c",
        3 => {
            return Err(DomainError::NotImplemented(
                "SNMP v3 报文需要 USM 上下文：请用 parse_v3_trap/parse_message 并配置 AGF_INGEST_SNMP_V3_*".to_string(),
            ));
        }
        other => {
            return Err(DomainError::Parse(format!("SNMP 版本号 {other} 未知")));
        }
    };
    let community = ber::render_bytes(&message_reader.read_octet_string()?);
    if let Some(expected) = expected_community.filter(|e| !e.is_empty()) {
        if !constant_time_eq(expected.as_bytes(), community.as_bytes()) {
            return Err(DomainError::Unauthenticated(format!("SNMP community 不匹配（来源 {community} 被拒绝）")));
        }
    }
    let (pdu_tag, pdu) = message_reader.read_tlv()?;
    let mut trap = SnmpTrap {
        version: version.to_string(),
        community,
        user: None,
        security_level: None,
        engine_id: None,
        pdu_type: "trap".to_string(),
        request_id: None,
        enterprise: None,
        agent_address: None,
        generic_trap: None,
        specific_trap: None,
        varbinds: Vec::new(),
        source: String::new(),
    };
    apply_pdu(&mut trap, pdu_tag, pdu)?;
    Ok(trap)
}

/// 解析 SNMP v3 Trap（`noAuthNoPriv` / `authNoPriv`）。
///
/// 便利入口：内部新建一次性的时限状态与统计（**不跨报文保持时限**），
/// 长跑接收器请用 [`parse_v3_message`] 并复用同一份 [`EngineClock`] / [`UsmStats`]。
///
/// # Errors
/// 结构非法、安全级别不支持（`authPriv`）、用户名不匹配、摘要错误、超时限窗口、PDU 不是 Trap。
pub fn parse_v3_trap(bytes: &[u8], config: &UsmConfig) -> DomainResult<SnmpTrap> {
    parse_v3_message(bytes, config, &EngineClock::new(), &UsmStats::new())
}

/// 解析 SNMP v3 报文（带时限状态与统计；**接收器长跑用这个**）。
///
/// # Errors
/// 同 [`parse_v3_trap`]。
pub fn parse_v3_message(
    bytes: &[u8],
    config: &UsmConfig,
    clock: &EngineClock,
    stats: &UsmStats,
) -> DomainResult<SnmpTrap> {
    let mut reader = ber::Reader::new(bytes);
    let (tag, message, message_offset) = reader.read_tlv_at()?;
    if tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse(format!("SNMP 报文顶层必须是 SEQUENCE，实际 0x{tag:02x}")));
    }
    if !reader.eof() {
        return Err(DomainError::Parse(format!("SNMP 报文尾随 {} 字节未消费", reader.remaining())));
    }
    let mut message_reader = ber::Reader::with_base(message, message_offset);
    if message_reader.read_integer()? != 3 {
        return Err(DomainError::Parse("parse_v3_message 只接受 SNMP v3 报文".to_string()));
    }
    v3_body(&mut message_reader, bytes, config, clock, stats)
}

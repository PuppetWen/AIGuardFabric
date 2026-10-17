//! 最小 BER（ASN.1 DER 子集）编解码：只覆盖 SNMP 报文用到的类型（TLV 常量与 `ber::Reader`）。

// ---------------------------------------------------------------------------
// BER / ASN.1
// ---------------------------------------------------------------------------

use agf_core::error::{DomainError, DomainResult};

/// `INTEGER`。
pub const TAG_INTEGER: u8 = 0x02;
/// `OCTET STRING`。
pub const TAG_OCTET_STRING: u8 = 0x04;
/// `NULL`。
pub const TAG_NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`。
pub const TAG_OID: u8 = 0x06;
/// `SEQUENCE`（构造类型）。
pub const TAG_SEQUENCE: u8 = 0x30;
/// `IpAddress`（`[APPLICATION 0]`）。
pub const TAG_IP_ADDRESS: u8 = 0x40;
/// `Counter32`（`[APPLICATION 1]`）。
pub const TAG_COUNTER32: u8 = 0x41;
/// `Gauge32` / `Unsigned32`（`[APPLICATION 2]`）。
pub const TAG_GAUGE32: u8 = 0x42;
/// `TimeTicks`（`[APPLICATION 3]`）。
pub const TAG_TIMETICKS: u8 = 0x43;
/// `Opaque`（`[APPLICATION 4]`）。
pub const TAG_OPAQUE: u8 = 0x44;
/// `Counter64`（`[APPLICATION 6]`）。
pub const TAG_COUNTER64: u8 = 0x45;
/// `NsapAddress`（`[APPLICATION 5]`）。
pub const TAG_NSAP: u8 = 0x46;
/// `SNMPv2-Trap-PDU`（`[7]` 构造，IMPLICIT）。
pub const TAG_TRAP_V2: u8 = 0xa7;
/// `Trap-PDU`（v1，`[4]` 构造，IMPLICIT）。
pub const TAG_TRAP_V1: u8 = 0xa4;
/// `InformRequest-PDU`（`[6]` 构造）。
pub const TAG_INFORM: u8 = 0xa6;
/// `GetRequest-PDU`（`[0]` 构造）——只用于在错误信息里指名道姓。
pub const TAG_GET_REQUEST: u8 = 0xa0;
/// `Report-PDU`（`[8]` 构造，RFC3412/3414：USM 用它回usmStats）。
pub const TAG_REPORT: u8 = 0xa8;

/// BER 读取器（游标式；**只接受定长编码**，不定长 `0x80` 直接拒绝）。
///
/// `base` 记录本读取器所读切片在**原始报文**中的绝对起始偏移：USM 校验要在整报文上
/// 重算 HMAC，必须能定位 `msgAuthenticationParameters` 的绝对位置（见 [`super::AuthProtocol`]）。
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    /// 构造（绝对偏移从 0 起）。
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, base: 0 }
    }

    /// 构造并把本切片的绝对起始偏移设为 `base`。
    #[must_use]
    pub const fn with_base(buf: &'a [u8], base: usize) -> Self {
        Self { buf, pos: 0, base }
    }

    /// 本读取器覆盖的切片在原始报文中的绝对起始偏移。
    #[must_use]
    pub const fn base(&self) -> usize {
        self.base
    }

    /// 是否已读完。
    #[must_use]
    pub const fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// 剩余字节数。
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// 读一个 TLV，返回 `(tag, value 切片)`。
    ///
    /// # Errors
    /// 越界、不定长编码或长度域非法。
    pub fn read_tlv(&mut self) -> DomainResult<(u8, &'a [u8])> {
        let (tag, value, _offset) = self.read_tlv_at()?;
        Ok((tag, value))
    }

    /// 读一个 TLV，并返回 value 在**原始报文**中的绝对偏移（USM 重算 HMAC 必需）。
    ///
    /// # Errors
    /// 越界、不定长编码或长度域非法。
    pub fn read_tlv_at(&mut self) -> DomainResult<(u8, &'a [u8], usize)> {
        let Some(tag) = self.buf.get(self.pos).copied() else {
            return Err(DomainError::Parse("SNMP BER 报文提前结束（缺 tag）".to_string()));
        };
        self.pos += 1;
        let length = self.read_length()?;
        let start = self.pos;
        let end = self.pos.saturating_add(length);
        if end > self.buf.len() {
            return Err(DomainError::Parse(format!("SNMP BER 长度 {length} 越界（剩余 {}）", self.remaining())));
        }
        let value = self.buf.get(start..end).unwrap_or_default();
        self.pos = end;
        Ok((tag, value, self.base.saturating_add(start)))
    }

    /// 读长度域（只支持定长）。
    ///
    /// # Errors
    /// 不定长（`0x80`）或长度域超长。
    fn read_length(&mut self) -> DomainResult<usize> {
        let Some(first) = self.buf.get(self.pos).copied() else {
            return Err(DomainError::Parse("SNMP BER 报文提前结束（缺长度）".to_string()));
        };
        self.pos += 1;
        if first & 0x80 == 0 {
            return Ok(usize::from(first));
        }
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(DomainError::Parse("SNMP BER 不定长编码不受支持".to_string()));
        }
        if count > 4 {
            return Err(DomainError::Parse(format!("SNMP BER 长度域 {count} 字节过长")));
        }
        let mut length = 0_usize;
        for _ in 0..count {
            let Some(byte) = self.buf.get(self.pos).copied() else {
                return Err(DomainError::Parse("SNMP BER 长度域越界".to_string()));
            };
            self.pos += 1;
            length = (length << 8) | usize::from(byte);
        }
        Ok(length)
    }

    /// 读有符号整数（二补码，支持任意长度）。
    ///
    /// # Errors
    /// TLV 非法或 tag 不是 `INTEGER`。
    pub fn read_integer(&mut self) -> DomainResult<i64> {
        let (tag, value) = self.read_tlv()?;
        if tag != TAG_INTEGER {
            return Err(DomainError::Parse(format!("SNMP 期望 INTEGER，实际 tag 0x{tag:02x}")));
        }
        Ok(decode_integer(value))
    }

    /// 读 `OCTET STRING` 原始字节。
    ///
    /// # Errors
    /// TLV 非法或 tag 不匹配。
    pub fn read_octet_string(&mut self) -> DomainResult<Vec<u8>> {
        let (tag, value) = self.read_tlv()?;
        if tag != TAG_OCTET_STRING {
            return Err(DomainError::Parse(format!("SNMP 期望 OCTET STRING，实际 tag 0x{tag:02x}")));
        }
        Ok(value.to_vec())
    }

    /// 读 `OBJECT IDENTIFIER` 文本（点分十进制）。
    ///
    /// # Errors
    /// TLV 非法或 OID 编码非法。
    pub fn read_oid(&mut self) -> DomainResult<String> {
        let (tag, value) = self.read_tlv()?;
        if tag != TAG_OID {
            return Err(DomainError::Parse(format!("SNMP 期望 OID，实际 tag 0x{tag:02x}")));
        }
        decode_oid(value)
    }
}

/// 解码 `INTEGER` 内容（大端二补码）。
#[must_use]
pub fn decode_integer(value: &[u8]) -> i64 {
    if value.is_empty() {
        return 0;
    }
    let negative = value.first().is_some_and(|b| b & 0x80 != 0);
    let mut raw_value = 0_i64;
    for byte in value {
        raw_value = (raw_value << 8) | i64::from(*byte);
    }
    if negative && value.len() < 8 {
        let shift = 8 * i32::try_from(value.len()).unwrap_or(8);
        raw_value -= 1_i64 << shift;
    }
    raw_value
}

/// 解码 `OCTET STRING` 形式的无符号整数（`Counter32`/`Gauge32`/`TimeTicks`/`Counter64`）。
#[must_use]
pub fn decode_unsigned(value: &[u8]) -> u64 {
    value.iter().fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

/// 解码 OID（首字节 = 40*X + Y，其余为 base-128 变长）。
///
/// # Errors
/// 空编码或变长段缺少结束位。
pub fn decode_oid(value: &[u8]) -> DomainResult<String> {
    let Some(first) = value.first().copied() else {
        return Err(DomainError::Parse("SNMP OID 编码为空".to_string()));
    };
    // 首字节 = 40*X + Y，X 上限为 2（2.40 及以后用首字节 >= 0x80 表示）
    let first_arc = u64::from(first / 40).min(2);
    let mut parts = vec![first_arc, u64::from(first) - 40 * first_arc];
    let mut acc = 0_u64;
    let mut pending = false;
    for byte in value.iter().skip(1) {
        acc = (acc << 7) | u64::from(byte & 0x7f);
        pending = byte & 0x80 != 0;
        if !pending {
            parts.push(acc);
            acc = 0;
        }
    }
    if pending {
        return Err(DomainError::Parse("SNMP OID 变长段缺少结束位".to_string()));
    }
    Ok(parts.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

/// `TimeTicks`（百分之一秒）渲染为 `N days, HH:MM:SS.cc`（net-snmp 风格）。
#[must_use]
pub fn format_timeticks(ticks: u64) -> String {
    let hundredths = ticks % 100;
    let total_secs = ticks / 100;
    let days = total_secs / 86_400;
    let hours = (total_secs % 86_400) / 3_600;
    let minutes = (total_secs % 3_600) / 60;
    let seconds = total_secs % 60;
    let day_label = if days == 1 { "day" } else { "days" };
    format!("{days} {day_label}, {hours:02}:{minutes:02}:{seconds:02}.{hundredths:02}")
}

/// 字节串渲染：可打印 ASCII 直接用，否则 hex（避免把二进制塞进事件正文）。
#[must_use]
pub fn render_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let printable = !bytes.is_empty() && bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\t');
    if printable {
        String::from_utf8_lossy(bytes).to_string()
    } else {
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

//! 采集器上行的**客户端证书解析**：头部来源、PEM/DER 解码、subject/SAN 提取与 SHA-256 指纹。
//!
//! ## 证书从哪里来
//!
//! `agf-server` 自身**不终结 TLS**（与既有部署口径一致：TLS/mTLS 由入口网关承担，
//! 见 `docs/deployment.md`）。网关校验客户端证书后把证书透传给应用，本模块消费两种头部：
//!
//! | 头部 | 含义 | 谁写入 |
//! |---|---|---|
//! | `X-SSL-Client-Verify` | `SUCCESS` = 网关已校验通过 | 入口网关（nginx/Envoy 标准约定） |
//! | `X-SSL-Client-Cert` | 客户端证书 **PEM**（可 percent-encoded） | 入口网关 |
//! | `X-AGF-Client-Cert-Der` | 客户端证书 **DER** 的 base64 | 本仓库自带的 `agf-mtls-terminator` |
//!
//! **这些头部本身不可信**：只应在"应用只接受来自网关的流量"的网络拓扑下启用，因此默认
//! 关闭，必须显式打开（[`super::ENV_TRUST_PROXY`]）。
//!
//! ## 与主体映射的分工
//!
//! 本模块**只做解析**（把字节变成 [`CertInfo`]），"证书主体 → 角色/租户"的授权决策在
//! [`super`]（`PrincipalMap` + 既有 RBAC）。解析与授权分开，是为了让"证书说了什么"与
//! "我们因此允许什么"各自可测、可审计。

use std::collections::BTreeMap;

use agf_core::error::DomainError;

use crate::error::{ApiError, ApiResult};

use super::{CertInfo, HEADER_CLIENT_CERT, HEADER_CLIENT_CERT_DER, HEADER_CLIENT_VERIFY};

/// 从请求头取证书（**仅在 `AGF_AGENT_MTLS_TRUST_PROXY=1` 时才有调用方**）。
///
/// 支持两种形态：PEM（`X-SSL-Client-Cert`，nginx 约定）与 base64 DER（`X-AGF-Client-Cert-Der`，
/// 本仓库自带的 terminator）。两者都要求 `X-SSL-Client-Verify: SUCCESS`。
///
/// # Errors
/// - 头部存在但网关未标记校验通过（`X-SSL-Client-Verify` ≠ `SUCCESS`）⇒ 401；
/// - PEM/percent-encoding/base64 非法、证书为空或 DER 无法解析 ⇒ 401。
pub fn cert_from_headers(headers: &axum::http::HeaderMap) -> ApiResult<Option<CertInfo>> {
    let pem = headers.get(HEADER_CLIENT_CERT);
    let der = headers.get(HEADER_CLIENT_CERT_DER);
    if pem.is_none() && der.is_none() {
        return Ok(None);
    }
    let verify = headers.get(HEADER_CLIENT_VERIFY).and_then(|v| v.to_str().ok()).unwrap_or_default();
    if !verify.trim().eq_ignore_ascii_case("SUCCESS") {
        return Err(ApiError::new(DomainError::Unauthenticated(format!(
            "网关未标记客户端证书校验通过（{HEADER_CLIENT_VERIFY}={verify:?}）：拒绝按证书身份信任该请求"
        ))));
    }
    if let Some(raw) = pem {
        let raw = raw
            .to_str()
            .map_err(|_| ApiError::new(DomainError::Unauthenticated(format!("{HEADER_CLIENT_CERT} 非 ASCII"))))?;
        return Ok(Some(parse_client_cert_pem(raw)?));
    }
    let raw = der
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::new(DomainError::Unauthenticated(format!("{HEADER_CLIENT_CERT_DER} 非 ASCII"))))?;
    Ok(Some(parse_client_cert_der_b64(raw)?))
}

/// 解析 base64 DER 客户端证书。
///
/// # Errors
/// base64 非法或 DER 结构非法。
pub fn parse_client_cert_der_b64(raw: &str) -> ApiResult<CertInfo> {
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| ApiError::new(DomainError::Unauthenticated(format!("客户端证书 base64 非法: {e}"))))?;
    if der.is_empty() {
        return Err(ApiError::new(DomainError::Unauthenticated("客户端证书为空（0 字节）".to_string())));
    }
    parse_client_cert_der(&der)
}

/// 解析 percent-encoded PEM 客户端证书。
///
/// # Errors
/// percent-encoding 非法、PEM 中没有证书或 DER 结构非法。
pub fn parse_client_cert_pem(raw: &str) -> ApiResult<CertInfo> {
    let decoded = percent_decode(raw)?;
    let der = pem_to_der(&decoded)
        .ok_or_else(|| ApiError::new(DomainError::Unauthenticated("客户端证书头部里没有 PEM 证书块".to_string())))?;
    parse_client_cert_der(&der)
}

/// 解析 DER 客户端证书（subject / SAN / 指纹）。
///
/// # Errors
/// DER 结构非法（不是 SEQUENCE / 缺少 subject / 长度越界）。
pub fn parse_client_cert_der(der: &[u8]) -> ApiResult<CertInfo> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let content = der_content(der, 0x30)
        .ok_or_else(|| ApiError::new(DomainError::Unauthenticated("客户端证书 DER 不是 SEQUENCE".to_string())))?;
    let tbs = der_content(content, 0x30)
        .ok_or_else(|| ApiError::new(DomainError::Unauthenticated("客户端证书缺少 tbsCertificate".to_string())))?;
    let mut offset = 0;
    // 可选 [0] version
    offset += der_total_len(tbs, offset, 0xa0);
    // serialNumber (INTEGER)
    offset += der_total_len(tbs, offset, 0x02);
    // signature AlgorithmIdentifier (SEQUENCE)
    offset += der_total_len(tbs, offset, 0x30);
    // issuer Name (SEQUENCE) —— 跳过
    offset += der_total_len(tbs, offset, 0x30);
    // validity (SEQUENCE) —— 跳过
    offset += der_total_len(tbs, offset, 0x30);
    // subject Name (SEQUENCE)
    let rest = tbs.get(offset..).unwrap_or_default();
    let subject_der = der_content(rest, 0x30)
        .ok_or_else(|| ApiError::new(DomainError::Unauthenticated("客户端证书缺少 subject".to_string())))?;
    let rdn = parse_name(subject_der);
    let san = parse_extensions(tbs).get("san").cloned().unwrap_or_default();
    let fingerprint = sha256_hex(der);
    let subject = format_subject(&rdn);
    let identity = if subject.is_empty() { format!("sha256:{fingerprint}") } else { subject.clone() };
    Ok(CertInfo {
        subject,
        common_name: rdn.get("CN").and_then(|v| v.first().cloned()),
        organization: rdn.get("O").and_then(|v| v.first().cloned()),
        organizational_units: rdn.get("OU").cloned().unwrap_or_default(),
        san,
        fingerprint_sha256: fingerprint,
        identity,
    })
}

/// X.500 主体属性（**后者同名属性追加**，不覆盖）。
type NameAttributes = BTreeMap<String, Vec<String>>;

/// 解析 X.501 `Name`（`SEQUENCE OF RelativeDistinguishedName`）。
fn parse_name(der: &[u8]) -> NameAttributes {
    let mut attributes: NameAttributes = BTreeMap::new();
    let mut offset = 0;
    while let Some(rdn) = der_content(&der[offset..], 0x31) {
        let mut inner = 0;
        while let Some(pair) = der_content(&rdn[inner..], 0x30) {
            // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
            if let Some(oid) = der_content(pair, 0x06) {
                let value_offset = der_total_len(pair, 0, 0x06);
                if let Some((_, value)) = der_any(&pair[value_offset.min(pair.len())..]) {
                    if let Some(name) = oid_name(oid) {
                        attributes
                            .entry(name.to_string())
                            .or_default()
                            .push(String::from_utf8_lossy(value).to_string());
                    }
                }
            }
            let step = der_total_len(&rdn[inner..], 0, 0x30);
            if step == 0 {
                break;
            }
            inner += step;
        }
        let step = der_total_len(&der[offset..], 0, 0x31);
        if step == 0 {
            break;
        }
        offset += step;
    }
    attributes
}

/// 只解析出我们关心的扩展：SAN（OID `2.5.29.17`）。
fn parse_extensions(tbs: &[u8]) -> BTreeMap<&'static str, Vec<String>> {
    let mut out: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut offset = 0;
    // tbs 里 extensions 是最后一个可选 [3] 元素；逐个 TLV 走过去找它
    while offset < tbs.len() {
        let Some((tag, content)) = der_any(&tbs[offset..]) else { break };
        if tag == 0xa3 {
            // [3] { SEQUENCE OF Extension }
            if let Some(list) = der_content(content, 0x30) {
                let mut inner = 0;
                while let Some(extension) = der_content(&list[inner..], 0x30) {
                    if let Some(oid) = der_content(extension, 0x06) {
                        let value_offset = der_total_len(extension, 0, 0x06);
                        if let Some(value) = der_content(&extension[value_offset.min(extension.len())..], 0x04) {
                            if oid == SAN_OID {
                                out.insert("san", parse_san(value));
                            }
                        }
                    }
                    let step = der_total_len(&list[inner..], 0, 0x30);
                    if step == 0 {
                        break;
                    }
                    inner += step;
                }
            }
        }
        let step = der_total_len(&tbs[offset..], 0, tag);
        if step == 0 {
            break;
        }
        offset += step;
    }
    out
}

/// `2.5.29.17` = subjectAltName。
const SAN_OID: &[u8] = &[0x55, 0x1d, 0x11];

/// 解析 SAN 扩展的值（`SEQUENCE OF GeneralName`）。
fn parse_san(value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(list) = der_content(value, 0x30) else { return out };
    let mut offset = 0;
    while let Some((tag, content)) = der_any(&list[offset..]) {
        let text = match tag {
            0x82 => Some(format!("DNS:{}", String::from_utf8_lossy(content))),
            0x81 => Some(format!("email:{}", String::from_utf8_lossy(content))),
            0x86 => Some(format!("URI:{}", String::from_utf8_lossy(content))),
            0x87 => Some(format!("IP:{}", format_ip(content))),
            _ => None,
        };
        if let Some(text) = text {
            out.push(text);
        }
        offset += der_total_len(&list[offset..], 0, tag);
    }
    out
}

/// 4/16 字节 IP → 点分/冒号形式（其他长度按 hex 保留）。
fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => bytes.chunks(2).map(|pair| format!("{:02x}{:02x}", pair[0], pair[1])).collect::<Vec<_>>().join(":"),
        _ => hex(bytes),
    }
}

/// 常用主体属性的 OID → 简称。
fn oid_name(oid: &[u8]) -> Option<&'static str> {
    match oid {
        [0x55, 0x04, 0x03] => Some("CN"),
        [0x55, 0x04, 0x0a] => Some("O"),
        [0x55, 0x04, 0x0b] => Some("OU"),
        [0x55, 0x04, 0x06] => Some("C"),
        [0x55, 0x04, 0x07] => Some("L"),
        [0x55, 0x04, 0x08] => Some("ST"),
        [0x55, 0x04, 0x05] => Some("serialNumber"),
        [0x55, 0x04, 0x04] => Some("SN"),
        [0x55, 0x04, 0x0c] => Some("ID"),
        _ => None,
    }
}

/// RFC 4514 顺序（`CN=...,OU=...,O=...`）——与 OpenSSL `-subject` 的常见顺序一致。
fn format_subject(attributes: &NameAttributes) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in ["CN", "OU", "O", "L", "ST", "C", "serialNumber", "SN", "ID"] {
        if let Some(values) = attributes.get(key) {
            for value in values {
                parts.push(format!("{key}={value}"));
            }
        }
    }
    parts.join(",")
}

/// 从 `der` 的**开头**读取一个 DER TLV：返回 `(tag, 内容, 完整字节)`。
///
/// 签名刻意是"整串 + 从 0 开始"：这样调用点写成 `der_tlv(&bytes[offset..])`，
/// 不会出现"把 tag 当 offset 传"的歧义（这个坑真的踩过一次）。
fn der_tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *der.first()?;
    let first = *der.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2_usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut value = 0_usize;
        for index in 0..count {
            value = (value << 8) | usize::from(*der.get(2 + index)?);
        }
        (value, 2 + count)
    };
    let end = header.checked_add(length)?;
    Some((tag, der.get(header..end)?, der.get(..end)?))
}

/// 读取一个 TLV，且**只接受指定 tag**（不匹配 ⇒ `None`）。
fn der_content(der: &[u8], expect_tag: u8) -> Option<&[u8]> {
    match der_tlv(der) {
        Some((tag, content, _)) if tag == expect_tag => Some(content),
        _ => None,
    }
}

/// 读取任意 TLV（不限定 tag）。
fn der_any(der: &[u8]) -> Option<(u8, &[u8])> {
    der_tlv(der).map(|(tag, content, _)| (tag, content))
}

/// 从 `der[offset..]` 跳过**一个指定 tag 的元素**，返回它的完整长度（不匹配 ⇒ 0）。
fn der_total_len(der: &[u8], offset: usize, expect_tag: u8) -> usize {
    match der_tlv(der.get(offset..).unwrap_or_default()) {
        Some((tag, _, full)) if tag == expect_tag => full.len(),
        _ => 0,
    }
}

/// PEM → DER（取**第一个** `CERTIFICATE` 块；前后可有其他文本）。
#[must_use]
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let rest = &pem[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = rest.find("-----END CERTIFICATE-----")?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&body)
}

/// 最小 base64 解码（`+` / `/`，可带 `=` 填充）。
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// percent-decoding（`%XX`；`+` **不**当作空格——证书 PEM 里没有它）。
fn percent_decode(raw: &str) -> ApiResult<String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| ApiError::new(DomainError::Validation("证书头部 percent-encoding 截断".to_string())))?;
            let text = std::str::from_utf8(hex)
                .map_err(|_| ApiError::new(DomainError::Validation("证书头部 percent-encoding 非法".to_string())))?;
            let value = u8::from_str_radix(text, 16)
                .map_err(|_| ApiError::new(DomainError::Validation("证书头部 percent-encoding 非法".to_string())))?;
            out.push(value);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

/// SHA-256 hex（小写）。
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

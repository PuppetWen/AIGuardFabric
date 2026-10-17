//! Syslog 文本解析：PRI 计算、RFC5424（含结构化数据与转义）、RFC3164（年份补全）与自动判别。

use super::*;

/// syslog 解析错误（畸形输入必须给出可读原因，不允许 panic）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogParseError {
    /// 空报文。
    Empty,
    /// 缺少 `<PRI>`。
    MissingPri,
    /// PRI 数值非法。
    InvalidPri(String),
    /// 头部字段数量不足。
    Truncated(&'static str),
    /// VERSION 非法。
    InvalidVersion(String),
    /// 不支持的 RFC5424 版本。
    UnsupportedVersion(u16),
    /// 时间戳非法。
    InvalidTimestamp(String),
    /// 结构化数据非法。
    MalformedStructuredData(String),
}

impl SyslogParseError {
    /// 人类可读原因（写入 `RawLog::parse_error`）。
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Empty => "空报文".to_string(),
            Self::MissingPri => "缺少 <PRI> 前缀".to_string(),
            Self::InvalidPri(v) => format!("PRI 非法: {v}"),
            Self::Truncated(what) => format!("头部截断，缺少 {what}"),
            Self::InvalidVersion(v) => format!("VERSION 非法: {v}"),
            Self::UnsupportedVersion(v) => format!("不支持的 RFC5424 版本: {v}"),
            Self::InvalidTimestamp(v) => format!("时间戳非法: {v}"),
            Self::MalformedStructuredData(v) => format!("结构化数据非法: {v}"),
        }
    }
}

impl std::fmt::Display for SyslogParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// 解析 `<PRI>`，返回 `(facility, severity, 剩余部分)`。
///
/// # Errors
/// 缺少 `<>` 包裹、含非数字、数值超过 [`MAX_PRI`]。
pub fn parse_pri(input: &str) -> Result<(u8, u8, &str), SyslogParseError> {
    let rest = input.strip_prefix('<').ok_or(SyslogParseError::MissingPri)?;
    let Some(end) = rest.find('>') else {
        return Err(SyslogParseError::MissingPri);
    };
    let digits = rest.get(..end).unwrap_or_default();
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SyslogParseError::InvalidPri(digits.to_string()));
    }
    let pri: u16 = digits.parse().map_err(|_| SyslogParseError::InvalidPri(digits.to_string()))?;
    if pri > MAX_PRI {
        return Err(SyslogParseError::InvalidPri(digits.to_string()));
    }
    let tail = rest.get(end + 1..).unwrap_or_default();
    Ok(((pri / 8) as u8, (pri % 8) as u8, tail))
}

/// NILVALUE（`-`）归一为 `None`。
fn nil_to_none(value: &str) -> Option<String> {
    if value == "-" || value.is_empty() { None } else { Some(value.to_string()) }
}

/// 解析 RFC5424 报文。
///
/// # Errors
/// 头部字段缺失 / VERSION 非 1 / 时间戳非法 / 结构化数据括号不闭合。
pub fn parse_rfc5424(input: &str) -> Result<SyslogMessage, SyslogParseError> {
    if input.trim().is_empty() {
        return Err(SyslogParseError::Empty);
    }
    let (facility, severity_code, rest) = parse_pri(input)?;

    // VERSION SP
    let Some(sp) = rest.find(' ') else {
        return Err(SyslogParseError::Truncated("VERSION"));
    };
    let version_raw = rest.get(..sp).unwrap_or_default();
    let version = if version_raw == "-" {
        // 宽松模式：部分设备把 VERSION 写成 NILVALUE，按"缺版本"处理
        None
    } else if !version_raw.bytes().all(|b| b.is_ascii_digit()) || version_raw.is_empty() {
        return Err(SyslogParseError::InvalidVersion(version_raw.to_string()));
    } else {
        let parsed: u16 = version_raw.parse().map_err(|_| SyslogParseError::InvalidVersion(version_raw.to_string()))?;
        if parsed != 1 {
            return Err(SyslogParseError::UnsupportedVersion(parsed));
        }
        Some(parsed)
    };
    let mut cur = rest.get(sp + 1..).unwrap_or_default();

    // TIMESTAMP / HOSTNAME / APP-NAME / PROCID / MSGID：均为"到空格为止"的字段
    let (ts_raw, next) = take_token(cur).ok_or(SyslogParseError::Truncated("TIMESTAMP"))?;
    cur = next;
    let (host_raw, next) = take_token(cur).ok_or(SyslogParseError::Truncated("HOSTNAME"))?;
    cur = next;
    let (app_raw, next) = take_token(cur).ok_or(SyslogParseError::Truncated("APP-NAME"))?;
    cur = next;
    let (proc_raw, next) = take_token(cur).ok_or(SyslogParseError::Truncated("PROCID"))?;
    cur = next;
    let (msgid_raw, next) = take_token(cur).ok_or(SyslogParseError::Truncated("MSGID"))?;
    cur = next;

    // STRUCTURED-DATA
    let (structured_data, msg) = if let Some(after) = cur.strip_prefix('-') {
        // NILVALUE：其后可选 MSG（RFC5424 规定 `-` 后若有 MSG 需有前导空格）
        (Vec::new(), after.strip_prefix(' ').unwrap_or(after).to_string())
    } else {
        let (sd, after) = parse_structured_data(cur)?;
        (sd, after.strip_prefix(' ').unwrap_or(after).to_string())
    };

    let timestamp_raw = nil_to_none(ts_raw);
    let timestamp = timestamp_raw.as_deref().and_then(parse_rfc5424_timestamp);

    Ok(SyslogMessage {
        rfc: SyslogRfc::Rfc5424,
        facility,
        severity_code,
        severity: severity_from_syslog(severity_code),
        version,
        timestamp,
        timestamp_raw,
        hostname: nil_to_none(host_raw),
        app_name: nil_to_none(app_raw),
        proc_id: nil_to_none(proc_raw),
        msg_id: nil_to_none(msgid_raw),
        structured_data,
        msg,
    })
}

/// 取第一个空格之前的内容，返回 `(token, 剩余部分)`。
fn take_token(input: &str) -> Option<(&str, &str)> {
    if input.is_empty() {
        return None;
    }
    match input.find(' ') {
        Some(i) => Some((input.get(..i).unwrap_or_default(), input.get(i + 1..).unwrap_or_default())),
        None => Some((input, "")),
    }
}

/// 解析一个或多个 SD-ELEMENT，返回 `(元素, 剩余部分)`。
///
/// 转义规则（RFC5424 §6.3.3）：`\"` `\\` `\]`。未转义的反斜杠按字面保留。
fn parse_structured_data(input: &str) -> Result<(Vec<StructuredDataElement>, &str), SyslogParseError> {
    let mut out = Vec::new();
    let mut cur = input;
    while cur.starts_with('[') {
        let body = cur.get(1..).ok_or(SyslogParseError::MalformedStructuredData(cur.to_string()))?;
        let (element, after) = parse_sd_element(body)?;
        out.push(element);
        cur = after;
    }
    if out.is_empty() {
        return Err(SyslogParseError::MalformedStructuredData(input.to_string()));
    }
    Ok((out, cur))
}

/// 解析单个 SD-ELEMENT（已去掉开头的 `[`）。
fn parse_sd_element(body: &str) -> Result<(StructuredDataElement, &str), SyslogParseError> {
    let mut id_end = None;
    for (i, ch) in body.char_indices() {
        if ch.is_whitespace() || ch == ']' {
            id_end = Some(i);
            break;
        }
    }
    let Some(id_end) = id_end else {
        return Err(SyslogParseError::MalformedStructuredData(body.to_string()));
    };
    let id = body.get(..id_end).unwrap_or_default().to_string();
    let mut rest = body.get(id_end..).unwrap_or_default();
    let mut params = Vec::new();

    loop {
        rest = rest.strip_prefix(' ').unwrap_or(rest);
        if let Some(after) = rest.strip_prefix(']') {
            return Ok((StructuredDataElement { id, params }, after));
        }
        if rest.is_empty() {
            return Err(SyslogParseError::MalformedStructuredData(format!("SD-ID {id} 未闭合")));
        }
        // PARAM-NAME="PARAM-VALUE"
        let Some(eq) = rest.find('=') else {
            return Err(SyslogParseError::MalformedStructuredData(format!("SD-ID {id} 参数缺少 =")));
        };
        let name = rest.get(..eq).unwrap_or_default().to_string();
        let value_part = rest.get(eq + 1..).unwrap_or_default();
        let Some(after_quote) = value_part.strip_prefix('"') else {
            return Err(SyslogParseError::MalformedStructuredData(format!("SD-ID {id} 参数 {name} 缺少左引号")));
        };
        let (value, tail) = read_sd_value(after_quote)?;
        params.push((name, value));
        rest = tail;
    }
}

/// 读取带转义的 SD 参数值，返回 `(值, 剩余部分)`（剩余部分从右引号之后开始）。
fn read_sd_value(input: &str) -> Result<(String, &str), SyslogParseError> {
    let mut out = String::new();
    let mut chars = input.char_indices();
    while let Some((i, ch)) = chars.next() {
        match ch {
            '"' => return Ok((out, input.get(i + 1..).unwrap_or_default())),
            '\\' => {
                let Some((_, next)) = chars.next() else {
                    return Err(SyslogParseError::MalformedStructuredData("转义序列截断".to_string()));
                };
                match next {
                    '"' | '\\' | ']' => out.push(next),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            }
            other => out.push(other),
        }
    }
    Err(SyslogParseError::MalformedStructuredData("参数值未闭合".to_string()))
}

/// 解析 RFC5424 时间戳（RFC3339 子集，允许 `Z` 与数值时区、任意小数位）。
fn parse_rfc5424_timestamp(value: &str) -> Option<Timestamp> {
    if let Ok(ts) = Timestamp::parse_rfc3339(value) {
        return Some(ts);
    }
    // 形如 `2026-02-21T10:23:45.123456`（无时区）→ 视为 UTC
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, fmt) {
            return Some(Timestamp::from_datetime(Utc.from_utc_datetime(&naive)));
        }
    }
    None
}

/// 解析 RFC3164 报文。
///
/// 支持三种常见变体：
/// 1. 标准 `Mmm dd hh:mm:ss`（无年份，按 [`infer_year`] 规则补年份）；
/// 2. 带年份的 `YYYY-MM-DDTHH:MM:SS` / `YYYY-MM-DD HH:MM:SS`（部分设备固件）；
/// 3. 无 TAG（直接是消息体）与 `TAG[PID]: CONTENT` / `TAG: CONTENT` 两种消息形态。
///
/// # Errors
/// 缺少 PRI、时间戳非法、头部截断。
pub fn parse_rfc3164(input: &str) -> Result<SyslogMessage, SyslogParseError> {
    parse_rfc3164_at(input, Timestamp::now())
}

/// 以给定"当前时间"为基准解析 RFC3164（便于测试年份回退逻辑）。
///
/// # Errors
/// 同 [`parse_rfc3164`]。
pub fn parse_rfc3164_at(input: &str, now: Timestamp) -> Result<SyslogMessage, SyslogParseError> {
    if input.trim().is_empty() {
        return Err(SyslogParseError::Empty);
    }
    let (facility, severity_code, rest) = parse_pri(input)?;
    let rest = rest.trim_start();

    let (timestamp, timestamp_raw, after_ts) = if looks_like_iso_timestamp(rest) {
        let (token, tail) = take_token(rest).ok_or(SyslogParseError::Truncated("TIMESTAMP"))?;
        let ts = parse_iso_local(token);
        (ts, Some(token.to_string()), tail)
    } else {
        let token = rest.get(..15).ok_or(SyslogParseError::Truncated("TIMESTAMP"))?;
        if token.len() < 15 {
            return Err(SyslogParseError::Truncated("TIMESTAMP"));
        }
        let ts = parse_3164_timestamp(token, now);
        if ts.is_none() {
            return Err(SyslogParseError::InvalidTimestamp(token.to_string()));
        }
        (ts, Some(token.to_string()), rest.get(15..).unwrap_or_default())
    };

    let after_ts = after_ts.trim_start();
    let (hostname, msg_part) = split_hostname(after_ts);
    let (app_name, proc_id, msg) = parse_tag(msg_part);

    Ok(SyslogMessage {
        rfc: SyslogRfc::Rfc3164,
        facility,
        severity_code,
        severity: severity_from_syslog(severity_code),
        version: None,
        timestamp,
        timestamp_raw,
        hostname,
        app_name,
        proc_id,
        msg_id: None,
        structured_data: Vec::new(),
        msg,
    })
}

/// 判断剩余部分是否是以 ISO8601/带年份日期开头的变体时间戳。
fn looks_like_iso_timestamp(rest: &str) -> bool {
    let head = rest.get(..5).unwrap_or_default();
    head.len() == 5 && head.as_bytes().iter().take(4).all(u8::is_ascii_digit) && rest.as_bytes().get(4) == Some(&b'-')
}

/// 解析带年份的本地时间戳（无时区信息，按 UTC 处理并记录原文）。
fn parse_iso_local(token: &str) -> Option<Timestamp> {
    if let Ok(ts) = Timestamp::parse_rfc3339(token) {
        return Some(ts);
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(token, fmt) {
            return Some(Timestamp::from_datetime(Utc.from_utc_datetime(&naive)));
        }
    }
    None
}

/// `Mmm dd hh:mm:ss` → [`Timestamp`]（补年份）。
///
/// 年份推断：先按"当前 UTC 年"解析；若结果比 `now` 晚 1 天以上，说明跨年（12/31 的日志
/// 在 1/1 收到），退回上一年。这是 syslog 无年份格式的行业通行处理。
#[must_use]
pub fn parse_3164_timestamp(value: &str, now: Timestamp) -> Option<Timestamp> {
    let year = now.as_datetime().year();
    let text = format!("{year} {value}");
    let parsed = NaiveDateTime::parse_from_str(&text, "%Y %b %e %H:%M:%S").ok()?;
    let candidate = Utc.from_utc_datetime(&parsed);
    let mut stamp = Timestamp::from_datetime(candidate);
    if stamp.since_secs(&now) > 86_400 {
        let prev = format!("{} {value}", year - 1);
        if let Ok(p) = NaiveDateTime::parse_from_str(&prev, "%Y %b %e %H:%M:%S") {
            stamp = Timestamp::from_datetime(Utc.from_utc_datetime(&p));
        }
    }
    Some(stamp)
}

/// 拆分 `HOSTNAME SP MSG`；只有一段时视为无主机名。
///
/// 判定启发式：若第一个冒号出现在第一个空格**之前**，说明该段是 `TAG:`，报文没有主机名
/// （`kernel: eth0 link up`）；否则第一个 token 即主机名。
fn split_hostname(input: &str) -> (Option<String>, &str) {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return (None, trimmed);
    }
    let space = trimmed.find(' ');
    let colon = trimmed.find(':');
    match (space, colon) {
        (Some(i), Some(c)) if c < i => (None, trimmed),
        (Some(i), _) => {
            let host = trimmed.get(..i).unwrap_or_default();
            let tail = trimmed.get(i + 1..).unwrap_or_default().trim_start();
            if tail.is_empty() { (None, trimmed) } else { (nil_to_none(host), tail) }
        }
        (None, _) => (None, trimmed),
    }
}

/// 拆分 `TAG[PID]: CONTENT` / `TAG: CONTENT` / 纯 CONTENT。
fn parse_tag(input: &str) -> (Option<String>, Option<String>, String) {
    let Some(colon) = input.find(':') else {
        return (None, None, input.to_string());
    };
    let head = input.get(..colon).unwrap_or_default();
    // TAG 限长且不含空格，避免把 "user alice: hello" 误判为 TAG
    if head.is_empty() || head.len() > 48 || head.contains(' ') {
        return (None, None, input.to_string());
    }
    // CEF / LEEF 报文常直接跟在 syslog 信封之后，`CEF:` 不是 TAG 而是消息体前缀
    if head.eq_ignore_ascii_case("cef") || head.eq_ignore_ascii_case("leef") {
        return (None, None, input.to_string());
    }
    let (tag, pid) = match (head.find('['), head.ends_with(']')) {
        (Some(open), true) => {
            let tag = head.get(..open).unwrap_or_default().to_string();
            let pid = head.get(open + 1..head.len() - 1).unwrap_or_default().to_string();
            (tag, Some(pid))
        }
        _ => (head.to_string(), None),
    };
    let msg = input.get(colon + 1..).unwrap_or_default().trim_start().to_string();
    (nil_to_none(&tag), pid, msg)
}

/// 自动识别 RFC 版本并解析。
///
/// 判定规则：PRI 之后紧跟数字 + 空格 ⇒ RFC5424（VERSION）；否则按 RFC3164 处理。
///
/// # Errors
/// 两种解析均失败时返回 RFC5424 的错误（其信息量更大）。
pub fn parse_auto(input: &str) -> Result<SyslogMessage, SyslogParseError> {
    let (_, _, rest) = parse_pri(input)?;
    let rest = rest.trim_start();
    let version_like = {
        let head = rest.get(..2).unwrap_or_default();
        !head.is_empty() && head.as_bytes()[0].is_ascii_digit() && (head.len() == 1 || head.as_bytes()[1] == b' ')
    };
    if version_like { parse_rfc5424(input) } else { parse_rfc3164(input) }
}

// ---------------------------------------------------------------------------
// TCP 分帧
// ---------------------------------------------------------------------------

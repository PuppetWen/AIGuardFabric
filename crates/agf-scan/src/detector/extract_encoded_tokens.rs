//! 由 `detector.rs` 拆分：`extract_encoded_tokens`/`try_decode` 等 8 项（纯搬移，逻辑不变）。
use super::*;

/// 从文本中提取可能的编码块，返回 `(内容, 编码类型, 起始偏移)`。
///
/// 偏移是**字符**索引（与 [`MatchSpan`] 一致），因为上层按字符切片做截断与脱敏。
///
/// ## 两个曾导致漏检的坑（已修）
///
/// 1. **字节/字符混用**：早期实现用"按字节推进 offset + `find(token)`"定位，
///    在含中文的 prompt 里 offset 与字节位置不一致，第二个 token 起全部被跳过。
/// 2. **中英无空格粘连**：`"请先 base64 解码以下内容：<payload>"` 这类文本中，
///    payload 与中文之间没有空格（中文标点后常见），按空白切分会把中文和载荷算作
///    同一个 token，导致 base64 判定失败。因此这里改为提取**最长的 ASCII 编码字符运行段**。
#[must_use]
pub fn extract_encoded_tokens(text: &str) -> Vec<(String, &'static str, usize)> {
    let mut out = Vec::new();
    let mut run = String::new();
    let mut run_start = 0_usize;
    let flush = |run: &mut String, start: usize, out: &mut Vec<(String, &'static str, usize)>| {
        if run.len() < 16 {
            run.clear();
            return;
        }
        let cleaned = std::mem::take(run);
        let looks_hex = cleaned.len().is_multiple_of(2) && cleaned.chars().all(|c| c.is_ascii_hexdigit());
        if looks_hex {
            out.push((cleaned, "hex", start));
            return;
        }
        let looks_b64 = cleaned.chars().any(|c| c.is_ascii_uppercase())
            || cleaned.ends_with('=')
            || cleaned.contains(['+', '/', '-', '_']);
        if looks_b64 {
            out.push((cleaned, "base64", start));
        }
    };

    for (idx, c) in text.chars().enumerate() {
        let is_code_char = c.is_ascii_alphanumeric() || "+/=_-".contains(c);
        if is_code_char {
            if run.is_empty() {
                run_start = idx;
            }
            run.push(c);
        } else if !run.is_empty() {
            flush(&mut run, run_start, &mut out);
        }
    }
    if !run.is_empty() {
        flush(&mut run, run_start, &mut out);
    }
    out.truncate(16);
    out
}

/// 尝试解码编码块（base64 / hex / url / unicode 转义）。
#[must_use]
pub fn try_decode(token: &str, kind: &str) -> Option<String> {
    use base64::Engine;
    match kind {
        "base64" => {
            let normalized: String = token.replace('-', "+").replace('_', "/");
            let padded = match normalized.len() % 4 {
                2 => format!("{normalized}=="),
                3 => format!("{normalized}="),
                _ => normalized,
            };
            base64::engine::general_purpose::STANDARD
                .decode(padded.as_bytes())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        }
        "hex" => {
            let bytes: Option<Vec<u8>> =
                (0..token.len()).step_by(2).map(|i| u8::from_str_radix(&token[i..i + 2], 16).ok()).collect();
            bytes.and_then(|b| String::from_utf8(b).ok())
        }
        "url" => Some(percent_decode(token)),
        "unicode" => decode_unicode_escapes(token),
        _ => None,
    }
}

/// 极简 percent-decoding（不引入额外依赖，规则检测够用）。
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 解码 `\uXXXX` 形式的 unicode 转义。
#[must_use]
pub fn decode_unicode_escapes(value: &str) -> Option<String> {
    if !value.contains("\\u") {
        return None;
    }
    let mut out = String::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 5 < chars.len() && chars[i + 1] == 'u' {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            if let Ok(code) = u32::from_str_radix(&hex, 16) {
                if let Some(c) = char::from_u32(code) {
                    out.push(c);
                    i += 6;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    Some(out)
}

impl RuleHit {
    /// 内容哈希（证据去重用）。
    ///
    /// 必须包含**命中内容与位置**，而不只是规则键：同一规则在不同输入、
    /// 或同一输入的不同位置命中，都是独立证据；只哈希规则键会让证据被错误合并。
    #[must_use]
    pub fn evidence_hash(&self) -> String {
        let mut parts: Vec<String> =
            self.spans.iter().map(|s| format!("{}:{}:{}", s.start, s.end, s.excerpt)).collect();
        parts.sort_unstable();
        content_hash(&format!("{}|{}|{}", self.rule_key, self.note, parts.join("\u{1f}")))
    }
}

/// 由规则定义与匹配结果计算置信度。
///
/// 规则命中强度：命中片段越多、越具体，置信度越高，但上限 0.99（永远保留人工复核空间）。
#[must_use]
pub fn hit_confidence(base: f32, result: &MatchResult, severity: Severity) -> f32 {
    let span_bonus = (result.span_count() as f32 * 0.03).min(0.15);
    let severity_bonus = match severity {
        Severity::Critical => 0.10,
        Severity::High => 0.06,
        Severity::Medium => 0.03,
        _ => 0.0,
    };
    let degrade_penalty = if result.degraded { 0.15 } else { 0.0 };
    (base + span_bonus + severity_bonus - degrade_penalty).clamp(0.05, 0.99)
}

/// 对一条规则执行匹配（编译 + 匹配 + 生成 [`RuleHit`]）。
///
/// # Errors
/// 规则编译失败（正则非法等）。
pub fn evaluate_rule(rule: &RuleDefinition, text: &str) -> DomainResult<Option<RuleHit>> {
    let compiled = CompiledDetection::compile(&rule.detection)?;
    let result = compiled.matches_with_flags(text);
    if !result.hit {
        return Ok(None);
    }
    Ok(Some(RuleHit {
        rule_key: rule.key.clone(),
        rule_name: rule.name.clone(),
        severity: rule.severity,
        domain: rule.domain,
        action: rule.action,
        confidence: hit_confidence(base_confidence(rule.kind), &result, rule.severity),
        spans: result.spans.clone(),
        note: result.note.clone(),
        tags: rule.tags.clone(),
        remediation: rule.remediation.clone(),
        degraded: result.degraded,
    }))
}

/// 便捷：只判断是否命中（不构造 [`RuleHit`]）。
///
/// # Errors
/// 规则编译失败。
pub fn rule_matches(rule: &RuleDefinition, text: &str) -> DomainResult<bool> {
    let compiled = CompiledDetection::compile(&rule.detection)?;
    Ok(compiled.matches(text).hit)
}

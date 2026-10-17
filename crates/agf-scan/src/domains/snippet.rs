//! 由 `domains.rs` 拆分：`snippet` 等 9 个函数（纯搬移，逻辑不变）。
use super::*;

/// 生成脱敏的上下文片段（围绕命中词前后各 40 字符）。
#[must_use]
pub fn snippet(text: &str, needle: &str) -> String {
    let lower = text.to_lowercase();
    let Some(pos) = lower.find(&needle.to_lowercase()) else {
        let head: String = text.chars().take(60).collect();
        return crate::detector::safe_excerpt(&head, 0, head.chars().count());
    };
    // 用字符索引保证 UTF-8 边界安全
    let chars: Vec<char> = text.chars().collect();
    let char_pos = text[..pos].chars().count();
    let start = char_pos.saturating_sub(40);
    let end = (char_pos + needle.chars().count() + 40).min(chars.len());
    let slice: String = chars[start..end].iter().collect();
    crate::detector::safe_excerpt(&slice, 0, slice.chars().count())
}

/// 统计不可见/零宽字符数量。
#[must_use]
pub fn count_invisible(text: &str) -> usize {
    text.chars()
        .filter(|c| {
            matches!(*c, '\u{200b}'..='\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{feff}' | '\u{00ad}' | '\u{2060}')
        })
        .count()
}

/// 检测编码绕过载荷。
///
/// **关键实现细节**：base64 / hex 解码是大小写敏感的，因此载荷提取必须使用**原文**，
/// 不能用小写化后的文本（否则解码必然失败，导致编码绕过漏检）。
#[must_use]
pub fn detect_encoding_bypass(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let has_instruction = ["base64", "解码", "decode", "rot13", "hex", "urlencode", "unescape", "编码后"]
        .iter()
        .any(|p| lower.contains(p));

    if has_instruction {
        for (token, kind, _) in crate::detector::extract_encoded_tokens(text) {
            if let Some(decoded) = crate::detector::try_decode(&token, kind) {
                let dl = decoded.to_lowercase();
                if ["ignore", "system prompt", "忽略", "指令", "password", "token", "secret", "jailbreak"]
                    .iter()
                    .any(|k| dl.contains(k))
                {
                    return Some(format!("{kind} 编码载荷解码后出现敏感内容（载荷已打码）"));
                }
            }
        }
        if let Some(decoded) = crate::detector::decode_unicode_escapes(text) {
            let dl = decoded.to_lowercase();
            if ["ignore", "system prompt", "忽略", "指令", "password"].iter().any(|k| dl.contains(k)) {
                return Some("unicode 转义载荷解码后出现敏感内容".to_string());
            }
        }
    }

    let invisible = count_invisible(text);
    if invisible >= 3 {
        return Some(format!("文本含 {invisible} 个零宽字符，可能用于绕过关键词匹配"));
    }
    if has_homoglyph(text) {
        return Some("检测到同形字混排（如西里尔字母替换拉丁字母），可能用于绕过匹配".to_string());
    }
    None
}

/// 是否含同形字混排（西里尔/希腊字母混入拉丁文本）。
#[must_use]
pub fn has_homoglyph(text: &str) -> bool {
    let mut has_latin = false;
    let mut has_cyrillic_or_greek = false;
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            has_latin = true;
        } else if ('\u{0400}'..='\u{04ff}').contains(&c) || ('\u{0370}'..='\u{03ff}').contains(&c) {
            has_cyrillic_or_greek = true;
        }
    }
    has_latin && has_cyrillic_or_greek
}

/// 检测上下文冲突（同一文档中对同一主题给出相互否定的权威声明）。
#[must_use]
pub fn detect_context_conflict(document: &str) -> Option<String> {
    let lower = document.to_lowercase();
    let contradictions = [
        ("allow", "must not allow"),
        ("允许", "禁止"),
        ("可以访问", "不得访问"),
        ("正确做法是", "正确做法不是"),
        ("是安全的", "是不安全的"),
    ];
    for (a, b) in contradictions {
        if lower.contains(a) && lower.contains(b) {
            return Some(format!("文档中同时出现相互矛盾的声明（`{a}` 与 `{b}`），提示存在分块召回污染"));
        }
    }
    None
}

/// 检测参数中的内网/环回目标（SSRF 面）。
#[must_use]
pub fn detect_internal_target(arguments: &str) -> Option<String> {
    let candidates = ["127.0.0.1", "localhost", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal"];
    let lower = arguments.to_lowercase();
    for c in candidates {
        if lower.contains(c) {
            return Some(c.to_string());
        }
    }
    if let Ok(re) = regex::Regex::new(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    ) {
        if let Some(m) = re.find(arguments) {
            return Some(m.as_str().to_string());
        }
    }
    None
}

/// 检测 PII（返回掩码后的命中列表）。
#[must_use]
pub fn detect_pii(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    static PATTERNS: std::sync::LazyLock<[Result<regex::Regex, regex::Error>; 3]> = std::sync::LazyLock::new(|| {
        [
            r"\b1[3-9]\d{9}\b",
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
        ]
        .map(regex::Regex::new)
    });
    for re in PATTERNS.iter().flatten() {
        for m in re.find_iter(text).take(5) {
            out.push(agf_core::secret::mask_default(m.as_str()));
        }
    }
    out
}

/// 检测数据外传 URL（Markdown 图片 / 短链 / 收集器域名）。
#[must_use]
pub fn detect_exfil_url(text: &str) -> Option<String> {
    let nonce = ["webhook.site", "requestbin", "pipedream", "ngrok", "burpcollaborator", "interact.sh", "oast"];
    static MARKDOWN_IMAGE_REGEX: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"!\[[^\]]*\]\((https?://[^\s)]+)\)"));
    if let Ok(re) = MARKDOWN_IMAGE_REGEX.as_ref() {
        if let Some(caps) = re.captures(text) {
            if let Some(url) = caps.get(1) {
                let u = url.as_str().to_string();
                let ul = u.to_lowercase();
                let suspicious = nonce.iter().any(|k| ul.contains(k))
                    || ul.contains("collect")
                    || ul.contains("track")
                    || ul.contains("pixel");
                let long_query = u.contains('?') && u.split('?').nth(1).is_some_and(|q| q.len() > 40);
                if suspicious || long_query {
                    return Some(u);
                }
            }
        }
    }
    let lower = text.to_lowercase();
    for k in nonce {
        if let Some(pos) = lower.find(k) {
            let start = pos.saturating_sub(20);
            let end = (pos + 60).min(text.len());
            return Some(text[start..end].to_string());
        }
    }
    None
}

/// 计算报告的综合风险分（0-100，用于排序与看板）。
#[must_use]
pub fn aggregate_risk_score(reports: &[DomainReport]) -> u8 {
    let severity_weight = |s: Severity| -> u32 {
        match s {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 12,
            Severity::Low => 5,
            Severity::Info => 0,
        }
    };
    let mut score = 0_u32;
    for r in reports {
        for h in &r.hits {
            let w = severity_weight(h.severity);
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let contribution = (w as f32 * h.confidence) as u32;
            score += contribution;
        }
    }
    u8::try_from(score.min(100)).unwrap_or(100)
}

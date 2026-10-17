//! 密钥原语：凭据识别、掩码、指纹与随机生成。
//!
//! 本模块**不包含任何 I/O**，是纯函数集合，便于单元测试与属性测试覆盖。
//! 真实加解密由 `agf-storage::crypto` / `agf-auth` 承担（依赖 `aes-gcm`），
//! 这里只做与算法无关的识别、掩码和指纹计算。

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credential::CredentialKind;

/// 掩码规则：保留前 `keep_front` 与后 `keep_back` 个字符，中间用 `*` 填充。
///
/// 字符串过短（`len < 8`）时**全部打码**，避免"掩码后仍可还原"；
/// 打码长度等于原文长度，便于人工核对长度而无法还原内容。
#[must_use]
pub fn mask_secret(secret: &str, keep_front: usize, keep_back: usize) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();
    if len == 0 {
        return String::new();
    }
    if len < 8 || len <= keep_front + keep_back {
        return "*".repeat(len);
    }
    let front: String = chars[..keep_front].iter().collect();
    let back: String = chars[len - keep_back..].iter().collect();
    let masked = "*".repeat((len - keep_front - keep_back).min(8));
    format!("{front}{masked}{back}")
}

/// 默认掩码（前 4 后 4）。
#[must_use]
pub fn mask_default(secret: &str) -> String {
    mask_secret(secret, 4, 4)
}

/// 计算凭据指纹：`SHA-256(盐 || 明文)` 的 hex 前 32 位。
///
/// 盐由 `fingerprint_salt` 提供（平台级固定盐，存放于主密钥体系），
/// 使得指纹**不可被彩虹表反查**，但仍可在库内做"同一密钥多处出现"的关联。
#[must_use]
pub fn fingerprint(secret: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"|");
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

/// 计算内容哈希（SHA-256 hex，全长度），用于基线比对。
#[must_use]
pub fn content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// 生成密码学安全随机字节。
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0_u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// 生成随机密钥（base64）。
#[must_use]
pub fn generate_key_b64(len: usize) -> String {
    B64.encode(random_bytes(len))
}

/// 生成强随机口令（满足默认口令策略：长度 + 三类字符）。
///
/// 使用无歧义字符集（去掉 `0O1lI`），便于人工抄录。
#[must_use]
pub fn generate_password(len: usize) -> String {
    use rand::seq::SliceRandom;
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"!@#$%^&*-_=+";
    let len = len.max(12);
    let mut rng = rand::thread_rng();
    let mut out: Vec<char> = Vec::with_capacity(len);
    // 先保证四类各一个，再随机补足
    for set in [LOWER, UPPER, DIGIT, SYMBOL] {
        if let Some(c) = set.choose(&mut rng) {
            out.push(char::from(*c));
        }
    }
    let all: Vec<u8> = [LOWER, UPPER, DIGIT, SYMBOL].concat();
    while out.len() < len {
        if let Some(c) = all.choose(&mut rng) {
            out.push(char::from(*c));
        }
    }
    // 洗牌，避免固定前缀模式被猜到
    out.shuffle(&mut rng);
    out.into_iter().collect()
}

/// 生成 API Key（`agf_live_<32 hex>`），返回 `(明文, 前缀, 指纹输入)`。
#[must_use]
pub fn generate_api_key(prefix: &str) -> String {
    format!("{prefix}{}", hex::encode(random_bytes(24)))
}

/// 生成会话 / 刷新令牌（不透明随机串）。
#[must_use]
pub fn generate_token() -> String {
    B64.encode(random_bytes(32)).replace(['+', '/', '='], "-")
}

/// 一条凭据模式定义。
#[derive(Debug, Clone, Copy)]
pub struct CredentialPattern {
    /// 类型。
    pub kind: CredentialKind,
    /// 模式名（稳定标识，用于规则与统计）。
    pub name: &'static str,
    /// 正则。
    pub regex: &'static str,
    /// 基础置信度（0.0-1.0）。
    pub confidence: f32,
}

/// 内置凭据识别模式表。
///
/// 覆盖 §4.2 凭证泄露要求的 API Key / AK-SK / Token / 私钥 / JWT / 硬编码密钥。
/// 模式刻意保守（宁可漏报也不制造大量噪声），高噪声场景由语义规则与 LLM 研判补足。
pub static CREDENTIAL_PATTERNS: LazyLock<Vec<CredentialPattern>> = LazyLock::new(|| {
    vec![
        CredentialPattern {
            kind: CredentialKind::LlmApiKey,
            name: "openai_key",
            regex: r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::LlmApiKey,
            name: "anthropic_key",
            regex: r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::LlmApiKey,
            name: "dashscope_key",
            regex: r"\bsk-[a-f0-9]{32}\b",
            confidence: 0.8,
        },
        CredentialPattern {
            kind: CredentialKind::CloudAkSk,
            name: "aliyun_ak",
            regex: r"\bLTAI[A-Za-z0-9]{12,20}\b",
            confidence: 0.97,
        },
        CredentialPattern {
            kind: CredentialKind::AwsAkSk,
            name: "aws_access_key_id",
            regex: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            confidence: 0.97,
        },
        CredentialPattern {
            kind: CredentialKind::BearerToken,
            name: "jwt",
            regex: r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
            confidence: 0.9,
        },
        CredentialPattern {
            kind: CredentialKind::BearerToken,
            name: "github_pat",
            regex: r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::BearerToken,
            name: "slack_token",
            regex: r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
            confidence: 0.9,
        },
        CredentialPattern {
            kind: CredentialKind::SshPrivateKey,
            name: "openssh_private_key",
            regex: r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----",
            confidence: 0.99,
        },
        CredentialPattern {
            kind: CredentialKind::TlsPrivateKey,
            name: "pkcs8_private_key",
            regex: r"-----BEGIN PRIVATE KEY-----",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::WebhookSecret,
            name: "dingtalk_webhook",
            regex: r"oapi\.dingtalk\.com/robot/send\?access_token=[A-Za-z0-9]{20,}",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::WebhookSecret,
            name: "feishu_webhook",
            regex: r"open\.feishu\.cn/open-apis/bot/v2/hook/[a-f0-9\-]{20,}",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::WebhookSecret,
            name: "slack_webhook",
            regex: r"hooks\.slack\.com/services/T[A-Za-z0-9_]{6,}/B[A-Za-z0-9_]{6,}/[A-Za-z0-9_]{20,}",
            confidence: 0.95,
        },
        CredentialPattern {
            kind: CredentialKind::GenericPassword,
            name: "kv_password_assignment",
            regex: r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?([^\s"',;]{8,})["']?"#,
            confidence: 0.6,
        },
        CredentialPattern {
            kind: CredentialKind::GenericPassword,
            name: "connection_string_password",
            regex: r"(?i)\b(?:postgres(?:ql)?|mysql|redis|mongodb)://[^\s:@/]+:([^\s@/]{6,})@",
            confidence: 0.85,
        },
        CredentialPattern {
            kind: CredentialKind::McpPlaintext,
            name: "mcp_env_api_key",
            regex: r#"(?i)"(?:[A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)"\s*:\s*"([^"]{8,})""#,
            confidence: 0.75,
        },
    ]
});

// Only the fixed built-in table is cached; caller-supplied patterns remain per-call.
static COMPILED_CREDENTIAL_PATTERNS: LazyLock<Vec<(CredentialPattern, Regex)>> = LazyLock::new(|| {
    CREDENTIAL_PATTERNS
        .iter()
        .filter_map(|pattern| Regex::new(pattern.regex).ok().map(|regex| (*pattern, regex)))
        .collect()
});

/// 一条凭据命中。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialMatch {
    /// 模式名。
    pub pattern: String,
    /// 凭据类型。
    pub kind: CredentialKind,
    /// 命中文本的掩码形态（**不含明文**）。
    pub masked: String,
    /// 命中位置（字符偏移）。
    pub start: usize,
    /// 命中位置结束。
    pub end: usize,
    /// 明文长度。
    pub length: usize,
    /// 置信度。
    pub confidence: f32,
}

/// 在文本中扫描凭据。
///
/// 返回的 [`CredentialMatch`] **不包含明文**，只包含掩码和位置，
/// 因此该结果可安全落库、上报、写日志。
#[must_use]
pub fn scan_credentials(text: &str, extra_patterns: &[CredentialPattern]) -> Vec<CredentialMatch> {
    let mut out: Vec<CredentialMatch> = Vec::new();
    for (pattern, regex) in COMPILED_CREDENTIAL_PATTERNS.iter() {
        scan_single_pattern(text, pattern, regex, &mut out);
    }
    for pattern in extra_patterns {
        let Ok(regex) = Regex::new(pattern.regex) else { continue };
        scan_single_pattern(text, pattern, &regex, &mut out);
    }
    // 去重（同位置同模式），并按位置排序
    out.sort_by(|a, b| (a.start, a.end, a.pattern.as_str()).cmp(&(b.start, b.end, b.pattern.as_str())));
    out.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.pattern == b.pattern);
    out
}

fn scan_single_pattern(text: &str, p: &CredentialPattern, re: &Regex, out: &mut Vec<CredentialMatch>) {
    for caps in re.captures_iter(text) {
        // 若正则带捕获组，优先用第 1 组（更精确的密钥部分）
        let chosen = caps.get(1).or_else(|| caps.get(0));
        let Some(g) = chosen else { continue };
        let matched = g.as_str();
        if matched.len() < 6 || is_placeholder(matched) {
            continue;
        }
        out.push(CredentialMatch {
            pattern: p.name.to_string(),
            kind: p.kind,
            masked: mask_default(matched),
            start: g.start(),
            end: g.end(),
            length: matched.chars().count(),
            confidence: p.confidence,
        });
    }
}

/// 判断是否像占位符/模板变量（`${...}`、`{{...}}`、`changeme`、`xxx`、`your_key_here`）。
#[must_use]
pub fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    let lower = v.to_lowercase();
    if v.starts_with("${") || v.starts_with("{{") || v.starts_with('<') || v.starts_with('%') {
        return true;
    }
    if lower.contains("your_") || lower.contains("your-") || lower.contains("example") || lower.contains("placeholder")
    {
        return true;
    }
    if lower.contains("changeme") || lower.contains("change_me") || lower.contains("xxx") || lower.contains("todo") {
        return true;
    }
    // 全部同一字符（aaaaaa）
    v.chars().all(|c| c == v.chars().next().unwrap_or(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_keeps_edges_and_hides_middle() {
        let m = mask_secret("sk-1234567890abcdef", 4, 4);
        assert!(m.starts_with("sk-1"));
        assert!(m.ends_with("cdef"));
        assert!(m.contains('*'));
        assert!(!m.contains("567890a"));
    }

    #[test]
    fn short_secret_fully_masked() {
        assert_eq!(mask_secret("abc", 2, 2), "***");
        assert_eq!(mask_secret("", 4, 4), "");
        assert_eq!(mask_default("1234567"), "*******");
        assert_eq!(mask_default("12345678"), "********");
        assert_eq!(mask_default("123456789"), "1234*6789");
    }

    #[test]
    fn fingerprint_is_stable_and_salt_dependent() {
        let a = fingerprint("secret-value", "salt1");
        let b = fingerprint("secret-value", "salt1");
        let c = fingerprint("secret-value", "salt2");
        let d = fingerprint("other-value", "salt1");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn content_hash_is_sha256_hex() {
        let h = content_hash("hello");
        assert_eq!(h.len(), 64);
        assert_eq!(h, content_hash("hello"));
        assert_ne!(h, content_hash("hello "));
    }

    #[test]
    fn generated_password_meets_default_policy() {
        let policy = crate::auth::PasswordPolicy { deny_list: vec![], ..crate::auth::PasswordPolicy::default() };
        for _ in 0..25 {
            let p = generate_password(16);
            assert_eq!(p.chars().count(), 16);
            assert!(policy.validate(&p, "user").is_ok(), "生成口令未通过策略: {p}");
        }
    }

    #[test]
    fn api_key_and_token_shapes() {
        let k = generate_api_key("agf_live_");
        assert!(k.starts_with("agf_live_"));
        assert_eq!(k.len(), "agf_live_".len() + 48);
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
        assert!(!t1.contains(['+', '/', '=']));
    }

    #[test]
    fn scans_openai_and_aliyun_keys() {
        let text = "配置: OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWx 和 AK LTAI5tAbCdEfGhIjKlMnOp";
        let hits = scan_credentials(text, &[]);
        assert!(hits.iter().any(|h| h.pattern.as_str() == "openai_key"), "未识别 OpenAI Key: {hits:?}");
        assert!(hits.iter().any(|h| h.pattern.as_str() == "aliyun_ak"), "未识别阿里云 AK: {hits:?}");
    }

    #[test]
    fn scans_jwt_and_private_key() {
        let jwt = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hits = scan_credentials(jwt, &[]);
        assert!(hits.iter().any(|h| h.pattern.as_str() == "jwt"));

        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        let hits2 = scan_credentials(pem, &[]);
        assert!(hits2.iter().any(|h| h.pattern.as_str() == "openssh_private_key"));
    }

    #[test]
    fn scans_connection_string_password() {
        let hits = scan_credentials("postgres://agf:S3cr3tP@ss@127.0.0.1:5432/db", &[]);
        assert!(hits.iter().any(|h| h.pattern.as_str() == "connection_string_password"));
    }

    #[test]
    fn placeholders_are_ignored() {
        let text = "api_key = ${OPENAI_API_KEY} ; password = your_password_here ; token = {{token}}";
        let hits = scan_credentials(text, &[]);
        assert!(hits.is_empty(), "占位符不应被识别为凭据: {hits:?}");
    }

    #[test]
    fn match_never_contains_plaintext() {
        let secret = "sk-proj-VerySecretValue1234567890";
        let hits = scan_credentials(&format!("key={secret}"), &[]);
        assert!(!hits.is_empty());
        for h in &hits {
            assert!(!h.masked.contains("VerySecretValue"));
        }
    }

    #[test]
    fn dedup_same_position() {
        let hits = scan_credentials("LTAI5tAbCdEfGhIjKlMnOp", &[]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn custom_patterns_are_used() {
        let custom = CredentialPattern {
            kind: CredentialKind::GenericPassword,
            name: "internal_prefix",
            regex: r"\bAGFINT_[A-Z0-9]{8}\b",
            confidence: 0.9,
        };
        let hits = scan_credentials("token AGFINT_ABCD1234 结束", &[custom]);
        assert!(hits.iter().any(|h| h.pattern.as_str() == "internal_prefix"));
    }
}

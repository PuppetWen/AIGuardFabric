//! 脱敏原语（§4.3 双向脱敏、§4.2 凭证泄露防护）。
//!
//! 平台有两条脱敏通道：
//! - **入站脱敏**：用户提示词/工具参数中的凭据在落库、送模型前替换为占位符，
//!   并通过 [`RedactionMap`] 保留可逆映射（会话级，内存/Redis，请求结束即销毁）；
//! - **出站脱敏**：模型输出中的敏感信息（PII、凭据）在返回给 Agent 前打码。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::credential::CredentialKind;
use crate::secret::{CredentialMatch, mask_default};

/// 脱敏策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum RedactionMode {
    /// 仅替换凭据（API Key/私钥等）。
    CredentialsOnly,
    /// 凭据 + PII（手机号、邮箱、身份证、银行卡）。
    #[default]
    CredentialsAndPii,
    /// 全部（含内部 IP、主机名、路径）。
    Aggressive,
    /// 不脱敏（仅审计，用于排障；需高权限）。
    None,
}

impl RedactionMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CredentialsOnly => "credentials-only",
            Self::CredentialsAndPii => "credentials-and-pii",
            Self::Aggressive => "aggressive",
            Self::None => "none",
        }
    }

    /// 是否处理 PII。
    #[must_use]
    pub const fn handles_pii(&self) -> bool {
        matches!(self, Self::CredentialsAndPii | Self::Aggressive)
    }

    /// 是否执行任何替换。
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// PII 类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PiiKind {
    /// 中国大陆手机号。
    PhoneCn,
    /// 邮箱。
    Email,
    /// 身份证号。
    IdCardCn,
    /// 银行卡号。
    BankCard,
    /// IPv4 地址。
    IpV4,
    /// 内网主机名。
    Hostname,
}

impl PiiKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PhoneCn => "phone-cn",
            Self::Email => "email",
            Self::IdCardCn => "id-card-cn",
            Self::BankCard => "bank-card",
            Self::IpV4 => "ipv4",
            Self::Hostname => "hostname",
        }
    }
}

/// 一次脱敏替换。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    /// 占位符（如 `[[AGF_SECRET_1]]`）。
    pub placeholder: String,
    /// 被替换内容的掩码（不可逆）。
    pub masked: String,
    /// 类别描述（`credential:llm-api-key` / `pii:phone-cn`）。
    pub category: String,
    /// 原文长度。
    pub length: usize,
}

/// 脱敏映射（可逆；**仅在会话内存在，禁止落库明文**）。
#[derive(Debug, Clone, Default)]
pub struct RedactionMap {
    /// 占位符 → 原文。
    values: BTreeMap<String, String>,
    /// 记录列表（用于审计与展示）。
    entries: Vec<Redaction>,
    /// 计数（生成递增占位符）。
    counter: u32,
}

impl RedactionMap {
    /// 新建空映射。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 是否为空（无任何脱敏发生）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// 脱敏条目。
    #[must_use]
    pub fn entries(&self) -> &[Redaction] {
        &self.entries
    }

    /// 记录一次替换并返回占位符。
    pub fn record(&mut self, original: &str, category: &str) -> String {
        self.counter += 1;
        let placeholder = format!("[[AGF_{}_{}]]", category.replace([':', '-'], "_").to_uppercase(), self.counter);
        self.values.insert(placeholder.clone(), original.to_string());
        self.entries.push(Redaction {
            placeholder: placeholder.clone(),
            masked: mask_default(original),
            category: category.to_string(),
            length: original.chars().count(),
        });
        placeholder
    }

    /// 还原文本中的占位符。
    #[must_use]
    pub fn restore(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (ph, original) in &self.values {
            out = out.replace(ph, original);
        }
        out
    }

    /// 占位符数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }
}

/// 脱敏结果。
#[derive(Debug, Clone)]
pub struct RedactOutcome {
    /// 脱敏后的文本。
    pub text: String,
    /// 替换记录。
    pub redactions: Vec<Redaction>,
}

impl RedactOutcome {
    /// 是否发生了脱敏。
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.redactions.is_empty()
    }
}

/// 对文本执行脱敏。
///
/// 顺序：先凭据（更长更特定），再 PII。使用 [`RedactionMap`] 记录可逆映射。
pub fn redact_text(text: &str, mode: RedactionMode, map: &mut RedactionMap) -> RedactOutcome {
    if !mode.is_active() {
        return RedactOutcome { text: text.to_string(), redactions: Vec::new() };
    }
    let mut out = text.to_string();
    let mut redactions: Vec<Redaction> = Vec::new();

    // 1) 凭据（使用 agf-core 的凭据识别）
    let matches: Vec<CredentialMatch> = crate::secret::scan_credentials(text, &[]);
    // 从后往前替换，避免偏移错乱
    let mut sorted = matches;
    sorted.sort_by_key(|m| std::cmp::Reverse(m.start));
    for m in sorted {
        let Some(slice) = out.get(m.start..m.end) else { continue };
        let original = slice.to_string();
        let placeholder = map.record(&original, &format!("credential:{}", credential_category(m.kind)));
        out.replace_range(m.start..m.end, &placeholder);
        redactions.push(Redaction {
            placeholder,
            masked: m.masked.clone(),
            category: format!("credential:{}", credential_category(m.kind)),
            length: original.chars().count(),
        });
    }

    // 2) PII（按需）
    if mode.handles_pii() {
        for (kind, re) in pii_patterns() {
            let mut hits: Vec<(usize, usize, String)> = Vec::new();
            for caps in re.captures_iter(&out) {
                let Some(g) = caps.get(0) else { continue };
                hits.push((g.start(), g.end(), g.as_str().to_string()));
            }
            hits.sort_by_key(|h| std::cmp::Reverse(h.0));
            for (start, end, original) in hits {
                let placeholder = map.record(&original, &format!("pii:{}", kind.as_str()));
                out.replace_range(start..end, &placeholder);
                redactions.push(Redaction {
                    placeholder,
                    masked: mask_default(&original),
                    category: format!("pii:{}", kind.as_str()),
                    length: original.chars().count(),
                });
            }
        }
    }

    // 3) 激进模式：内网 IP / 主机名 / Windows 用户目录
    if mode == RedactionMode::Aggressive {
        for re in aggressive_patterns() {
            let mut hits: Vec<(usize, usize, String)> = Vec::new();
            for caps in re.captures_iter(&out) {
                let Some(g) = caps.get(0) else { continue };
                hits.push((g.start(), g.end(), g.as_str().to_string()));
            }
            hits.sort_by_key(|h| std::cmp::Reverse(h.0));
            for (start, end, original) in hits {
                if original.contains("AGF_") {
                    continue;
                }
                let placeholder = map.record(&original, "infra");
                out.replace_range(start..end, &placeholder);
                redactions.push(Redaction {
                    placeholder,
                    masked: mask_default(&original),
                    category: "infra".to_string(),
                    length: original.chars().count(),
                });
            }
        }
    }

    RedactOutcome { text: out, redactions }
}

/// 凭据类型 → 短类别名。
#[must_use]
pub const fn credential_category(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::LlmApiKey => "llm-api-key",
        CredentialKind::CloudAkSk => "cloud-aksk",
        CredentialKind::AwsAkSk => "aws-aksk",
        CredentialKind::StsToken => "sts-token",
        CredentialKind::BearerToken => "bearer-token",
        CredentialKind::RefreshToken => "refresh-token",
        CredentialKind::DbPassword => "db-password",
        CredentialKind::SshPrivateKey => "ssh-private-key",
        CredentialKind::TlsPrivateKey => "tls-private-key",
        CredentialKind::McpPlaintext => "mcp-plaintext",
        CredentialKind::WebhookSecret => "webhook-secret",
        CredentialKind::MasterKey => "master-key",
        CredentialKind::GenericPassword => "generic-password",
    }
}

/// PII 正则集合。
fn pii_patterns() -> Vec<(PiiKind, regex::Regex)> {
    let defs: Vec<(PiiKind, &str)> = vec![
        // 中国大陆手机号（1 开头 11 位）
        (PiiKind::PhoneCn, r"\b1[3-9]\d{9}\b"),
        // 邮箱
        (PiiKind::Email, r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        // 身份证（18 位，末位可为 X）
        (PiiKind::IdCardCn, r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
        // 银行卡（16-19 位数字，避免与身份证重复：身份证已在前面处理）
        (PiiKind::BankCard, r"\b(?:62|4|5[1-5])\d{14,17}\b"),
    ];
    defs.into_iter().filter_map(|(k, p)| regex::Regex::new(p).ok().map(|re| (k, re))).collect()
}

/// 激进模式正则（内网地址与主机名）。
fn aggressive_patterns() -> Vec<regex::Regex> {
    [
        // 私网 IPv4
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        // Windows 用户目录
        r"(?i)[A-Z]:\\Users\\[^\\\s]+",
        // Unix home
        r"/(?:home|Users)/[A-Za-z0-9._\-]+",
    ]
    .iter()
    .filter_map(|p| regex::Regex::new(p).ok())
    .collect()
}

/// 对 JSON 载荷做脱敏（递归处理字符串字段）。
///
/// 键名命中 `sensitive_keys`（不区分大小写）时整值打码；
/// 其余字符串走 [`redact_text`]。
#[must_use]
pub fn redact_json(value: &serde_json::Value, mode: RedactionMode, map: &mut RedactionMap) -> serde_json::Value {
    let sensitive = ["password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "private_key"];
    fn walk(
        v: &serde_json::Value,
        mode: RedactionMode,
        map: &mut RedactionMap,
        sensitive: &[&str],
        key: Option<&str>,
    ) -> serde_json::Value {
        match v {
            serde_json::Value::String(s) => {
                if let Some(k) = key {
                    let lk = k.to_lowercase();
                    if sensitive.iter().any(|s| lk.contains(s)) {
                        let ph = map.record(s, "secret-field");
                        return serde_json::Value::String(ph);
                    }
                }
                serde_json::Value::String(redact_text(s, mode, map).text)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(|i| walk(i, mode, map, sensitive, None)).collect())
            }
            serde_json::Value::Object(o) => {
                let mut out = serde_json::Map::new();
                for (k, val) in o {
                    out.insert(k.clone(), walk(val, mode, map, sensitive, Some(k)));
                }
                serde_json::Value::Object(out)
            }
            other => other.clone(),
        }
    }
    walk(value, mode, map, &sensitive, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_redacted_and_restorable() {
        let text = "调用模型: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop";
        let mut map = RedactionMap::new();
        let out = redact_text(text, RedactionMode::CredentialsOnly, &mut map);
        assert!(out.changed());
        assert!(!out.text.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT 必须被替换: {}", out.text);
        assert!(out.text.contains("[[AGF_CREDENTIAL_BEARER_TOKEN_1]]"));
        let restored = map.restore(&out.text);
        assert_eq!(restored, text);
    }

    #[test]
    fn pii_redaction_only_in_pii_modes() {
        let text = "联系 13812345678 或 test.user@example.com";
        let mut m1 = RedactionMap::new();
        let cred_only = redact_text(text, RedactionMode::CredentialsOnly, &mut m1);
        assert!(cred_only.text.contains("13812345678"), "仅凭据模式不应动手机号");

        let mut m2 = RedactionMap::new();
        let pii = redact_text(text, RedactionMode::CredentialsAndPii, &mut m2);
        assert!(!pii.text.contains("13812345678"));
        assert!(!pii.text.contains("test.user@example.com"));
        assert!(pii.redactions.iter().any(|r| r.category == "pii:phone-cn"));
        assert!(pii.redactions.iter().any(|r| r.category == "pii:email"));
    }

    #[test]
    fn id_card_and_bank_card_detected() {
        let text = "身份证 11010519491231002X 银行卡 6222021234567890123";
        let mut map = RedactionMap::new();
        let out = redact_text(text, RedactionMode::CredentialsAndPii, &mut map);
        assert!(out.redactions.iter().any(|r| r.category == "pii:id-card-cn"));
        assert!(out.redactions.iter().any(|r| r.category == "pii:bank-card"));
    }

    #[test]
    fn aggressive_mode_masks_internal_ip_and_paths() {
        let text = r"连接 192.168.1.10 与 10.0.5.7，路径 C:\Users\alice\project 和 /home/bob/x";
        let mut map = RedactionMap::new();
        let out = redact_text(text, RedactionMode::Aggressive, &mut map);
        assert!(!out.text.contains("192.168.1.10"));
        assert!(!out.text.contains("10.0.5.7"));
        assert!(!out.text.contains("alice"));
        assert!(!out.text.contains("bob"));
    }

    #[test]
    fn aggressive_mode_does_not_touch_placeholders() {
        let text = "密钥 [[AGF_CREDENTIAL_LLM_API_KEY_1]] 与 10.1.2.3";
        let mut map = RedactionMap::new();
        let out = redact_text(text, RedactionMode::Aggressive, &mut map);
        assert!(out.text.contains("[[AGF_CREDENTIAL_LLM_API_KEY_1]]"), "占位符不能被二次脱敏: {}", out.text);
        assert!(!out.text.contains("10.1.2.3"));
    }

    #[test]
    fn none_mode_is_noop() {
        let text = "sk-proj-abcdefghijklmnopqrstuvwx 13812345678";
        let mut map = RedactionMap::new();
        let out = redact_text(text, RedactionMode::None, &mut map);
        assert_eq!(out.text, text);
        assert!(!out.changed());
        assert!(map.is_empty());
    }

    #[test]
    fn json_redaction_masks_sensitive_keys() {
        let v = serde_json::json!({
            "model": "gpt-4o",
            "api_key": "sk-proj-abcdefghijklmnopqrstuvwx",
            "nested": {"password": "S3cr3tP@ssw0rd!", "note": "联系 13812345678"},
            "list": [{"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"}]
        });
        let mut map = RedactionMap::new();
        let out = redact_json(&v, RedactionMode::CredentialsAndPii, &mut map);
        let s = out.to_string();
        assert!(!s.contains("sk-proj-abcdefghijklmnopqrstuvwx"));
        assert!(!s.contains("S3cr3tP@ssw0rd!"));
        assert!(!s.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
        assert!(!s.contains("13812345678"));
        assert!(s.contains("gpt-4o"), "非敏感值应保留");
        assert!(s.contains("[[AGF_PII_PHONE_CN_"), "PII 应替换为占位符: {s}");
    }

    #[test]
    fn redaction_map_restores_json_roundtrip() {
        let v = serde_json::json!({"api_key": "sk-proj-abcdefghijklmnopqrstuvwx"});
        let mut map = RedactionMap::new();
        let out = redact_json(&v, RedactionMode::CredentialsAndPii, &mut map);
        let masked_key = out["api_key"].as_str().unwrap_or_default().to_string();
        let restored = map.restore(&masked_key);
        assert_eq!(restored, "sk-proj-abcdefghijklmnopqrstuvwx");
    }

    #[test]
    fn mode_helpers() {
        assert!(RedactionMode::default().handles_pii());
        assert!(!RedactionMode::CredentialsOnly.handles_pii());
        assert!(!RedactionMode::None.is_active());
        assert_eq!(RedactionMode::Aggressive.as_str(), "aggressive");
    }

    #[test]
    fn credential_category_names() {
        assert_eq!(credential_category(CredentialKind::AwsAkSk), "aws-aksk");
        assert_eq!(credential_category(CredentialKind::SshPrivateKey), "ssh-private-key");
        assert_eq!(PiiKind::IdCardCn.as_str(), "id-card-cn");
        assert_eq!(PiiKind::IpV4.as_str(), "ipv4");
    }
}

//! Parity against the preserved pre-cache scanner; fixtures contain synthetic tokens only.
use agf_core::credential::CredentialKind;
use agf_core::secret::{
    CREDENTIAL_PATTERNS, CredentialMatch, CredentialPattern, is_placeholder, mask_default, scan_credentials,
};
use regex::Regex;

fn uncached_scan_credentials_oracle(text: &str, extra_patterns: &[CredentialPattern]) -> Vec<CredentialMatch> {
    let mut out: Vec<CredentialMatch> = Vec::new();
    let iter = CREDENTIAL_PATTERNS.iter().chain(extra_patterns.iter());
    for p in iter {
        let Ok(re) = Regex::new(p.regex) else { continue };
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
    // 去重（同位置同模式），并按位置排序
    out.sort_by(|a, b| (a.start, a.end, a.pattern.as_str()).cmp(&(b.start, b.end, b.pattern.as_str())));
    out.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.pattern == b.pattern);
    out
}

#[test]
fn every_builtin_retains_uncached_oracle_results() {
    let fixtures = [
        ("openai_key", "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"),
        ("anthropic_key", "sk-ant-AbCdEfGhIjKlMnOpQrStUvWx"),
        ("dashscope_key", "sk-0123456789abcdef0123456789abcdef"),
        ("aliyun_ak", "LTAI5tAbCdEfGhIjKlMnOp"),
        ("aws_access_key_id", "AKIA0123456789ABCDEF"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        ("github_pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
        ("slack_token", "xoxb-1234567890-abC"),
        ("openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("pkcs8_private_key", "-----BEGIN PRIVATE KEY-----"),
        ("dingtalk_webhook", "oapi.dingtalk.com/robot/send?access_token=AbCdEfGhIjKlMnOpQrStUvWx"),
        ("feishu_webhook", "open.feishu.cn/open-apis/bot/v2/hook/01234567-89ab-cdef-0123-456789abcdef"),
        ("slack_webhook", "hooks.slack.com/services/TABCDEF/B123456/AbCdEfGhIjKlMnOpQrStUv"),
        ("kv_password_assignment", "password='S3cureAb9!'"),
        ("connection_string_password", "postgres://agf:S3cureAb9!@localhost/db"),
        ("mcp_env_api_key", r#""MY_API_KEY": "AbCdEf123456""#),
    ];
    assert_eq!(fixtures.len(), CREDENTIAL_PATTERNS.len());
    for (name, text) in fixtures {
        let hits = scan_credentials(text, &[]);
        assert!(hits.iter().any(|hit| hit.pattern == name), "missing {name}");
        assert_eq!(hits, uncached_scan_credentials_oracle(text, &[]), "{name}");
    }
}

#[test]
fn extras_skip_invalid_and_preserve_first_capture_and_absent_capture_fallback() {
    let extras = [
        CredentialPattern { kind: CredentialKind::GenericPassword, name: "invalid", regex: "(", confidence: 0.1 },
        CredentialPattern {
            kind: CredentialKind::McpPlaintext,
            name: "first_capture",
            regex: r"key=([A-Za-z0-9]{12})(Z)?",
            confidence: 0.37,
        },
        CredentialPattern {
            kind: CredentialKind::BearerToken,
            name: "optional_capture",
            regex: r"(OPTIONAL_)?AGFINT_[A-Z0-9]{8}",
            confidence: 0.81,
        },
    ];
    let text = "key=Ab12Cd34Ef56Z and AGFINT_ABCD1234";
    let hits = scan_credentials(text, &extras);
    assert_eq!(hits, uncached_scan_credentials_oracle(text, &extras));
    assert_eq!(hits.len(), 2);
    let first = &hits[0];
    assert_eq!(first.pattern, "first_capture");
    assert_eq!(&text[first.start..first.end], "Ab12Cd34Ef56");
    assert_eq!(first.kind, CredentialKind::McpPlaintext);
    assert_eq!(first.confidence.to_bits(), 0.37_f32.to_bits());
    assert_eq!(hits[1].pattern, "optional_capture");
    assert_eq!(&text[hits[1].start..hits[1].end], "AGFINT_ABCD1234");

    // Reusing a caller's name with a different regex must use this invocation's regex.
    let changed = CredentialPattern { regex: r"AGFALT_[A-Z0-9]{8}", ..extras[2] };
    let changed_hits = scan_credentials("AGFINT_ABCD1234 AGFALT_EFGH5678", &[changed]);
    assert_eq!(changed_hits, uncached_scan_credentials_oracle("AGFINT_ABCD1234 AGFALT_EFGH5678", &[changed]));
    assert_eq!(changed_hits.len(), 1);
    assert_eq!(changed_hits[0].start, "AGFINT_ABCD1234 ".len());
}

#[test]
fn overlaps_keep_stable_dedup_metadata_and_original_sort_order() {
    let duplicate = CredentialPattern {
        kind: CredentialKind::GenericPassword,
        name: "openai_key",
        regex: r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        confidence: 0.01,
    };
    let captured = CredentialPattern {
        kind: CredentialKind::McpPlaintext,
        name: "overlap_capture",
        regex: r"sk-([A-Za-z0-9_\-]{20,})",
        confidence: 0.37,
    };
    let extras = [duplicate, captured, captured];
    let text = "sk-ant-AbCdEfGhIjKlMnOpQrStUvWx sk-0123456789abcdef0123456789abcdef";
    let hits = scan_credentials(text, &extras);
    assert_eq!(hits, uncached_scan_credentials_oracle(text, &extras));
    assert_eq!(hits.iter().filter(|hit| hit.pattern == "overlap_capture").count(), 2);
    for hit in hits.iter().filter(|hit| hit.pattern == "openai_key") {
        assert_eq!(hit.kind, CredentialKind::LlmApiKey);
        assert_eq!(hit.confidence.to_bits(), 0.95_f32.to_bits());
    }
    assert!(hits.windows(2).all(|pair| {
        (pair[0].start, pair[0].end, pair[0].pattern.as_str()) < (pair[1].start, pair[1].end, pair[1].pattern.as_str())
    }));
    assert!(hits.iter().any(|hit| hit.pattern == "anthropic_key" && hit.start == 0));
}

#[test]
fn utf8_offsets_byte_minimum_masks_and_placeholders_match_oracle() {
    let extra = CredentialPattern {
        kind: CredentialKind::GenericPassword,
        name: "utf8_capture",
        regex: r"密钥=([^ ;]+)",
        confidence: 0.37,
    };
    let text = "前缀🔒 密钥=é中a ; 密钥=ab ; 密钥=${TOKEN_VALUE} ; 密钥=your_value_here ; 密钥=abc123456";
    let hits = scan_credentials(text, &[extra]);
    assert_eq!(hits, uncached_scan_credentials_oracle(text, &[extra]));
    assert_eq!(hits.len(), 2);
    let first = &hits[0];
    let start = text.find("é中a");
    assert_eq!(Some(first.start), start);
    assert_eq!(first.end - first.start, 6);
    assert_eq!(first.length, 3);
    assert_eq!(first.masked, "***");
    assert_eq!(&text[first.start..first.end], "é中a");
    assert_eq!(hits[1].masked, mask_default("abc123456"));
}

#[test]
fn empty_first_capture_and_mixed_corpus_match_uncached_oracle() {
    let empty_capture = CredentialPattern {
        kind: CredentialKind::BearerToken,
        name: "empty_first_capture",
        regex: r"(a*)AGFINT_[A-Z0-9]{8}",
        confidence: 0.5,
    };
    let corpus = [
        "",
        r#"{"remote_addr":"192.0.2.10","request":"GET /health HTTP/1.1","status":200,"body_bytes_sent":12}"#,
        "前缀🔒 AGFINT_ABCD1234 后缀",
        "api_key=${OPENAI_API_KEY}; password=your_password_here; secret=changeme12345",
        "password=é中aé; postgres://agf:Ab12Cd34@localhost/db; -----BEGIN RSA PRIVATE KEY-----",
        r#"{"MY_API_KEY":"sk-proj-AbCdEfGhIjKlMnOpQrStUvWx","PASSWORD":"myRealValue123"}"#,
    ];
    for text in corpus {
        assert_eq!(scan_credentials(text, &[empty_capture]), uncached_scan_credentials_oracle(text, &[empty_capture]));
    }
    assert!(scan_credentials("AGFINT_ABCD1234", &[empty_capture]).is_empty());
}

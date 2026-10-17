//! 环境变量硬编码密钥扫描（Windows/Linux/macOS 使用同一标准库实现）。
//!
//! 扫描对象：
//! 1. **进程环境变量**（`AGF_AGENT_*` 之外的业务 Key，如 `OPENAI_API_KEY=sk-…`）；
//! 2. **`~/.env` / `~/.env.local`** 等本地环境文件（按行号定位）。
//!
//! ## 判定口径（与平台侧 `agf_core::secret` 一致）
//!
//! - 形如 `sk-…` / `AKIA…` / JWT / 私钥头 → 由内置模式表给出类型与置信度；
//! - 键名含 `API_KEY|TOKEN|SECRET|PASSWORD|ACCESS_KEY` 且值 ≥16 字符且非占位符 → `generic_env_secret`；
//! - 占位符（`${VAR}`、`changeme`、`your_key_here`、全同字符）一律**不报**。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 环境变量读取被限制（沙箱/服务账号） | 产出空结果并记 scope，不报错 |
//! | `.env` 文件不存在 | 跳过（不产生 warning，属正常情况） |
//! | 文本文件超大/非 UTF-8 | 记 warning，跳过该文件 |
//! | Linux/macOS | 与 Windows 共用读取与掩码逻辑；Linux 已在容器运行，macOS 待真机验证 |

use agf_core::agent::DetectedCredential;

use super::{
    CollectContext, CollectorOutcome, is_sensitive_key, looks_like_plaintext_secret, read_text, scan_text_secrets,
};

/// 采集器名。
pub const NAME: &str = "env-secrets";

/// `.env` 候选文件名。
pub const ENV_FILE_NAMES: [&str; 4] = [".env", ".env.local", ".env.development", ".env.production"];

/// 扫描"键值对"集合（纯函数，便于用构造样本单测，不依赖真实环境变量）。
#[must_use]
pub fn scan_pairs(pairs: &[(String, String)]) -> Vec<DetectedCredential> {
    let mut out: Vec<DetectedCredential> = Vec::new();
    for (key, value) in pairs {
        // 管控端给本 Agent 的上行密钥属于运行自身，不作为业务密钥资产上报。
        if key.to_ascii_uppercase().starts_with("AGF_AGENT_") {
            continue;
        }
        let source = format!("env:{key}");
        // ① 内置模式表精确命中（sk- / AKIA / JWT / 私钥 …）
        for hit in scan_text_secrets(&source, value) {
            out.push(hit);
        }
        // ② 敏感键名 + 长值启发式
        if looks_like_plaintext_secret(key, value) {
            out.push(DetectedCredential {
                source_file: source.clone(),
                line: 0,
                kind: "generic_env_secret".to_string(),
                masked: agf_core::secret::mask_default(value.trim()),
                context: None,
                confidence: if is_sensitive_key(key) { 0.6 } else { 0.5 },
            });
        }
    }
    out.sort_by(|a, b| (a.source_file.as_str(), a.kind.as_str()).cmp(&(b.source_file.as_str(), b.kind.as_str())));
    out.dedup_by(|a, b| a.source_file == b.source_file && a.kind == b.kind);
    out
}

/// 扫描真实进程环境变量。
#[must_use]
pub fn scan_process_env() -> Vec<DetectedCredential> {
    let pairs: Vec<(String, String)> = std::env::vars().collect();
    scan_pairs(&pairs)
}

/// 执行采集。
#[must_use]
pub fn collect(ctx: &CollectContext) -> CollectorOutcome<DetectedCredential> {
    if crate::platform::current() == crate::platform::HostPlatform::Other {
        return CollectorOutcome::unsupported(NAME, "环境变量采集不支持当前平台".to_string());
    }
    let started = std::time::Instant::now();
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: scan_process_env(),
        credential_hits: Vec::new(),
        scope: vec!["env:process".to_string()],
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    for name in ENV_FILE_NAMES {
        let path = ctx.home.join(name);
        if !path.is_file() {
            continue;
        }
        outcome.scope.push(path.display().to_string());
        match read_text(&path, ctx.max_file_bytes) {
            Ok(text) => outcome.items.extend(scan_text_secrets(&path.display().to_string(), &text)),
            Err(reason) => outcome.warnings.push(format!("{}: {reason}", path.display())),
        }
    }
    outcome.items.sort_by(|a, b| (a.source_file.as_str(), a.line).cmp(&(b.source_file.as_str(), b.line)));
    outcome.items.dedup_by(|a, b| a.source_file == b.source_file && a.line == b.line && a.kind == b.kind);
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn detects_openai_and_aws_keys_without_leaking_plaintext() {
        let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
        // 注意：AWS 官方文档里的 `…EXAMPLE` 会被 agf_core 的占位符识别排除，这里用真实形态样本
        let aws = "AKIAIOSFODNN7ABCDEFG";
        let hits = scan_pairs(&pairs(&[("OPENAI_API_KEY", secret), ("AWS_ACCESS_KEY_ID", aws)]));
        assert!(hits.iter().any(|h| h.kind == "openai_key"), "应识别 sk- 前缀: {hits:?}");
        assert!(hits.iter().any(|h| h.kind == "aws_access_key_id"), "应识别 AKIA: {hits:?}");
        for hit in &hits {
            assert!(!hit.masked.contains(secret), "掩码不得包含完整明文");
            assert!(!hit.masked.contains(aws), "掩码不得包含完整明文");
            assert!(hit.confidence > 0.0);
        }
    }

    #[test]
    fn detects_sensitive_key_heuristic() {
        let hits = scan_pairs(&pairs(&[("MY_SERVICE_TOKEN", "abcdef0123456789abcdef0123456789")]));
        assert!(hits.iter().any(|h| h.kind == "generic_env_secret"));
        assert!(hits[0].masked.starts_with("abcd"));
    }

    #[test]
    fn negative_samples_are_not_reported() {
        let hits = scan_pairs(&pairs(&[
            ("PATH", "/usr/local/bin:/usr/bin"),
            ("HOME", "/home/alice"),
            ("OPENAI_API_KEY", "${OPENAI_API_KEY}"),
            ("MY_TOKEN", "short"),
            ("MY_SECRET", "changeme"),
            ("MY_PASSWORD", "xxxxxxxxxxxxxxxxxxxx"),
            ("AGF_AGENT_TOKEN", "sk-abcdefghijklmnopqrstuvwxyz012345"),
            ("EMPTY", ""),
        ]));
        assert!(hits.is_empty(), "占位符/短值/全同字符不得误报: {hits:?}");
    }

    #[test]
    fn duplicates_are_collapsed() {
        let value = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let hits = scan_pairs(&pairs(&[("A_API_KEY", value), ("A_API_KEY", value)]));
        let count = hits.iter().filter(|h| h.kind == "openai_key").count();
        assert_eq!(count, 1, "同一来源同一模式只报一次");
    }

    #[test]
    fn collect_reads_process_env_and_env_files() {
        let dir = tempfile::tempdir().expect("临时目录");
        std::fs::write(dir.path().join(".env"), "SERVICE_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345\nPATH=/usr/bin\n")
            .expect("写入 .env");
        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert_eq!(outcome.name, NAME);
        assert!(outcome.is_ok());
        assert!(outcome.scope.iter().any(|s| s.contains(".env")));
        let from_file = outcome.items.iter().find(|h| h.source_file.contains(".env")).expect("应命中 .env 中的密钥");
        assert_eq!(from_file.line, 1, "行号必须准确");
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    }

    #[test]
    fn missing_env_files_are_silently_skipped() {
        let dir = tempfile::tempdir().expect("临时目录");
        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert!(!outcome.scope.iter().any(|s| s.contains(".env")), "不存在的文件不应进入 scope");
    }
}

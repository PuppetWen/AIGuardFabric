//! `agfctl genkey` — 生成密钥 / 强随机口令。
//!
//! ## 安全约束（§2.6 安全基线）
//!
//! 1. **明文只出现在 stdout（或 `--out` 文件），绝不进日志**——本模块不调用 `tracing`，
//!    产出的 [`GenkeyReport`] 里也只有掩码形态，因此"顺手 `info!(?report)`"不会泄密；
//! 2. `--out` 落盘时 POSIX 权限收紧到 `0600`，并在人类可读输出里提示权限要求；
//! 3. `admin-password` 用 `agf-auth` 的 Argon2id 写入（参数与生产一致），
//!    并且**当场自校验一次**哈希，避免把不可用的哈希交给用户。

use std::path::PathBuf;

use agf_auth::PasswordHasher;
use serde::Serialize;

use crate::cli::KeyKind;
use crate::error::{AppError, Exit};
use crate::output::Output;

/// JWT 密钥长度（字节）——`agf-auth::TokenIssuer` 要求 ≥32 字节。
pub const JWT_SECRET_BYTES: usize = 48;
/// 字段级加密主密钥长度（字节）——AES-256-GCM 要求 32 字节。
pub const FIELD_KEY_BYTES: usize = 32;
/// 引导管理员口令长度。
pub const ADMIN_PASSWORD_LEN: usize = 24;

/// 生成结果（**不含明文**，可安全打印/落日志）。
#[derive(Debug, Clone, Serialize)]
pub struct GenkeyReport {
    /// 生成类型。
    pub kind: String,
    /// 环境变量占用名（提示用户写到哪里）。
    pub env_var: String,
    /// 明文长度（字符）。
    pub plaintext_len: usize,
    /// 明文掩码形态。
    pub masked: String,
    /// Argon2id PHC 哈希（仅 `admin-password`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phc: Option<String>,
    /// 输出文件（省略时写 stdout）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out: Option<String>,
    /// 给操作者的安全提示。
    pub notes: Vec<String>,
}

/// 一次生成的完整产物。
#[derive(Debug, Clone)]
pub struct GenkeyOutcome {
    /// 明文（**只应写 stdout 或文件**）。
    pub plaintext: String,
    /// 不含明文的报告。
    pub report: GenkeyReport,
}

/// 生成密钥/口令（纯逻辑，不写任何文件）。
///
/// # Errors
/// Argon2 哈希失败或生成的口令未通过口令策略。
pub fn generate(kind: KeyKind) -> Result<GenkeyOutcome, AppError> {
    match kind {
        KeyKind::Jwt => {
            let secret = agf_core::secret::generate_key_b64(JWT_SECRET_BYTES);
            Ok(GenkeyOutcome {
                report: GenkeyReport {
                    kind: kind.as_str().to_string(),
                    env_var: "AGF_JWT_SECRET".to_string(),
                    plaintext_len: secret.chars().count(),
                    masked: agf_core::secret::mask_default(&secret),
                    phc: None,
                    out: None,
                    notes: vec![
                        format!("写入 .env 的 AGF_JWT_SECRET；解码后 {JWT_SECRET_BYTES} 字节（HS256 最低要求 32）"),
                        "轮换 JWT 密钥会使全部在途令牌失效，请在维护窗口执行".to_string(),
                    ],
                },
                plaintext: secret,
            })
        }
        KeyKind::Field => {
            let key = agf_core::secret::generate_key_b64(FIELD_KEY_BYTES);
            Ok(GenkeyOutcome {
                report: GenkeyReport {
                    kind: kind.as_str().to_string(),
                    env_var: "AGF_MASTER_KEY_BASE64".to_string(),
                    plaintext_len: key.chars().count(),
                    masked: agf_core::secret::mask_default(&key),
                    phc: None,
                    out: None,
                    notes: vec![
                        format!("写入 .env 的 AGF_MASTER_KEY_BASE64；解码后必须正好 {FIELD_KEY_BYTES} 字节"),
                        "主密钥用于凭据字段级加密：丢失将导致已存凭据不可解，务必进 KMS/密钥保管".to_string(),
                    ],
                },
                plaintext: key,
            })
        }
        KeyKind::AdminPassword => {
            let hasher = PasswordHasher::default();
            // 引导管理员口令是"进生产的第一把钥匙"，因此比策略下限更严：
            // agf-auth 的 `generate_initial_password()` 取 max(策略最小值, 20)，
            // 对 CLI 交付场景偏短，这里固定按 ADMIN_PASSWORD_LEN 生成（≥24 字符），
            // 再走同一套 check_policy / hash_checked / 自校验。
            let password = agf_core::secret::generate_password(ADMIN_PASSWORD_LEN);
            hasher
                .check_policy(&password, "admin")
                .map_err(|e| AppError::Fatal(anyhow::anyhow!("生成口令未通过口令策略（不应发生）: {e}")))?;
            let phc = hasher.hash_checked(&password, "admin")?;
            // 自校验：确保交付的哈希可用，避免用户拿到一个永远校验不过的串
            let valid =
                hasher.verify(&password, &phc).map_err(|e| AppError::Fatal(anyhow::anyhow!("自校验失败: {e}")))?;
            if !valid {
                return Err(AppError::Fatal(anyhow::anyhow!("Argon2id 自校验未通过，拒绝输出该哈希")));
            }
            Ok(GenkeyOutcome {
                report: GenkeyReport {
                    kind: kind.as_str().to_string(),
                    env_var: "AGF_BOOTSTRAP_ADMIN_PASSWORD（或 SQL 写入 users.password_hash）".to_string(),
                    plaintext_len: password.chars().count(),
                    masked: agf_core::secret::mask_default(&password),
                    phc: Some(phc),
                    out: None,
                    notes: vec![
                        format!(
                            "口令长度 {}（≥ {}，严于策略下限），大小写字母/数字/符号四类齐备",
                            password.chars().count(),
                            ADMIN_PASSWORD_LEN
                        ),
                        "明文只出现一次：请立即交给使用者，不要粘贴进聊天/工单/日志".to_string(),
                        "哈希为 Argon2id(m=19456KiB,t=2,p=1)，与 agf-auth 生产参数一致".to_string(),
                    ],
                },
                plaintext: password,
            })
        }
    }
}

/// 渲染人类可读输出（**默认打码**；`reveal` 时才打印明文，供 stdout/文件用）。
#[must_use]
pub fn render_text(outcome: &GenkeyOutcome, reveal: bool) -> String {
    let r = &outcome.report;
    let mut s = String::new();
    s.push_str(&format!("生成类型: {}\n", r.kind));
    s.push_str(&format!("建议写入: {}\n", r.env_var));
    let shown = if reveal { outcome.plaintext.clone() } else { r.masked.clone() };
    s.push_str(&format!("明文(len={}): {shown}\n", r.plaintext_len));
    if let Some(phc) = &r.phc {
        s.push_str(&format!("Argon2id: {phc}\n"));
    }
    if let Some(out) = &r.out {
        s.push_str(&format!("已写入: {out}\n"));
    }
    for note in &r.notes {
        s.push_str(&format!("说明: {note}\n"));
    }
    s
}

/// `genkey` 主体：生成 → 可选落盘 → 打印。
///
/// # Errors
/// 生成失败、写文件失败或权限收紧失败（Unix）。
pub fn run(kind: KeyKind, out: Option<PathBuf>, output: Output) -> Result<(), AppError> {
    let outcome = generate(kind)?;
    let mut report = outcome.report.clone();

    if let Some(path) = &out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("{}\n", outcome.plaintext))?;
        report.out = Some(path.to_string_lossy().replace('\\', "/"));
        report.notes.push(if cfg!(windows) {
            "文件权限：Windows 请用 icacls 限制到当前用户（本工具不改 ACL）".to_string()
        } else {
            "文件权限已收紧到 0600（仅属主可读）".to_string()
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }

    if output.is_json() {
        let mut value = serde_json::to_value(&report)?;
        if let Some(map) = value.as_object_mut() {
            map.insert("ok".to_string(), serde_json::Value::Bool(true));
            if out.is_none() {
                // stdout 就是机密通道：JSON 模式把明文放进来，方便 `--json | jq -r .plaintext`
                map.insert("plaintext".to_string(), serde_json::Value::String(outcome.plaintext.clone()));
            }
        }
        output.emit(&value)?;
    } else {
        output.line(&render_text(&outcome, out.is_none()));
    }
    Ok(())
}

/// 供测试与调用方使用的显式失败构造（生成类型非法）。
#[must_use]
pub fn unsupported_kind(kind: &str) -> AppError {
    AppError::Exit(Exit::failed(format!("不支持的生成类型: {kind}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_key_decodes_to_expected_length_and_is_unique() {
        let a = generate(KeyKind::Jwt).expect("生成 jwt");
        let b = generate(KeyKind::Jwt).expect("生成 jwt");
        assert_ne!(a.plaintext, b.plaintext, "两次生成必须不同");
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(&a.plaintext).expect("base64 合法");
        assert_eq!(decoded.len(), JWT_SECRET_BYTES);
        assert_eq!(a.report.env_var, "AGF_JWT_SECRET");
        assert_eq!(a.report.kind, "jwt");
        assert!(a.report.phc.is_none());
    }

    #[test]
    fn field_key_decodes_to_32_bytes() {
        let key = generate(KeyKind::Field).expect("生成 field");
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(&key.plaintext).expect("base64 合法");
        assert_eq!(decoded.len(), FIELD_KEY_BYTES, "AES-256-GCM 主密钥必须是 32 字节");
        assert_eq!(key.report.env_var, "AGF_MASTER_KEY_BASE64");
    }

    #[test]
    fn admin_password_hashes_with_argon2id_and_verifies() {
        let outcome = generate(KeyKind::AdminPassword).expect("生成口令");
        let phc = outcome.report.phc.clone().expect("必须带 Argon2id 哈希");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "参数须与生产一致: {phc}");
        let hasher = PasswordHasher::default();
        assert_eq!(hasher.verify(&outcome.plaintext, &phc).ok(), Some(true), "交付的哈希必须能校验通过");
        assert_eq!(hasher.verify("wrong-password", &phc).ok(), Some(false));
        assert!(hasher.check_policy(&outcome.plaintext, "admin").is_ok(), "生成口令必须过策略");
        assert!(outcome.plaintext.chars().count() >= ADMIN_PASSWORD_LEN);
    }

    #[test]
    fn report_never_contains_plaintext() {
        for kind in [KeyKind::Jwt, KeyKind::Field, KeyKind::AdminPassword] {
            let outcome = generate(kind).expect("生成");
            let json = serde_json::to_string(&outcome.report).expect("序列化");
            assert!(!json.contains(&outcome.plaintext), "报告（可落日志）泄露了明文: kind={}", outcome.report.kind);
            let masked = &outcome.report.masked;
            assert!(masked.contains('*'), "掩码必须打码: {masked}");
            assert!(!masked.contains(&outcome.plaintext), "掩码不得等于明文");
        }
    }

    #[test]
    fn render_text_hides_plaintext_unless_revealed() {
        let outcome = generate(KeyKind::Field).expect("生成");
        let hidden = render_text(&outcome, false);
        assert!(!hidden.contains(&outcome.plaintext), "默认渲染不得含明文");
        assert!(hidden.contains("建议写入: AGF_MASTER_KEY_BASE64"));
        let revealed = render_text(&outcome, true);
        assert!(revealed.contains(&outcome.plaintext));
        assert!(revealed.contains(&format!("len={}", outcome.plaintext.chars().count())));
    }

    #[test]
    fn unsupported_kind_maps_to_validation_failure() {
        let err = unsupported_kind("rsa");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("rsa"));
    }
}

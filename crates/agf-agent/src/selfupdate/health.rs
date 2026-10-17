//! 健康证据绑定同一随机数、事务、程序摘要与原始截止时间。
use super::{
    journal::{self, Journal, Phase},
    paths::{InstallRoot, deny, io, plain},
};
use agf_core::error::DomainResult;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::PathBuf, time::Duration};
use uuid::Uuid;
pub(crate) const ENV_ROOT: &str = "AGF_UPDATE_INSTALL_ROOT";
pub(crate) const ENV_TX: &str = "AGF_UPDATE_TRANSACTION";
pub(crate) const ENV_NONCE: &str = "AGF_UPDATE_HEALTH_NONCE";
pub(crate) const ENV_TARGET: &str = "AGF_UPDATE_TARGET_NAME";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    transaction: Uuid,
    nonce: Uuid,
    executable_sha256: String,
    observed_ms: u64,
}
pub(crate) fn valid(root: &InstallRoot, fact: &Journal) -> DomainResult<bool> {
    let directory = journal::tx_dir(root, fact.transaction)?;
    // 安装根及事务目录仍是权威归属边界，错误必须阻止恢复操作。
    plain(&directory)?;
    let path = directory.join("heartbeat.json");
    // 健康文件只是确认凭证；损坏、链接、超预算或无法读取均表示未健康，
    // 不能让它绕过原始截止时间，永久挡住已校验备份的安全回滚。
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    if !metadata.is_file() || metadata.file_type().is_symlink() || reparse || metadata.len() > 65536 {
        return Ok(false);
    }
    let mut bytes = Vec::new();
    let Ok(file) = std::fs::File::open(&path) else { return Ok(false) };
    if file.take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
        return Ok(false);
    }
    let Ok(value) = serde_json::from_slice::<Heartbeat>(&bytes) else { return Ok(false) };
    // 发布候选摘要与健康凭证的字段名不同，但必须匹配同一已验签程序。
    let executable_matches = value.executable_sha256 == fact.candidate_sha256;
    Ok(value.transaction == fact.transaction
        && value.nonce == fact.nonce
        && executable_matches
        && value.observed_ms > 0
        && value.observed_ms <= fact.health_deadline_ms
        && value.observed_ms <= journal::now_ms()?
        && journal::hash_file(&root.target)?.0 == fact.candidate_sha256)
}
fn context() -> DomainResult<Option<(InstallRoot, Journal)>> {
    let Some(root) = std::env::var_os(ENV_ROOT) else {
        if [ENV_TX, ENV_NONCE, ENV_TARGET].iter().any(|name| std::env::var_os(name).is_some()) {
            return Err(deny("Incomplete supervised-update environment"));
        }
        return Ok(None);
    };
    let transaction = std::env::var(ENV_TX)
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or_else(|| deny("Invalid supervised-update transaction"))?;
    let nonce = std::env::var(ENV_NONCE)
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or_else(|| deny("Invalid supervised-update nonce"))?;
    let name = std::env::var(ENV_TARGET).map_err(|_| deny("Missing supervised-update target"))?;
    // 健康上报必须来自安装目标自身的运行映像。
    let root_path = PathBuf::from(root);
    plain(&root_path)?;
    let root_path = std::fs::canonicalize(root_path).map_err(io)?;
    let target = root_path.join(&name);
    plain(&target)?;
    if name.is_empty()
        || std::path::Path::new(&name).components().count() != 1
        || !matches!(std::path::Path::new(&name).components().next(), Some(std::path::Component::Normal(_)))
        || std::fs::canonicalize(std::env::current_exe().map_err(io)?).map_err(io)? != target
    {
        return Err(deny("Supervised heartbeat must originate from the installed executable"));
    }
    let root = InstallRoot { root: root_path, target };
    let fact = journal::load(&root, transaction)?;
    if fact.nonce != nonce
        || !matches!(fact.phase, Phase::AwaitingHealth | Phase::Confirmed)
        || journal::hash_file(&root.target)?.0 != fact.candidate_sha256
    {
        return Err(deny("Supervised-update identity or installed bytes changed"));
    }
    Ok(Some((root, fact)))
}
/// Agent 收到已认证平台的成功响应后才能记录启动健康。
/// 普通启动、未受更新监督的 Agent 返回 false。
///
/// # Errors
/// 更新身份非法、启动租约过期、程序被修改或持久化失败时返回错误。
pub fn acknowledge_platform_heartbeat() -> DomainResult<bool> {
    let Some((root, fact)) = context()? else {
        return Ok(false);
    };
    if valid(&root, &fact)? {
        return Ok(true);
    }
    let observed_ms = journal::now_ms()?;
    if observed_ms > fact.health_deadline_ms {
        return Err(deny("Original update health deadline expired"));
    }
    journal::write_json(
        &journal::tx_dir(&root, fact.transaction)?.join("heartbeat.json"),
        &Heartbeat {
            transaction: fact.transaction,
            nonce: fact.nonce,
            executable_sha256: fact.candidate_sha256.clone(),
            observed_ms,
        },
    )?;
    Ok(true)
}
/// 在受监督子进程内启动仅约束自身的启动看门狗。
/// 外部监督助手崩溃后，未确认健康的新 Agent 仍会按原始期限自行退出。
///
/// # Errors
/// 在采集循环启动前拒绝伪造或不完整的更新环境。
pub fn arm_update_watchdog() -> DomainResult<()> {
    let Some((root, fact)) = context()? else {
        return Ok(());
    };
    let remaining = fact.health_deadline_ms.saturating_sub(journal::now_ms()?);
    let _watchdog = std::thread::Builder::new()
        .name("agf-update-startup-health".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_millis(remaining));
            if !valid(&root, &fact).unwrap_or(false) {
                std::process::exit(78);
            }
        })
        .map_err(io)?;
    Ok(())
}

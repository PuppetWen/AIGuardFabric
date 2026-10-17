//! Existing runtime only. Key is environment-only and diagnostics never echo child stderr.
use super::{
    fail,
    owned::{Owned, plain},
};
use agf_core::error::DomainResult;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub(super) fn executable(name: &str) -> DomainResult<PathBuf> {
    let supplied = PathBuf::from(std::env::var_os(name).ok_or_else(|| fail("explicit runtime ENV required"))?);
    if !supplied.is_absolute() || !supplied.is_file() {
        return Err(fail("existing absolute runtime file required"));
    }
    let resolved = supplied.canonicalize().map_err(|_| fail("runtime resolution"))?;
    // NVM links are allowed only for the read-only tool binary, never SDK/source/data.
    let text = resolved.to_string_lossy().replace('\\', "/").trim_start_matches("//?/").to_ascii_lowercase();
    if !text.starts_with("d:/environment/") && !text.starts_with("e:/environment/") {
        return Err(fail("runtime outside existing Environment"));
    }
    Ok(supplied)
}
pub(super) fn command(program: PathBuf, owned: &Owned, directory: &Path) -> DomainResult<Command> {
    plain(directory)?;
    let mut command = Command::new(program);
    command
        .current_dir(directory)
        .env("AGF_ZERO_CODE_SDK_ROOT", &owned.sdk)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env_remove("AGF_TEST_DATABASE_URL")
        .env_remove("AGF_MASTER_KEY_BASE64")
        .env_remove("AGF_JWT_SECRET")
        .env_remove("PYTHONPATH")
        .env_remove("PYTHONHOME")
        .env_remove("NODE_OPTIONS");
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        command.env_remove(name);
    }
    command
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(command)
}
pub(super) async fn run(mut command: Command, key: Option<&str>, business: bool) -> DomainResult<Value> {
    let mut child = command.spawn().map_err(|_| fail("existing child runtime spawn"))?;
    let stdout = child.stdout.take().ok_or_else(|| fail("child stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| fail("child stderr"))?;
    let output = tokio::spawn(capture(stdout));
    let errors = tokio::spawn(capture(stderr));
    let status = match tokio::time::timeout(Duration::from_secs(45), child.wait()).await {
        Ok(result) => result.map_err(|_| fail("child wait"))?,
        Err(_) => {
            // Reap the process before outer cleanup can touch its files.
            let _ = child.kill().await;
            output.abort();
            errors.abort();
            let _ = output.await;
            let _ = errors.await;
            return Err(fail("child deadline"));
        }
    };
    let stdout = output.await.map_err(|_| fail("child stdout join"))??;
    let stderr = errors.await.map_err(|_| fail("child stderr join"))??;
    if stdout.len() > 64 * 1024 || stderr.len() > 64 * 1024 {
        return Err(fail("bounded child output"));
    }
    if let Some(key) = key {
        assert!(!stdout.windows(key.len()).any(|b| b == key.as_bytes()));
        assert!(!stderr.windows(key.len()).any(|b| b == key.as_bytes()));
    }
    if business {
        assert!(status.success(), "original business child exit must remain success");
    } else {
        let diagnostic: Value = stderr
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice(line).ok())
            .next_back()
            .unwrap_or(Value::Null);
        // Counts and fixed error classes only; never print a child body or arbitrary string.
        let pending = diagnostic["pending"].as_u64();
        let quarantined = diagnostic["quarantined"].as_u64();
        let active = diagnostic["delivery_active"].as_bool();
        let error = match diagnostic["last_error"].as_str().or(diagnostic["error"].as_str()) {
            Some("network_error") => "network_error",
            Some("invalid_ack") => "invalid_ack",
            Some("collector_startup_failed") => "collector_startup_failed",
            Some("delivery_storage_failed") => "delivery_storage_failed",
            Some(_) => "other_fixed_class",
            None => "none",
        };
        assert!(
            status.success(),
            "explicit queue-only maintenance must finish successfully: exit={:?}, pending={pending:?}, quarantined={quarantined:?}, active={active:?}, error={error}",
            status.code()
        );
    }
    // Python drain diagnostics use stderr; Node drain uses stdout. Never surface raw diagnostic text.
    let bytes = if stdout.is_empty() { &stderr } else { &stdout };
    let line = bytes.split(|b| *b == b'\n').rfind(|line| !line.is_empty()).ok_or_else(|| fail("child JSON absent"))?;
    serde_json::from_slice(line).map_err(|_| fail("safe child JSON shape"))
}
async fn capture(stream: impl tokio::io::AsyncRead + Unpin) -> DomainResult<Vec<u8>> {
    let mut bytes = Vec::new();
    stream.take(65_537).read_to_end(&mut bytes).await.map_err(|_| fail("child bounded pipe"))?;
    Ok(bytes)
}

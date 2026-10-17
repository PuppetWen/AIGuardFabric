//! 真实 CLI 入口拒绝明文与脚本，副作用只可能由明确已批准的 PE/ELF 启动产生。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{fs, path::Path, process::Command};
#[test]
fn explicit_process_commands_exist_and_plaintext_observation_fails_before_any_kernel_or_wmi_activation() {
    let help = Command::new(env!("CARGO_BIN_EXE_agf-agent")).arg("--help").output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("process-observe") && help.contains("process-run"));
    let output = Command::new(env!("CARGO_BIN_EXE_agf-agent"))
        .args([
            "process-observe",
            "--server",
            "http://127.0.0.1:1",
            "--agent-id",
            "11111111-1111-4111-8111-111111111111",
            "--seconds",
            "1",
            "--limit",
            "1",
        ])
        .env("AGF_AGENT_TOKEN", "agf_owned_fixture")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("verified HTTPS"));
}
#[test]
fn managed_cli_never_implicitly_executes_a_shell_script_or_its_argument_side_effect() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-data/process-hook-cli");
    fs::create_dir_all(&parent).unwrap();
    let dir = tempfile::tempdir_in(parent).unwrap();
    let script = dir.path().join("owned-never-run.cmd");
    fs::write(&script, b"@echo unexpected > side-effect.marker\r\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agf-agent"))
        .args([
            "process-run",
            "--server",
            "https://localhost:1",
            "--agent-id",
            "11111111-1111-4111-8111-111111111111",
            "--executable",
        ])
        .arg(&script)
        .args(["--", "&", "owned-never-run"])
        .env("AGF_AGENT_TOKEN", "agf_owned_fixture")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!dir.path().join("side-effect.marker").exists());
}

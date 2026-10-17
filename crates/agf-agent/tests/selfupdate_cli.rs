//! 使用临时安装根及独占环回套接字，验证真实 CLI 准入及恢复路径。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_agent::{
    ReleaseAsset, ReleaseManifest, platform,
    selfupdate::{TrustedReleaseKey, release_signing_payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use std::{fs, path::Path, process::Command, time::Duration};
mod selfupdate_heartbeat;
fn temporary_root() -> tempfile::TempDir {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-data/selfupdate-cli");
    fs::create_dir_all(&parent).unwrap();
    tempfile::tempdir_in(parent).unwrap()
}
fn inputs(dir: &Path, url: &str, real_signature: bool) {
    let key = SigningKey::from_bytes(&[73_u8; 32]);
    let mut manifest = ReleaseManifest {
        version: "99.0.0".into(),
        notes: None,
        rollout_percent: 100,
        assets: vec![ReleaseAsset {
            platform: platform::current().as_str().into(),
            arch: platform::current_arch().into(),
            url: url.into(),
            sha256: agf_agent::selfupdate::sha256_hex(b"payload"),
            size: 7,
        }],
        signature: None,
    };
    let signature = key.sign(&release_signing_payload(&manifest).unwrap());
    manifest.signature = Some(if real_signature {
        format!("ed25519-v1:operator-fixture:{}", STANDARD.encode(signature.to_bytes()))
    } else {
        "ed25519-v1:operator-fixture:present-but-forged".into()
    });
    fs::write(dir.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
    fs::write(
        dir.join("trusted.json"),
        serde_json::to_vec(&TrustedReleaseKey {
            key_id: "operator-fixture".into(),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        })
        .unwrap(),
    )
    .unwrap();
    fs::write(dir.join("agent-fixture.exe"), b"previous-owned-fixture").unwrap();
}
fn apply(dir: &Path, origin: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agf-agent"));
    command
        .arg("apply-update")
        .arg("--manifest")
        .arg(dir.join("manifest.json"))
        .arg("--trusted-key")
        .arg(dir.join("trusted.json"))
        .arg("--install-root")
        .arg(dir)
        .args([
            "--target-name",
            "agent-fixture.exe",
            "--current",
            "1.0.0",
            "--agent-id",
            "cli-fixture",
            "--origin",
            origin,
        ]);
    command
}
#[test]
fn explicit_cli_rejects_signature_presence_before_creating_any_update_transaction() {
    let dir = temporary_root();
    inputs(dir.path(), "https://localhost:1/artifact", false);
    let output = apply(dir.path(), "https://localhost:1").output().unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(dir.path().join("agent-fixture.exe")).unwrap(), b"previous-owned-fixture");
    assert!(!dir.path().join(".agf-updates").exists());
    let help = Command::new(env!("CARGO_BIN_EXE_agf-agent")).arg("--help").output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("apply-update") && help.contains("recover-update"));
}
#[tokio::test]
async fn actual_cli_rejects_non_run_before_connecting_or_creating_update_history() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let dir = temporary_root();
    inputs(dir.path(), &format!("{origin}/artifact"), true);
    let mut command = apply(dir.path(), &origin);
    command.args(["--", "mcp-proxy"]);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap()).await.unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("only the run subcommand"));
    assert!(!dir.path().join(".agf-updates").exists());
    assert_eq!(fs::read(dir.path().join("agent-fixture.exe")).unwrap(), b"previous-owned-fixture");
    assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_cli_https_failure_retains_old_bytes_and_recovers_same_prepared_journal_without_redownload() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await.unwrap().unwrap();
        let mut first = [0_u8; 1];
        socket.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], 22, "The actual updater sent a TLS handshake, never plaintext HTTP");
    });
    let dir = temporary_root();
    let origin = format!("https://127.0.0.1:{port}");
    inputs(dir.path(), &format!("{origin}/artifact"), true);
    let path = dir.path().to_owned();
    let output = tokio::task::spawn_blocking(move || apply(&path, &origin).output().unwrap()).await.unwrap();
    peer.await.unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(dir.path().join("agent-fixture.exe")).unwrap(), b"previous-owned-fixture");
    let entries = fs::read_dir(dir.path().join(".agf-updates")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(entries.len(), 1);
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(entries[0].path().join("journal.json")).unwrap()).unwrap();
    let transaction = journal["transaction"].as_str().unwrap();
    let recovered = Command::new(env!("CARGO_BIN_EXE_agf-agent"))
        .arg("recover-update")
        .arg("--install-root")
        .arg(dir.path())
        .args(["--target-name", "agent-fixture.exe", "--transaction", transaction])
        .output()
        .unwrap();
    assert!(recovered.status.success(), "A failed download leaves an attributable prepared transaction");
    let receipt: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(receipt["transaction"], transaction);
    assert_eq!(receipt["status"], "prepared");
    assert_eq!(fs::read(dir.path().join("agent-fixture.exe")).unwrap(), b"previous-owned-fixture");
}

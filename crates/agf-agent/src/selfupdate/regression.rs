//! 真实文件与进程回归只使用临时安装目录及本测试持有的子进程。
use super::*;
use crate::platform;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use std::{fs, path::Path, time::Duration};
pub(super) fn temporary_root() -> tempfile::TempDir {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-data/selfupdate");
    fs::create_dir_all(&parent).unwrap();
    tempfile::tempdir_in(parent).unwrap()
}

pub(super) fn signed(bytes: &[u8], url: &str) -> (ReleaseManifest, TrustedReleaseKey, DownloadPolicy) {
    let key = SigningKey::from_bytes(&[41_u8; 32]);
    let anchor =
        TrustedReleaseKey { key_id: "fixture-key".into(), public_key_hex: hex::encode(key.verifying_key().to_bytes()) };
    let mut manifest = ReleaseManifest {
        version: "99.0.0".into(),
        notes: None,
        rollout_percent: 100,
        assets: vec![ReleaseAsset {
            platform: platform::current().as_str().into(),
            arch: platform::current_arch().into(),
            url: url.into(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
        }],
        signature: None,
    };
    resign(&mut manifest);
    let policy = DownloadPolicy {
        allowed_origins: vec![reqwest::Url::parse(url).unwrap().origin().ascii_serialization()],
        enterprise_ca: None,
        max_bytes: journal::MAX_FILE,
    };
    (manifest, anchor, policy)
}
fn resign(manifest: &mut ReleaseManifest) {
    let signature = SigningKey::from_bytes(&[41_u8; 32]).sign(&release_signing_payload(manifest).unwrap());
    manifest.signature = Some(format!("ed25519-v1:fixture-key:{}", STANDARD.encode(signature.to_bytes())));
}
pub(super) fn verified(bytes: &[u8]) -> VerifiedUpdate {
    let (manifest, anchor, policy) = signed(bytes, "https://releases.example.invalid/agent");
    verify_release(
        &manifest,
        &anchor,
        policy,
        "owned-fixture-agent",
        "1.0.0",
        platform::current(),
        platform::current_arch(),
    )
    .unwrap()
    .expect("Signed eligible fixture")
}
fn root(dir: &Path) -> InstallRoot {
    fs::write(dir.join("agent-fixture.exe"), b"previous-owned-fixture").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("agent-fixture.exe"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    InstallRoot::new(dir, "agent-fixture.exe").unwrap()
}
fn stage(root: InstallRoot, bytes: &[u8]) -> StagedUpdate {
    let value = StagedUpdate::begin(root, &verified(bytes)).unwrap();
    fs::write(value.candidate().unwrap(), bytes).unwrap();
    value.prepared().unwrap();
    value
}
#[test]
fn independently_pinned_key_and_every_signed_field_are_enforced_before_eligibility() {
    let (original, anchor, policy) = signed(b"payload", "https://releases.example.invalid/agent");
    let verify = |value: &ReleaseManifest, key: &TrustedReleaseKey| {
        verify_release(value, key, policy.clone(), "fixture", "1.0.0", platform::current(), platform::current_arch())
    };
    assert!(verify(&original, &anchor).unwrap().is_some());
    let mut bad_key = anchor.clone();
    bad_key.public_key_hex = hex::encode(SigningKey::from_bytes(&[42_u8; 32]).verifying_key().to_bytes());
    assert!(verify(&original, &bad_key).is_err());
    for field in ["url", "sha", "size", "version", "rollout"] {
        let mut changed = original.clone();
        match field {
            "url" => changed.assets[0].url.push_str("/changed"),
            "sha" => changed.assets[0].sha256 = "0".repeat(64),
            "size" => changed.assets[0].size += 1,
            "version" => changed.version = "100.0.0".into(),
            _ => changed.rollout_percent = 0,
        }
        assert!(verify(&changed, &anchor).is_err(), "Unauthenticated field {field} was trusted");
    }
    let mut missing = original.clone();
    missing.signature = None;
    assert!(verify(&missing, &anchor).is_err());
    let mut fake = original.clone();
    fake.signature = Some("present-is-not-authentic".into());
    assert!(verify(&fake, &anchor).is_err());
    assert!(
        plan_update("1.0.0", &original, platform::current(), platform::current_arch())
            .unwrap()
            .unwrap()
            .requires_manual_approval
    );
}
#[test]
fn authenticated_rollout_origins_size_and_duplicate_selectors_fail_closed() {
    let (mut manifest, anchor, policy) = signed(b"payload", "https://releases.example.invalid/agent");
    let verify = |value: &ReleaseManifest| {
        verify_release(
            value,
            &anchor,
            policy.clone(),
            "fixture",
            "1.0.0",
            platform::current(),
            platform::current_arch(),
        )
    };
    manifest.rollout_percent = 0;
    resign(&mut manifest);
    assert!(verify(&manifest).unwrap().is_none());
    manifest.rollout_percent = 101;
    resign(&mut manifest);
    assert!(verify(&manifest).is_err());
    manifest.rollout_percent = 100;
    manifest.assets[0].size = 0;
    resign(&mut manifest);
    assert!(verify(&manifest).is_err());
    manifest.assets[0].size = 7;
    manifest.assets[0].url = "http://releases.example.invalid/agent".into();
    resign(&mut manifest);
    assert!(verify(&manifest).is_err());
    manifest.assets[0].url = "https://other.example.invalid/agent".into();
    resign(&mut manifest);
    assert!(verify(&manifest).is_err());
    manifest.assets[0].url = "https://releases.example.invalid/agent".into();
    manifest.assets.push(manifest.assets[0].clone());
    resign(&mut manifest);
    assert!(verify(&manifest).is_err());
    for percent in [0, 1, 50, 99, 100] {
        assert_eq!(rollout_selected("same-agent", percent), rollout_selected("same-agent", percent));
    }
    assert!(!rollout_selected("same-agent", 0));
    assert!(rollout_selected("same-agent", 100));
}
#[tokio::test]
async fn public_updater_rejects_non_run_before_network_or_transaction_creation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let (manifest, anchor, policy) = signed(b"payload", &format!("{origin}/artifact"));
    let update =
        verify_release(&manifest, &anchor, policy, "fixture", "1.0.0", platform::current(), platform::current_arch())
            .unwrap()
            .unwrap();
    for arguments in [Vec::new(), vec!["mcp-proxy".into()], vec!["collect".into()]] {
        let dir = temporary_root();
        let root = root(dir.path());
        assert!(download_and_apply(&update, root.clone(), &arguments).await.is_err());
        assert!(!root.root.join(".agf-updates").exists());
        assert_eq!(fs::read(&root.target).unwrap(), b"previous-owned-fixture");
    }
    assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());
}
#[test]
fn crash_after_atomic_replace_recovers_original_transaction_and_verified_previous_bytes() {
    let dir = temporary_root();
    let root = root(dir.path());
    let mut staged = stage(root.clone(), b"candidate-owned-fixture");
    let tx = staged.fact.transaction;
    staged.replace(0).unwrap();
    assert_eq!(fs::read(&root.target).unwrap(), b"candidate-owned-fixture");
    // 模拟原子改名完成、最终事务状态落盘之前发生崩溃。
    staged.fact.phase = journal::Phase::Replacing;
    journal::save(&root, &staged.fact).unwrap();
    drop(staged);
    let recovered = recover_update(root.clone(), tx).unwrap();
    assert_eq!(recovered.status, "rolled_back");
    assert_eq!(fs::read(&root.target).unwrap(), b"previous-owned-fixture");
    assert_eq!(recover_update(root, tx).unwrap().transaction, tx);
}
#[test]
fn malformed_or_oversized_health_evidence_cannot_block_expired_transaction_rollback() {
    for evidence in [Vec::new(), b"{broken".to_vec(), vec![b'x'; 65537]] {
        let dir = temporary_root();
        let root = root(dir.path());
        let mut staged = stage(root.clone(), b"candidate-owned-fixture");
        staged.replace(0).unwrap();
        let transaction = staged.fact.transaction;
        let heartbeat = journal::tx_dir(&root, transaction).unwrap().join("heartbeat.json");
        fs::write(&heartbeat, evidence).unwrap();
        assert!(!health::valid(&root, &staged.fact).unwrap());
        assert_eq!(fs::read(&root.target).unwrap(), b"candidate-owned-fixture");
        drop(staged);
        let recovered = recover_update(root.clone(), transaction).unwrap();
        assert_eq!(recovered.status, "rolled_back");
        assert_eq!(recovered.transaction, transaction);
        assert_eq!(fs::read(&root.target).unwrap(), b"previous-owned-fixture");
        assert_eq!(recover_update(root, transaction).unwrap().status, "rolled_back");
    }
}
#[test]
fn concurrent_update_changed_target_and_corrupt_backup_never_overwrite_unattributed_bytes() {
    let dir = temporary_root();
    let root = root(dir.path());
    let mut staged = stage(root.clone(), b"candidate-owned-fixture");
    assert!(StagedUpdate::begin(root.clone(), &verified(b"another")).is_err());
    fs::write(&root.target, b"external-change").unwrap();
    assert!(staged.replace(0).is_err());
    assert_eq!(fs::read(&root.target).unwrap(), b"external-change");
    fs::write(&root.target, b"previous-owned-fixture").unwrap();
    staged.replace(0).unwrap();
    fs::write(journal::tx_dir(&root, staged.fact.transaction).unwrap().join("previous"), b"corrupt-backup").unwrap();
    let tx = staged.fact.transaction;
    drop(staged);
    assert!(recover_update(root.clone(), tx).is_err());
    assert_eq!(fs::read(&root.target).unwrap(), b"candidate-owned-fixture");
    assert_eq!(journal::load(&root, tx).unwrap().phase, journal::Phase::RollbackPending);
}
#[test]
fn invalid_root_traversal_current_image_and_journal_identity_are_rejected() {
    let dir = temporary_root();
    let root = root(dir.path());
    assert!(InstallRoot::new(dir.path(), "../agent-fixture.exe").is_err());
    let own = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    assert!(InstallRoot::new(own.parent().unwrap(), own.file_name().unwrap().to_str().unwrap()).is_err());
    let staged = stage(root.clone(), b"candidate");
    let tx = staged.fact.transaction;
    let mut corrupt = staged.fact.clone();
    corrupt.target_name = "outside.exe".into();
    journal::save(&root, &corrupt).unwrap();
    drop(staged);
    assert!(recover_update(root, tx).is_err());
}
#[cfg(windows)]
#[test]
fn windows_occupied_image_is_refused_without_stopping_the_owner() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = temporary_root();
    let root = root(dir.path());
    let handle = fs::OpenOptions::new().read(true).share_mode(0).open(&root.target).unwrap();
    assert!(root.idle().is_err());
    drop(handle);
    assert!(root.idle().is_ok());
}
#[cfg(unix)]
#[test]
fn symlinked_install_root_and_journal_are_refused() {
    let dir = temporary_root();
    let root = root(dir.path());
    let linked = dir.path().join("linked");
    std::os::unix::fs::symlink(dir.path(), &linked).unwrap();
    assert!(InstallRoot::new(&linked, "agent-fixture.exe").is_err());
    let staged = stage(root.clone(), b"candidate");
    let tx = staged.fact.transaction;
    let journal_path = journal::tx_dir(&root, tx).unwrap().join("journal.json");
    fs::rename(&journal_path, journal_path.with_extension("original")).unwrap();
    std::os::unix::fs::symlink(journal_path.with_extension("original"), &journal_path).unwrap();
    drop(staged);
    assert!(recover_update(root, tx).is_err());
}
#[test]
#[ignore = "Owned child fixture; invoked only by the supervised update regression"]
fn supervised_child_healthy() {
    arm_update_watchdog().unwrap();
    assert!(acknowledge_platform_heartbeat().unwrap());
    std::thread::sleep(Duration::from_millis(350));
}
#[test]
#[ignore = "Owned child fixture; invoked only by the supervised update regression"]
fn supervised_child_no_health() {
    arm_update_watchdog().unwrap();
    std::thread::sleep(Duration::from_secs(5));
}
fn child_invalid_health(evidence: &[u8]) {
    arm_update_watchdog().unwrap();
    let root = std::path::PathBuf::from(std::env::var_os(health::ENV_ROOT).unwrap());
    let transaction = uuid::Uuid::parse_str(&std::env::var(health::ENV_TX).unwrap()).unwrap();
    let heartbeat = root.join(".agf-updates").join(transaction.to_string()).join("heartbeat.json");
    fs::write(heartbeat, evidence).unwrap();
    std::thread::sleep(Duration::from_secs(5));
}
#[test]
#[ignore = "Owned child fixture; invoked only by the supervised update regression"]
fn supervised_child_malformed_health() {
    child_invalid_health(b"{broken");
}
#[test]
#[ignore = "Owned child fixture; invoked only by the supervised update regression"]
fn supervised_child_oversized_health() {
    child_invalid_health(&vec![b'x'; 65537]);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_owned_child_health_confirms_and_failed_startup_rolls_back_without_touching_other_processes() {
    let executable = fs::read(std::env::current_exe().unwrap()).unwrap();
    for (helper, expected) in [
        ("supervised_child_healthy", "confirmed"),
        ("supervised_child_no_health", "rolled_back"),
        ("supervised_child_malformed_health", "rolled_back"),
        ("supervised_child_oversized_health", "rolled_back"),
    ] {
        let dir = temporary_root();
        let root = root(dir.path());
        let mut staged = stage(root.clone(), &executable);
        let args = vec![
            "--exact".into(),
            format!("selfupdate::regression::{helper}"),
            "--ignored".into(),
            "--nocapture".into(),
        ];
        let window = if expected == "confirmed" { Duration::from_secs(5) } else { Duration::from_millis(400) };
        let receipt = supervisor::supervise(&mut staged, &args, window).await.unwrap();
        assert_eq!(receipt.status, expected);
        drop(staged);
        for _ in 0..30 {
            if root.idle().is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(root.idle().is_ok(), "Owned helper must exit before removing its temporary root");
        assert_eq!(recover_update(root, receipt.transaction).unwrap().status, expected);
    }
    let dir = temporary_root();
    let root = root(dir.path());
    let mut staged = stage(root.clone(), b"not-an-executable");
    let receipt = supervisor::supervise(&mut staged, &[], Duration::from_millis(100)).await.unwrap();
    assert_eq!(receipt.status, "rolled_back");
    assert_eq!(fs::read(root.target).unwrap(), b"previous-owned-fixture");
}

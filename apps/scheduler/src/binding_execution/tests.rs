//! Actual file streaming, no outcome paths or free-form diagnostics cross the protocol.
use crate::{TaskOutcome, callback_binding::artifacts};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
struct Owned {
    base: PathBuf,
    path: PathBuf,
    owner: String,
}
fn plain(path: &Path) {
    for path in path.ancestors() {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            assert_eq!(metadata.file_attributes() & 0x400, 0);
        }
    }
}
impl Owned {
    fn open() -> Self {
        let base = std::env::var_os("AGF_SCHEDULER_CALLBACK_TEST_DIR")
            .map_or_else(|| std::env::temp_dir().join("scheduler-callback-validation"), PathBuf::from);
        assert!(base.is_absolute());
        std::fs::create_dir_all(&base).unwrap();
        plain(&base);
        let owner = format!("scheduler-callback-artifacts-{}", uuid::Uuid::new_v4());
        let path = base.join(&owner);
        std::fs::create_dir(&path).unwrap();
        let mut marker = std::fs::OpenOptions::new().write(true).create_new(true).open(path.join("owner.txt")).unwrap();
        marker.write_all(owner.as_bytes()).unwrap();
        Self { base, path, owner }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        plain(&self.path);
        assert!(self.path.starts_with(&self.base));
        assert_eq!(self.path.file_name().unwrap().to_str().unwrap(), self.owner);
        assert_eq!(std::fs::read_to_string(self.path.join("owner.txt")).unwrap(), self.owner);
        for name in ["report.txt", "outside.txt", "owner.txt"] {
            let file = self.path.join(name);
            if file.exists() {
                plain(&file);
                assert!(file.is_file());
                std::fs::remove_file(file).unwrap();
            }
        }
        std::fs::remove_dir(&self.path).unwrap();
    }
}
#[tokio::test]
async fn owned_artifacts_are_streamed_to_exact_digest_and_never_send_local_path_or_note() {
    let owned = Owned::open();
    let report = owned.path.join("report.txt");
    let bytes = b"owned report\n";
    std::fs::write(&report, bytes).unwrap();
    let mut result = TaskOutcome::ok("private-secret-note");
    result.artifacts.push(report.to_string_lossy().into_owned());
    let safe = artifacts::summarize(&result, std::slice::from_ref(&owned.path)).await.unwrap();
    assert_eq!(safe.artifacts.len(), 1);
    assert_eq!(safe.artifacts[0].bytes, bytes.len() as u64);
    assert_eq!(safe.artifacts[0].sha256, format!("{:x}", Sha256::digest(bytes)));
    let serialized = serde_json::to_string(&safe).unwrap();
    assert!(!serialized.contains("private-secret-note"));
    assert!(!serialized.contains("report.txt"));
}
#[tokio::test]
async fn outside_root_or_skipped_artifact_never_becomes_a_known_completion() {
    let owned = Owned::open();
    let outside = owned.path.join("outside.txt");
    std::fs::write(&outside, b"outside").unwrap();
    let mut result = TaskOutcome::ok("done");
    result.artifacts.push(outside.to_string_lossy().into_owned());
    assert!(artifacts::summarize(&result, &[]).await.is_err());
    result.skipped = true;
    assert!(artifacts::summarize(&result, std::slice::from_ref(&owned.path)).await.is_err());
}

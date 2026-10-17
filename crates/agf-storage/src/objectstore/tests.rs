//! 由 `objectstore.rs` 拆分：`temp_store` 等 8 个函数（纯搬移，逻辑不变）。

use std::path::Path;

use super::*;

pub(crate) fn temp_store() -> LocalFileObjectStore {
    let dir = std::env::temp_dir().join(format!("agf-obj-{}", uuid::Uuid::new_v4()));
    LocalFileObjectStore::new(&dir).unwrap_or_else(|_| unreachable!())
}

#[test]
pub(crate) fn key_validation_blocks_traversal() {
    assert!(validate_key("evidence/2026/03/x.json").is_ok());
    assert!(validate_key("../etc/passwd").is_err());
    assert!(validate_key("a/../../b").is_err());
    assert!(validate_key("/abs/path").is_err());
    assert!(validate_key("C:/windows/x").is_err());
    assert!(validate_key("").is_err());
}

#[test]
pub(crate) fn local_resolve_stays_inside_root() {
    let s = temp_store();
    let ok = s.resolve("a/b/c.txt");
    assert!(ok.is_ok());
    assert!(s.resolve("../escape.txt").is_err());
}

#[test]
pub(crate) fn content_hash_is_deterministic() {
    assert_eq!(content_hash(b"hello"), content_hash(b"hello"));
    assert_ne!(content_hash(b"hello"), content_hash(b"hell0"));
    assert_eq!(content_hash(b"").len(), 64);
}

#[tokio::test]
pub(crate) async fn memory_store_crud_roundtrip() {
    let s = MemoryObjectStore::new();
    let stored = s.put("evidence/1.txt", b"payload", Some("text/plain")).await;
    assert!(stored.is_ok());
    let Ok(stored) = stored else { return };
    assert_eq!(stored.size, 7);
    assert_eq!(stored.backend, "memory");
    assert_eq!(s.get("evidence/1.txt").await.ok(), Some(b"payload".to_vec()));
    assert_eq!(s.exists("evidence/1.txt").await.ok(), Some(true));
    assert_eq!(s.list("evidence/", 10).await.ok().map(|v| v.len()), Some(1));
    assert!(s.delete("evidence/1.txt").await.is_ok());
    assert_eq!(s.exists("evidence/1.txt").await.ok(), Some(false));
    assert_eq!(s.len().ok(), Some(0));
    assert!(s.get("missing").await.is_err());
    assert!(s.put("../evil", b"x", None).await.is_err());
}

#[tokio::test]
pub(crate) async fn local_store_crud_roundtrip() {
    let s = temp_store();
    let Ok(stored) = s.put("a/b.txt", b"data", None).await else { return };
    assert_eq!(stored.backend, "local");
    assert_eq!(s.get("a/b.txt").await.ok(), Some(b"data".to_vec()));
    assert!(s.exists("a/b.txt").await.ok().unwrap_or(false));
    assert_eq!(s.list("a/", 10).await.ok(), Some(vec!["a/b.txt".to_string()]));
    let url = s.presign_get("a/b.txt", 60).await;
    assert!(url.map(|u| u.starts_with("file://")).unwrap_or(false));
    assert!(s.delete("a/b.txt").await.is_ok());
    assert!(s.delete("a/b.txt").await.is_ok(), "删除不存在的对象应幂等");
    assert!(s.health().await.is_ok());
}

#[test]
pub(crate) fn normalize_path_handles_parent() {
    let p = normalize_path(Path::new("/root/a/../b"));
    assert!(p.to_string_lossy().replace('\\', "/").ends_with("root/b"));
}

#[tokio::test]
pub(crate) async fn build_object_store_falls_back_to_local_without_s3() {
    let cfg = crate::StorageConfig {
        data_dir: std::env::temp_dir().join(format!("agf-os-{}", uuid::Uuid::new_v4())),
        ..crate::StorageConfig::default()
    };
    let (store, note) = build_object_store(&cfg).await;
    assert_eq!(store.backend(), "local");
    assert!(note.unwrap_or_default().contains("本地文件系统"));
}

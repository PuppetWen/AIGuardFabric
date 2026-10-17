//! 由 `objectstore.rs` 拆分：`impl_MemoryObjectStore`/`impl_MemoryObjectStore` 等 5 项（纯搬移，逻辑不变）。
use super::*;

use crate::StorageConfig;
use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use async_trait::async_trait;
use std::collections::BTreeMap;
use tracing::{info, warn};

impl MemoryObjectStore {
    /// 新建空存储。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前对象数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn len(&self) -> DomainResult<usize> {
        self.objects.lock().map(|m| m.len()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    /// 是否为空。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn is_empty(&self) -> DomainResult<bool> {
        self.len().map(|n| n == 0)
    }
}

#[async_trait]
impl ObjectStore for MemoryObjectStore {
    fn backend(&self) -> &'static str {
        "memory"
    }

    fn is_available(&self) -> bool {
        true
    }

    async fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> DomainResult<StoredObject> {
        validate_key(key)?;
        let mut map = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.insert(key.to_string(), (data.to_vec(), content_type.map(ToString::to_string)));
        Ok(StoredObject {
            key: key.to_string(),
            size: data.len() as u64,
            content_type: content_type.map(ToString::to_string),
            content_hash: content_hash(data),
            backend: "memory".to_string(),
            stored_at: Timestamp::now(),
            metadata: BTreeMap::new(),
        })
    }

    async fn get(&self, key: &str) -> DomainResult<Vec<u8>> {
        let map = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.get(key)
            .map(|(d, _)| d.clone())
            .ok_or_else(|| DomainError::NotFound { entity: "memory-object", id: key.to_string() })
    }

    async fn exists(&self, key: &str) -> DomainResult<bool> {
        let map = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.contains_key(key))
    }

    async fn delete(&self, key: &str) -> DomainResult<()> {
        let mut map = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str, limit: usize) -> DomainResult<Vec<String>> {
        let map = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.keys().filter(|k| k.starts_with(prefix)).take(limit).cloned().collect())
    }

    async fn presign_get(&self, key: &str, _expires_secs: u64) -> DomainResult<String> {
        Ok(format!("memory://{key}"))
    }

    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// 依据配置选择对象存储实现。
///
/// 规则：S3 配置齐全 → S3（并在可用时确保桶存在）；否则 → 本地目录
/// `<data_dir>/objects`。**永不失败**，保证平台在无对象存储时仍可启动。
#[must_use]
pub fn select_object_store(cfg: &StorageConfig) -> std::sync::Arc<dyn ObjectStore> {
    if !cfg.s3_endpoint.is_empty() && !cfg.s3_access_key.is_empty() && !cfg.s3_secret_key.is_empty() {
        // S3 的构造是 async，这里用阻塞运行时不可取；由调用方在 async 上下文中
        // 显式调用 `S3ObjectStore::from_config`。本函数只做"能同步决定的降级"。
        warn!("S3 已配置，但对象存储需要异步初始化；请调用 build_object_store().await");
    }
    let fallback = cfg.data_dir.join("objects");
    match LocalFileObjectStore::new(&fallback) {
        Ok(s) => {
            info!(root = %fallback.display(), "对象存储使用本地文件系统（如需 S3/OSS 请配置 AGF_S3_*，或调用 build_object_store）");
            std::sync::Arc::new(s)
        }
        Err(e) => {
            warn!(error = %e, "本地对象存储目录创建失败，降级为内存实现（重启后数据丢失）");
            std::sync::Arc::new(MemoryObjectStore::new())
        }
    }
}

/// 异步构建对象存储（首选入口）：优先 S3，失败则本地，再失败则内存。
#[must_use]
pub async fn build_object_store(cfg: &StorageConfig) -> (std::sync::Arc<dyn ObjectStore>, Option<String>) {
    if !cfg.s3_endpoint.is_empty() && !cfg.s3_access_key.is_empty() && !cfg.s3_secret_key.is_empty() {
        match S3ObjectStore::from_config(cfg).await {
            Ok(s3) => match s3.ensure_bucket().await {
                Ok(()) => return (std::sync::Arc::new(s3), None),
                Err(e) => {
                    let note = format!("S3 桶不可用（{e}），已降级为本地文件系统");
                    warn!("{note}");
                    let fallback = cfg.data_dir.join("objects");
                    if let Ok(local) = LocalFileObjectStore::new(&fallback) {
                        return (std::sync::Arc::new(local), Some(note));
                    }
                    return (std::sync::Arc::new(MemoryObjectStore::new()), Some(note));
                }
            },
            Err(e) => {
                let note = format!("S3 初始化失败（{e}），已降级为本地文件系统");
                warn!("{note}");
                let fallback = cfg.data_dir.join("objects");
                if let Ok(local) = LocalFileObjectStore::new(&fallback) {
                    return (std::sync::Arc::new(local), Some(note));
                }
                return (std::sync::Arc::new(MemoryObjectStore::new()), Some(note));
            }
        }
    }
    let note = "未配置 AGF_S3_*，使用本地文件系统存储（离线可演示；生产建议接 OSS/S3）".to_string();
    let fallback = cfg.data_dir.join("objects");
    match LocalFileObjectStore::new(&fallback) {
        Ok(local) => (std::sync::Arc::new(local), Some(note)),
        Err(_) => (std::sync::Arc::new(MemoryObjectStore::new()), Some(note)),
    }
}

/// 把证据包打包为 base64（供 API 直接返回小证据）。
#[must_use]
pub fn encode_base64(data: &[u8]) -> String {
    B64.encode(data)
}

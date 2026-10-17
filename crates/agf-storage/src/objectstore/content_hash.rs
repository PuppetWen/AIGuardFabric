//! 由 `objectstore.rs` 拆分：`content_hash`/`validate_key` 等 7 项（纯搬移，逻辑不变）。
use super::*;

use crate::StorageConfig;
use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// 计算内容哈希（SHA-256 hex）。
#[must_use]
pub fn content_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 校验对象键安全性（禁止绝对路径与 `..`，防路径穿越写入）。
///
/// # Errors
/// 键非法时返回 [`DomainError::Validation`]。
pub fn validate_key(key: &str) -> DomainResult<()> {
    if key.is_empty() || key.len() > 1024 {
        return Err(DomainError::Validation("对象键长度非法".to_string()));
    }
    if key.starts_with('/') || key.starts_with('\\') || key.contains(':') {
        return Err(DomainError::Validation(format!("对象键不得为绝对路径: {key}")));
    }
    for seg in key.split(['/', '\\']) {
        if seg == ".." || seg.is_empty() && key.contains("//") {
            return Err(DomainError::Validation(format!("对象键不得包含空段或 ..: {key}")));
        }
    }
    if key.contains('\0') {
        return Err(DomainError::Validation("对象键不得包含 NUL".to_string()));
    }
    Ok(())
}

impl S3ObjectStore {
    /// 依据配置构造。
    ///
    /// # Errors
    /// 配置缺失或 SDK 初始化失败。
    pub async fn from_config(cfg: &StorageConfig) -> DomainResult<Self> {
        if cfg.s3_endpoint.is_empty() || cfg.s3_access_key.is_empty() || cfg.s3_secret_key.is_empty() {
            return Err(DomainError::Config(
                "S3 未配置（需要 AGF_S3_ENDPOINT / AGF_S3_ACCESS_KEY / AGF_S3_SECRET_KEY）".to_string(),
            ));
        }
        let creds = aws_sdk_s3::config::Credentials::new(
            cfg.s3_access_key.clone(),
            cfg.s3_secret_key.clone(),
            None,
            None,
            "aiguardfabric-static",
        );
        let mut builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(cfg.s3_region.clone()))
            .credentials_provider(creds)
            .force_path_style(cfg.s3_force_path_style);
        if !cfg.s3_endpoint.is_empty() {
            builder = builder.endpoint_url(cfg.s3_endpoint.clone());
        }
        let client = aws_sdk_s3::Client::from_conf(builder.build());
        info!(endpoint = %cfg.s3_endpoint, bucket = %cfg.s3_bucket, "S3 对象存储就绪");
        Ok(Self { client, bucket: cfg.s3_bucket.clone(), endpoint: cfg.s3_endpoint.clone() })
    }

    /// 桶名。
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// 端点。
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// 确保桶存在（幂等）。
    ///
    /// # Errors
    /// 创建失败。
    pub async fn ensure_bucket(&self) -> DomainResult<()> {
        match self.client.head_bucket().bucket(&self.bucket).send().await {
            Ok(_) => Ok(()),
            Err(_) => {
                self.client.create_bucket().bucket(&self.bucket).send().await.map_err(|e| {
                    DomainError::DependencyUnavailable {
                        dependency: "s3".to_string(),
                        cause: format!("创建桶 {} 失败: {e}", self.bucket),
                    }
                })?;
                info!(bucket = %self.bucket, "已创建对象存储桶");
                Ok(())
            }
        }
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    fn backend(&self) -> &'static str {
        "s3"
    }

    fn is_available(&self) -> bool {
        !self.endpoint.is_empty()
    }

    async fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> DomainResult<StoredObject> {
        validate_key(key)?;
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(data.to_vec()));
        if let Some(ct) = content_type {
            req = req.content_type(ct);
        }
        req.send().await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "s3".to_string(),
            cause: format!("上传 {key} 失败: {e}"),
        })?;
        debug!(key, bytes = data.len(), "对象已上传");
        Ok(StoredObject {
            key: key.to_string(),
            size: data.len() as u64,
            content_type: content_type.map(ToString::to_string),
            content_hash: content_hash(data),
            backend: "s3".to_string(),
            stored_at: Timestamp::now(),
            metadata: BTreeMap::new(),
        })
    }

    async fn get(&self, key: &str) -> DomainResult<Vec<u8>> {
        validate_key(key)?;
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| DomainError::NotFound { entity: "s3-object", id: format!("{key}: {e}") })?;
        let bytes =
            out.body.collect().await.map_err(|e| DomainError::Internal(format!("读取对象流失败: {e}")))?.into_bytes();
        Ok(bytes.to_vec())
    }

    async fn exists(&self, key: &str) -> DomainResult<bool> {
        validate_key(key)?;
        match self.client.head_object().bucket(&self.bucket).key(key).send().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn delete(&self, key: &str) -> DomainResult<()> {
        validate_key(key)?;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| DomainError::Internal(format!("删除对象 {key} 失败: {e}")))?;
        Ok(())
    }

    async fn list(&self, prefix: &str, limit: usize) -> DomainResult<Vec<String>> {
        let out = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .max_keys(i32::try_from(limit).unwrap_or(1000))
            .send()
            .await
            .map_err(|e| DomainError::Internal(format!("列出对象失败: {e}")))?;
        Ok(out.contents().iter().filter_map(|o| o.key().map(ToString::to_string)).collect())
    }

    async fn presign_get(&self, key: &str, expires_secs: u64) -> DomainResult<String> {
        validate_key(key)?;
        let cfg =
            aws_sdk_s3::presigning::PresigningConfig::expires_in(std::time::Duration::from_secs(expires_secs.max(1)))
                .map_err(|e| DomainError::Internal(format!("预签名配置非法: {e}")))?;
        let req = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(cfg)
            .await
            .map_err(|e| DomainError::Internal(format!("生成预签名 URL 失败: {e}")))?;
        Ok(req.uri().to_string())
    }

    async fn health(&self) -> DomainResult<()> {
        self.client.head_bucket().bucket(&self.bucket).send().await.map(|_| ()).map_err(|e| {
            DomainError::DependencyUnavailable {
                dependency: "s3".to_string(), cause: format!("head_bucket 失败: {e}")
            }
        })
    }
}

impl LocalFileObjectStore {
    /// 在指定根目录下创建（目录不存在会自动创建）。
    ///
    /// # Errors
    /// 目录创建失败。
    pub fn new(root: impl AsRef<Path>) -> DomainResult<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .map_err(|e| DomainError::Internal(format!("创建对象存储目录 {} 失败: {e}", root.display())))?;
        Ok(Self { root })
    }

    /// 根目录。
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 把对象键解析为受限于根目录的绝对路径（防穿越）。
    ///
    /// # Errors
    /// 键非法或解析后逃出根目录。
    pub fn resolve(&self, key: &str) -> DomainResult<PathBuf> {
        validate_key(key)?;
        let path = self.root.join(key);
        let normalized = normalize_path(&path);
        if !normalized.starts_with(normalize_path(&self.root)) {
            return Err(DomainError::Validation(format!("对象键逃出存储根目录: {key}")));
        }
        Ok(path)
    }
}

/// 归一化路径（去掉 `.` 与 `..`，不做文件系统访问）。
pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[async_trait]
impl ObjectStore for LocalFileObjectStore {
    fn backend(&self) -> &'static str {
        "local"
    }

    fn is_available(&self) -> bool {
        true
    }

    async fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> DomainResult<StoredObject> {
        let path = self.resolve(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| DomainError::Internal(format!("创建目录失败: {e}")))?;
        }
        let mut file =
            tokio::fs::File::create(&path).await.map_err(|e| DomainError::Internal(format!("创建文件失败: {e}")))?;
        file.write_all(data).await.map_err(|e| DomainError::Internal(format!("写入失败: {e}")))?;
        file.flush().await.map_err(|e| DomainError::Internal(format!("刷盘失败: {e}")))?;
        debug!(key, bytes = data.len(), "对象已写入本地存储");
        Ok(StoredObject {
            key: key.to_string(),
            size: data.len() as u64,
            content_type: content_type.map(ToString::to_string),
            content_hash: content_hash(data),
            backend: "local".to_string(),
            stored_at: Timestamp::now(),
            metadata: BTreeMap::new(),
        })
    }

    async fn get(&self, key: &str) -> DomainResult<Vec<u8>> {
        let path = self.resolve(key)?;
        tokio::fs::read(&path)
            .await
            .map_err(|e| DomainError::NotFound { entity: "local-object", id: format!("{key}: {e}") })
    }

    async fn exists(&self, key: &str) -> DomainResult<bool> {
        Ok(self.resolve(key)?.exists())
    }

    async fn delete(&self, key: &str) -> DomainResult<()> {
        let path = self.resolve(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DomainError::Internal(format!("删除失败: {e}"))),
        }
    }

    async fn list(&self, prefix: &str, limit: usize) -> DomainResult<Vec<String>> {
        let root = self.root.clone();
        let prefix = prefix.to_string();
        tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            let walker = walkdir::WalkDir::new(&root).into_iter().filter_map(Result::ok);
            for entry in walker {
                if !entry.file_type().is_file() {
                    continue;
                }
                let Ok(rel) = entry.path().strip_prefix(&root) else { continue };
                let key = rel.to_string_lossy().replace('\\', "/");
                if key.starts_with(&prefix) {
                    out.push(key);
                    if out.len() >= limit {
                        break;
                    }
                }
            }
            out.sort();
            out
        })
        .await
        .map_err(|e| DomainError::Internal(format!("遍历对象目录失败: {e}")))
    }

    async fn presign_get(&self, key: &str, _expires_secs: u64) -> DomainResult<String> {
        let path = self.resolve(key)?;
        Ok(format!("file://{}", path.display()))
    }

    async fn health(&self) -> DomainResult<()> {
        if self.root.exists() {
            Ok(())
        } else {
            Err(DomainError::DependencyUnavailable {
                dependency: "local-object-store".to_string(),
                cause: format!("目录不存在: {}", self.root.display()),
            })
        }
    }
}

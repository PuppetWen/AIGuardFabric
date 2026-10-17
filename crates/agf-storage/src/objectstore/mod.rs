//! 对象存储：证据包、原始日志归档、报表产物（§4.5 冷存储、§4.6 证据包）。
//!
//! 提供统一 [`ObjectStore`] trait 与三个实现：
//! - [`S3ObjectStore`]：MinIO / 阿里云 OSS / AWS S3（S3 兼容协议）；
//! - [`LocalFileObjectStore`]：本地文件系统（离线开发与气隙环境的默认降级）；
//! - [`MemoryObjectStore`]：进程内（单元测试）。
//!
//! `new()` 工厂按配置自动选择：S3 配置齐全 → S3；否则 → 本地目录。
//! **降级不失败**：这是"平台永远可启动"承诺的一部分。

use std::collections::BTreeMap;

use std::path::PathBuf;

use agf_core::error::DomainResult;

use agf_core::time::Timestamp;

use async_trait::async_trait;

use base64::Engine;

use base64::engine::general_purpose::STANDARD as B64;

use serde::{Deserialize, Serialize};

use tokio::io::AsyncWriteExt;

#[allow(unused_imports)]
pub use content_hash::*;
#[allow(unused_imports)]
pub use impl_memory_object_store::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 存储对象元数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    /// 对象键（相对路径，不含桶名）。
    pub key: String,
    /// 字节数。
    pub size: u64,
    /// 内容类型。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// 内容 SHA-256（防篡改与去重）。
    pub content_hash: String,
    /// 存储后端标识（`s3` / `local` / `memory`）。
    pub backend: String,
    /// 写入时间。
    pub stored_at: Timestamp,
    /// 自定义元数据。
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// 对象存储统一接口。
#[async_trait]
pub trait ObjectStore: Send + Sync + std::fmt::Debug {
    /// 后端名。
    fn backend(&self) -> &'static str;

    /// 是否可用（配置齐全）。
    fn is_available(&self) -> bool;

    /// 上传对象。
    ///
    /// # Errors
    /// 写入失败。
    async fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> DomainResult<StoredObject>;

    /// 下载对象。
    ///
    /// # Errors
    /// 对象不存在或读取失败。
    async fn get(&self, key: &str) -> DomainResult<Vec<u8>>;

    /// 对象是否存在。
    ///
    /// # Errors
    /// 探测失败。
    async fn exists(&self, key: &str) -> DomainResult<bool>;

    /// 删除对象。
    ///
    /// # Errors
    /// 删除失败。
    async fn delete(&self, key: &str) -> DomainResult<()>;

    /// 列出前缀下的对象。
    ///
    /// # Errors
    /// 列出失败。
    async fn list(&self, prefix: &str, limit: usize) -> DomainResult<Vec<String>>;

    /// 生成访问 URL。
    ///
    /// S3 返回预签名 URL；本地实现返回 `file://` 路径（前端不可直接用，
    /// 由 `agf-api` 提供带鉴权的下载代理接口）。
    ///
    /// # Errors
    /// 生成失败（如 S3 未配置签名密钥）。
    async fn presign_get(&self, key: &str, expires_secs: u64) -> DomainResult<String>;

    /// 健康探测。
    ///
    /// # Errors
    /// 后端不可达。
    async fn health(&self) -> DomainResult<()>;
}

// ---------------------------------------------------------------------------
// S3 / MinIO
// ---------------------------------------------------------------------------

/// S3 兼容对象存储（MinIO / OSS / AWS S3）。
#[derive(Debug)]
pub struct S3ObjectStore {
    client: aws_sdk_s3::Client,
    bucket: String,
    endpoint: String,
}

// ---------------------------------------------------------------------------
// 本地文件系统（离线降级）
// ---------------------------------------------------------------------------

/// 本地文件系统对象存储。
///
/// 用于开发机与气隙环境：`AGF_DATA_DIR/objects/<key>`。
#[derive(Debug)]
pub struct LocalFileObjectStore {
    root: PathBuf,
}

// ---------------------------------------------------------------------------
// 内存实现（测试）
// ---------------------------------------------------------------------------

/// 内存对象表：`键 → (内容, 内容类型)`。
///
/// 抽成别名是为了满足 clippy 的 `type_complexity`（复杂类型应命名）。
pub type MemoryObjects = std::sync::Mutex<BTreeMap<String, (Vec<u8>, Option<String>)>>;

/// 进程内对象存储（单元测试与端到端回放）。
#[derive(Debug, Default)]
pub struct MemoryObjectStore {
    objects: MemoryObjects,
}

mod content_hash;
mod impl_memory_object_store;
#[cfg(test)]
mod tests;

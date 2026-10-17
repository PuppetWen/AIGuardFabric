//! 幂等游标：对象指纹 `ObjectStamp` 与 `ObjectCursor`（ETag 去重 + 游标落盘/恢复）。

use super::*;

/// 单个对象的"已处理指纹"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStamp {
    /// 已处理的 ETag。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// 已处理的 LastModified。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// 已处理的字节数。
    pub size: u64,
}

impl ObjectStamp {
    /// 由元数据构造。
    #[must_use]
    pub fn from_meta(meta: &ObjectMeta) -> Self {
        Self { etag: meta.etag.clone(), last_modified: meta.last_modified.clone(), size: meta.size }
    }
}

/// 幂等游标：`key → 已处理指纹`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectCursor {
    /// 版本号（便于将来演进时识别旧文件）。
    #[serde(default)]
    pub version: u32,
    /// 已处理对象。
    #[serde(default)]
    pub objects: BTreeMap<String, ObjectStamp>,
}

impl ObjectCursor {
    /// 空游标（版本号 1）。
    #[must_use]
    pub fn new() -> Self {
        Self { version: 1, objects: BTreeMap::new() }
    }

    /// 已处理对象数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// 该对象是否需要拉取（新对象或 ETag 变化）。
    ///
    /// 判定顺序：**ETag 优先**（内容指纹），后端不给 ETag 时退化为 `(LastModified, size)`。
    #[must_use]
    pub fn needs_pull(&self, meta: &ObjectMeta) -> bool {
        let Some(previous) = self.objects.get(&meta.key) else {
            return true;
        };
        if let (Some(old), Some(new)) = (previous.etag.as_ref(), meta.etag.as_ref()) {
            return old != new;
        }
        if previous.last_modified.is_some() || meta.last_modified.is_some() {
            return previous.last_modified != meta.last_modified || previous.size != meta.size;
        }
        previous.size != meta.size
    }

    /// 标记对象已处理。
    pub fn mark(&mut self, meta: &ObjectMeta) {
        self.objects.insert(meta.key.clone(), ObjectStamp::from_meta(meta));
    }

    /// 从磁盘加载（文件不存在/损坏 ⇒ 空游标 + warn，绝不因此让进程起不来）。
    #[must_use]
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(cursor) => cursor,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "对象拉取游标文件损坏，按空游标继续（会重新拉取，不丢数据）");
                    Self::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "对象拉取游标文件不可读，按空游标继续");
                Self::new()
            }
        }
    }

    /// 原子写盘（先写 `.tmp` 再 rename；rename 覆盖已存在文件是 std 的既有语义）。
    ///
    /// # Errors
    /// 目录创建或写入失败。
    pub fn save(&self, path: &Path) -> DomainResult<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| DomainError::Internal(format!("创建游标目录 {} 失败: {e}", parent.display())))?;
            }
        }
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| DomainError::Internal(format!("序列化对象拉取游标失败: {e}")))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &body).map_err(|e| DomainError::Internal(format!("写入 {} 失败: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| DomainError::Internal(format!("游标落盘 {} 失败: {e}", path.display())))?;
        Ok(())
    }
}

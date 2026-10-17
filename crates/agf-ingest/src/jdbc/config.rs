//! 拉取配置与游标落盘：`SqlPullConfig`（表/游标列/单轮上限）与 `SqlCursorFile`。
//!

use super::*;

/// 拉取配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlPullConfig {
    /// 基础查询（不含游标谓词/排序/上限，由接收器拼装）。
    pub sql: String,
    /// 游标列（`None`/空 = 全量拉取，每轮拉到相同的头部若干行）。
    pub cursor_field: Option<String>,
    /// 游标列类型。
    pub cursor_type: CursorType,
    /// 单轮最多行数。
    pub batch_limit: usize,
    /// 轮询间隔（秒）。
    pub interval_secs: u64,
    /// 游标文件（`None` = 只存内存）。
    pub cursor_path: Option<PathBuf>,
}

impl Default for SqlPullConfig {
    fn default() -> Self {
        Self {
            sql: String::new(),
            cursor_field: None,
            cursor_type: CursorType::Int,
            batch_limit: 500,
            interval_secs: 60,
            cursor_path: None,
        }
    }
}

impl SqlPullConfig {
    /// 由日志源配置构造（`connection.sql` / `connection.cursor_field` / `poll_interval_secs`）。
    ///
    /// # Errors
    /// 未配置 `connection.sql`。
    pub fn from_source(source: &LogSource) -> DomainResult<Self> {
        let sql = source
            .connection
            .sql
            .clone()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| DomainError::Config("SQL 拉取需要 connection.sql".to_string()))?;
        Ok(Self {
            sql,
            cursor_field: source.connection.cursor_field.clone(),
            interval_secs: u64::try_from(source.poll_interval_secs.unwrap_or(60).max(1)).unwrap_or(60),
            ..Self::default()
        })
    }
}

/// 游标文件内容（单值，带版本号便于演进）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SqlCursorFile {
    /// 版本号。
    #[serde(default)]
    pub version: u32,
    /// 已拉取到的游标值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl SqlCursorFile {
    /// 从磁盘加载（缺失/损坏 ⇒ 无游标 + warn，不阻塞启动）。
    #[must_use]
    pub fn load(path: &Path) -> Option<String> {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(file) => file.cursor,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "SQL 拉取游标文件损坏，按无游标继续（会重拉，不丢数据）");
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "SQL 拉取游标文件不可读，按无游标继续");
                None
            }
        }
    }

    /// 原子写盘。
    ///
    /// # Errors
    /// 目录创建或写入失败。
    pub fn save(path: &Path, cursor: Option<&str>) -> DomainResult<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| DomainError::Internal(format!("创建游标目录 {} 失败: {e}", parent.display())))?;
            }
        }
        let body = serde_json::to_vec_pretty(&Self { version: 1, cursor: cursor.map(ToString::to_string) })
            .map_err(|e| DomainError::Internal(format!("序列化 SQL 拉取游标失败: {e}")))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &body).map_err(|e| DomainError::Internal(format!("写入 {} 失败: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path).map_err(|e| DomainError::Internal(format!("游标落盘失败: {e}")))?;
        Ok(())
    }
}

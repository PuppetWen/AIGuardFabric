//! 分区级 offset 游标 `KafkaCursor`（落盘/恢复/损坏容忍）与分区运行态快照 `KafkaPartitionState`。

use super::*;

/// 游标文件（`topic/partition → 下一个 offset`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KafkaCursor {
    /// 版本号。
    #[serde(default)]
    pub version: u32,
    /// 本地游标命名空间（Pulsar subscription / Kafka group.id；只作标注与一致性校验）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// `"{topic}/{partition}" → next offset`。
    #[serde(default)]
    pub offsets: BTreeMap<String, i64>,
}

impl KafkaCursor {
    /// 键（**每个分区独立游标**）。
    #[must_use]
    pub fn key(topic: &str, partition: i32) -> String {
        format!("{topic}/{partition}")
    }

    /// 从磁盘加载（缺失/损坏 ⇒ 空游标 + warn）。
    #[must_use]
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(cursor) => cursor,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Kafka 游标文件损坏，按空游标继续（会重放，不丢数据）");
                    Self { version: 1, namespace: None, offsets: BTreeMap::new() }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self { version: 1, namespace: None, offsets: BTreeMap::new() }
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Kafka 游标文件不可读，按空游标继续");
                Self { version: 1, namespace: None, offsets: BTreeMap::new() }
            }
        }
    }

    /// 原子写盘。
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
            .map_err(|e| DomainError::Internal(format!("序列化 Kafka 游标失败: {e}")))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &body).map_err(|e| DomainError::Internal(format!("写入 {} 失败: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path).map_err(|e| DomainError::Internal(format!("游标落盘失败: {e}")))?;
        Ok(())
    }

    /// 从**分区分片游标目录**合并加载（多副本模式）：扫描 `{prefix}{partition}.json` 并合并 offsets。
    ///
    /// 缺失目录/空目录 ⇒ 空游标（与 [`Self::load`] 同语义：重放而不是丢弃）。
    #[must_use]
    pub fn load_sharded(dir: &Path, prefix: &str) -> Self {
        let mut cursor = Self { version: 1, namespace: None, offsets: BTreeMap::new() };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return cursor;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(prefix) || !name.ends_with(".json") {
                continue;
            }
            let shard = Self::load(&entry.path());
            if cursor.namespace.is_none() {
                cursor.namespace.clone_from(&shard.namespace);
            }
            cursor.offsets.extend(shard.offsets);
        }
        cursor
    }

    /// 把**单个分区**的游标写进分区分片文件（多副本模式；只有该分区的 owner 会写它）。
    ///
    /// # Errors
    /// 目录创建或写入失败。
    pub fn save_shard(
        &self,
        dir: &Path,
        prefix: &str,
        topic: &str,
        partition: i32,
        next_offset: i64,
    ) -> DomainResult<()> {
        let shard = Self {
            version: 1,
            namespace: self.namespace.clone(),
            offsets: BTreeMap::from([(Self::key(topic, partition), next_offset)]),
        };
        shard.save(&dir.join(format!("{prefix}{partition}.json")))
    }
}

// ---------------------------------------------------------------------------
// 分区状态与指标
// ---------------------------------------------------------------------------

/// 单个分区的运行状态（`/stats` 直接渲染）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaPartitionState {
    /// 分区号。
    pub partition: i32,
    /// **本副本是否负责该分区**（多副本分配时由 [`PartitionOwnership`] 决定；单副本恒为 `true`）。
    ///
    /// `false` 的行只有归属信息：`next_offset`/`high_watermark`/`lag` 均为 `-1`
    /// （**`-1` = 未知，不由本副本负责**，不是"滞后为负"）。
    #[serde(default)]
    pub owned: bool,
    /// 该分区当前归属的副本序号。
    #[serde(default)]
    pub owner_instance: u32,
    /// 归属计算用到的存活副本集合（升序；单副本 = `[0]`）。
    #[serde(default)]
    pub live_instances: Vec<u32>,
    /// 本地游标：下一个待消费 offset。
    pub next_offset: i64,
    /// broker 高水位（下一个将被写入的 offset）。
    pub high_watermark: i64,
    /// 滞后 = 高水位 − 游标（不小于 0）。
    pub lag: i64,
    /// 最近一轮消费记录数。
    pub records: u64,
    /// 累计消费记录数。
    pub records_total: u64,
    /// 最近一次成功时间（epoch 毫秒）。
    pub last_success_ms: Option<i64>,
    /// 连续失败次数（成功即清零）。
    pub consecutive_failures: u32,
    /// 累计失败次数。
    pub failures_total: u64,
    /// 最近一次失败原因（**脱敏**：不含凭据）。
    pub last_error: Option<String>,
}

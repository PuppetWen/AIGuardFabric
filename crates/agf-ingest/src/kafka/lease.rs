//! 分区归属与实例租约：分区 → 实例的确定性映射、心跳租约文件写入/读取，以及 `PartitionOwnership` 接管语义。

use super::*;

/// 由**存活副本集合**计算某分区的归属（纯函数，确定性）。
///
/// 规则：存活副本序号**升序去重**后 `owner(p) = live[p % live.len()]`。
///
/// 语义（与 Kafka 消费者组的区别，如实）：
/// * 所有副本对同一 `live` 集合算出**同一个** owner ⇒ 一个分区**同时只有一个**消费者；
/// * 副本数变化 = **全量重分片**（不是"只接管死者的分区"）：`live` 少一个成员时，
///   原来属于它的分区按同一公式落到存活副本上 ⇒ **不会留下无主分区**；
/// * 代价：副本增减会让**部分存活副本**的分区也换手一次（rebalance 抖动），
///   这与 Kafka 的 range/cooperative 分配同类，但**没有** generation fence，
///   因此依赖"租约判活"把重叠窗口压到 `lease_ttl_ms` 以内（见 [`KafkaPullConfig::lease_ttl_ms`]）。
#[must_use]
pub fn partition_owner(partition: i32, live: &[u32]) -> Option<u32> {
    if live.is_empty() || partition < 0 {
        return None;
    }
    let index = usize::try_from(partition).ok()? % live.len();
    live.get(index).copied()
}

/// 归一化存活副本集合：去重 + 升序（**所有副本必须得到同一顺序**，否则会算出不同 owner）。
#[must_use]
pub fn normalize_live(mut live: Vec<u32>) -> Vec<u32> {
    live.sort_unstable();
    live.dedup();
    live
}

/// 租约心跳文件名（按**订阅名**隔离：只有同订阅名的副本才会互相接管）。
pub(super) fn lease_path(dir: &Path, namespace: &str, instance_id: u32) -> PathBuf {
    dir.join(format!("agf-ingest-{}.instance-{instance_id}.hb", sanitize_component(namespace)))
}

/// 文件名安全化（只保留 `[A-Za-z0-9._-]`，其余替换为 `_`）。
///
/// 用于租约心跳与分区分片游标文件名：订阅名/topic 里可能含 `/` `:`（例如 Pulsar 的
/// `persistent://tenant/ns/topic`），不能直接进文件名。
#[must_use]
pub fn sanitize_component(value: &str) -> String {
    value.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect()
}

/// 心跳正文：`instance_id ts_ms pid host`（一行，纯文本，便于排障时直接 cat）。
fn lease_heartbeat_body(instance_id: u32, now_ms: i64) -> String {
    let host = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).unwrap_or_else(|_| "-".to_string());
    format!("{instance_id} {now_ms} {} {host}\n", std::process::id())
}

/// 心跳里的存活时间戳（解析失败/文件不存在 = `None`）。
fn lease_read_timestamp(path: &Path) -> Option<(u32, i64)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let id: u32 = parts.next()?.parse().ok()?;
    let ts: i64 = parts.next()?.parse().ok()?;
    Some((id, ts))
}

/// 写一次心跳（**原子**：临时文件 + rename，避免副本读到半行）。
///
/// # Errors
/// 目录创建失败或写盘失败。
pub fn lease_write_heartbeat(dir: &Path, namespace: &str, instance_id: u32) -> DomainResult<PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| {
        DomainError::Config(format!("租约目录 {} 不可用（多副本接管需要所有副本可见的共享目录）: {e}", dir.display()))
    })?;
    let path = lease_path(dir, namespace, instance_id);
    let tmp = path.with_extension("hb.tmp");
    std::fs::write(&tmp, lease_heartbeat_body(instance_id, now_millis()))
        .map_err(|e| DomainError::Config(format!("写租约心跳 {} 失败: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &path).map_err(|e| DomainError::Config(format!("提交租约心跳失败: {e}")))?;
    Ok(path)
}

/// 读租约目录，返回 `(存活副本集合[含自己], 目录里出现过的全部副本序号)`。
///
/// 判活：`now - ts <= ttl_ms`。自己**永远算存活**（本进程正在跑）。
/// 目录不可读时返回 `(vec![me], vec![me])` 并由调用方回落到静态取模（见 [`KafkaPullConfig::lease_dir`]）。
#[must_use]
pub fn lease_live_instances(dir: &Path, namespace: &str, ttl_ms: u64, me: u32) -> (Vec<u32>, Vec<u32>) {
    let now = now_millis();
    let ttl = i64::try_from(ttl_ms).unwrap_or(i64::MAX);
    let prefix = format!("agf-ingest-{}.instance-", sanitize_component(namespace));
    let mut live = vec![me];
    let mut seen = vec![me];
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (live, seen);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) || !name.ends_with(".hb") {
            continue;
        }
        let Some((id, ts)) = lease_read_timestamp(&entry.path()) else {
            continue;
        };
        if !seen.contains(&id) {
            seen.push(id);
        }
        if id == me || now.saturating_sub(ts) <= ttl {
            if !live.contains(&id) {
                live.push(id);
            }
        }
    }
    (normalize_live(live), normalize_live(seen))
}

/// 一次分配决策的结果（每轮消费前重算；也是 `/stats`、`/metrics` 的归属来源）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionOwnership {
    /// 是否启用了多副本分配（关闭时 `owned` = topic 全部分区）。
    pub enabled: bool,
    /// 是否启用了租约接管（关闭 = 纯静态取模）。
    pub leased: bool,
    /// 本副本序号。
    pub instance_id: u32,
    /// 配置的副本总数。
    pub instance_count: u32,
    /// 本轮判活的副本序号（升序；含自己）。
    pub live_instances: Vec<u32>,
    /// 是否因租约目录不可读而回落到静态取模（此时**不接管**，只按 `instance_id % instance_count` 分片）。
    pub degraded: bool,
    /// 是否处于**启动静默期**（只写心跳、只观测，不认领任何分区）。
    ///
    /// 静默期内 `owned_partitions` 恒为空：这样"两个副本同时启动"不会出现
    /// "先起来的那一个先把全部分区都端走"的重叠窗口（见
    /// [`KafkaPullConfig::assign_settle_ms`]）。
    pub settling: bool,
    /// 租约判活时长（毫秒；接管时间上界的主要项）。
    pub lease_ttl_ms: u64,
    /// topic 的全部分区号（升序）。
    pub partitions: Vec<i32>,
    /// 本副本负责的分区（升序）。
    pub owned_partitions: Vec<i32>,
    /// 本轮**新接管**的分区（上一轮不属于自己）。
    pub taken_over_partitions: Vec<i32>,
    /// 归属：分区号 → 副本序号（`-1` = 无主：存活集合为空等异常态）。
    pub owners: BTreeMap<i32, u32>,
}

impl PartitionOwnership {
    /// 本副本是否负责该分区。
    #[must_use]
    pub fn owns(&self, partition: i32) -> bool {
        self.owned_partitions.binary_search(&partition).is_ok()
    }

    /// 某分区的归属副本序号（`None` = 无主）。
    #[must_use]
    pub fn owner_of(&self, partition: i32) -> Option<u32> {
        self.owners.get(&partition).copied()
    }

    /// 由配置 + 存活集合 + topic 分区列表算出归属（纯函数，便于单测与"两个副本算得一致"的断言）。
    ///
    /// `previous_owners`：上一轮的归属表（用于判定"新接管了哪些分区"）；
    /// `settling`：启动静默期 ⇒ 清空认领列表（仍如实给出 `owners` 供观测）。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn compute(
        config: &KafkaPullConfig,
        all_partitions: &[i32],
        live: &[u32],
        seen: &[u32],
        degraded: bool,
        previous_owners: &BTreeMap<i32, u32>,
    ) -> Self {
        Self::compute_with_settle(config, all_partitions, live, seen, degraded, previous_owners, false)
    }

    /// 同 [`Self::compute`]，但可显式指定是否处于启动静默期。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn compute_with_settle(
        config: &KafkaPullConfig,
        all_partitions: &[i32],
        live: &[u32],
        seen: &[u32],
        degraded: bool,
        previous_owners: &BTreeMap<i32, u32>,
        settling: bool,
    ) -> Self {
        let (me, count) = config.assignment_identity();
        let enabled = config.assignment_enabled();
        let leased = config.lease_enabled() && !degraded;
        let mut partitions = all_partitions.to_vec();
        partitions.sort_unstable();
        partitions.dedup();
        // 不启用多副本分配时：静态 owner = 自己，全部分区归自己（与历史行为一致）。
        let live_set: Vec<u32> = if !enabled {
            vec![me]
        } else if leased {
            // 租约模式下：**同时**把租约目录里出现过的副本也算进来（哪怕已判死），
            // 它们的分区会按存活集合重分片到存活者身上。
            let mut set = normalize_live(live.to_vec());
            if set.is_empty() {
                set.push(me);
            }
            if !set.contains(&me) {
                set.push(me);
                set = normalize_live(set);
            }
            let _ = seen;
            set
        } else {
            // 静态取模（含租约目录不可读的降级态）：候选 = 配置的 0..count
            (0..count).collect()
        };
        let mut owners = BTreeMap::new();
        let mut owned = Vec::new();
        let mut taken = Vec::new();
        for partition in &partitions {
            let owner = partition_owner(*partition, &live_set).unwrap_or(me);
            owners.insert(*partition, owner);
            if owner == me {
                owned.push(*partition);
                if previous_owners.get(partition).is_some_and(|prev| *prev != me) {
                    taken.push(*partition);
                }
            }
        }
        // 启动静默期：把"认领"清空（还能观测到 owners/live，但本轮不消费、不推进游标）
        if settling {
            owned.clear();
            taken.clear();
        }
        Self {
            enabled,
            leased,
            instance_id: me,
            instance_count: count,
            live_instances: live_set,
            degraded,
            settling,
            lease_ttl_ms: config.lease_ttl_ms,
            partitions,
            owned_partitions: owned,
            taken_over_partitions: taken,
            owners,
        }
    }
}

// ---------------------------------------------------------------------------
// 游标
// ---------------------------------------------------------------------------

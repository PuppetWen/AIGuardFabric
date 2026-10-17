//! 组内分区分配与 rebalance 判据：**全部是纯函数**（无 IO、无锁），因此可以离线逐条断言。
//!
//! ## 为什么客户端要实现分配器
//!
//! Kafka 的组协调器**不做**分区分配：它只负责成员管理（JoinGroup/SyncGroup/心跳/代际号），
//! 真正的分配由**组长（leader，协调器在 JoinGroup 响应里指定）**在 SyncGroup 里下发给全体成员。
//! 因此客户端必须实现至少一个分配器，否则组协议闭环不成立。这里实现两个标准策略：
//!
//! | 策略 | 语义 | 与 Java 客户端的一致性 |
//! |---|---|---|
//! | [`GroupAssignor::Range`] | 每个 topic 单独切分：订阅者按 `member_id` 排序，前 `p % n` 个成员各多分 1 个分区；分区是**连续区间** | 等价 `RangeAssignor` |
//! | [`GroupAssignor::RoundRobin`] | 把"全部 topic 的全部分区"按 `(topic, partition)` 排序后**轮转发牌**，跳过未订阅该 topic 的成员 | 等价 `RoundRobinAssignor` |
//!
//! 两者都保证：**同一分区只分给一个成员**（无重叠）、**所有被订阅的分区都分出去**（无遗漏）——
//! 这两条不变量由单测逐条覆盖（含"成员数 > 分区数"与"分区数变化"）。

use super::*;

/// 分配策略（对应 Kafka 的 `partition.assignment.strategy`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupAssignor {
    /// 区间分配（Kafka `RangeAssignor`）：每 topic 独立切分，分区连续。
    #[default]
    Range,
    /// 轮转分配（Kafka `RoundRobinAssignor`）：跨 topic 统一轮转。
    RoundRobin,
}

impl GroupAssignor {
    /// 协议名（JoinGroup 的 `protocols[].name`；必须与 Java 客户端同名才会被协调器认同）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Range => "range",
            Self::RoundRobin => "roundrobin",
        }
    }

    /// 解析文本（`range` / `roundrobin` / `round-robin`）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "range" => Some(Self::Range),
            "roundrobin" => Some(Self::RoundRobin),
            _ => None,
        }
    }
}

/// 一个组内成员及其订阅的 topic 列表（从 JoinGroup 请求的 member metadata 解出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// 协调器分配的成员 id。
    pub member_id: String,
    /// 订阅的 topic（去重后按字典序）。
    pub topics: Vec<String>,
}

impl GroupMember {
    /// 构造（topic 去重 + 排序，保证分配结果与成员上报顺序无关）。
    #[must_use]
    pub fn new(member_id: impl Into<String>, topics: impl IntoIterator<Item = String>) -> Self {
        let mut topics: Vec<String> = topics.into_iter().collect();
        topics.sort();
        topics.dedup();
        Self { member_id: member_id.into(), topics }
    }
}

/// 分配结果：`member_id → [(topic, partition)]`（每个成员的列表按 `(topic, partition)` 升序）。
pub type AssignmentPlan = BTreeMap<String, Vec<(String, i32)>>;

/// 计算组内分配（组长在 JoinGroup 之后、SyncGroup 之前调用）。
///
/// `topic_partitions` = **全体成员订阅的 topic 并集** → 该 topic 的全部分区（来自 Metadata）。
/// 未在 `topic_partitions` 里出现的 topic 视为"暂无分区"（不分配，也不报错——topic 可能刚被创建）。
#[must_use]
pub fn assign_partitions(
    strategy: GroupAssignor,
    members: &[GroupMember],
    topic_partitions: &BTreeMap<String, Vec<i32>>,
) -> AssignmentPlan {
    match strategy {
        GroupAssignor::Range => assign_range(members, topic_partitions),
        GroupAssignor::RoundRobin => assign_round_robin(members, topic_partitions),
    }
}

/// `RangeAssignor` 语义：**每个 topic 独立切分**。
///
/// 对某 topic 的 `p` 个分区与 `n` 个订阅者：前 `p % n` 个（按 `member_id` 排序）各拿 `p/n + 1` 个，
/// 其余各拿 `p/n` 个；分区是**按分区号升序的连续区间**。
fn assign_range(members: &[GroupMember], topic_partitions: &BTreeMap<String, Vec<i32>>) -> AssignmentPlan {
    let mut plan: AssignmentPlan = members.iter().map(|m| (m.member_id.clone(), Vec::new())).collect();
    let mut sorted: Vec<&GroupMember> = members.iter().collect();
    sorted.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    for (topic, partitions) in topic_partitions {
        let mut partitions = partitions.clone();
        partitions.sort_unstable();
        let subscribers: Vec<&GroupMember> =
            sorted.iter().copied().filter(|member| member.topics.contains(topic)).collect();
        if subscribers.is_empty() || partitions.is_empty() {
            continue;
        }
        let count = subscribers.len();
        let per_member = partitions.len() / count;
        let extra = partitions.len() % count;
        let mut cursor = 0_usize;
        for (index, member) in subscribers.iter().enumerate() {
            let take = per_member + usize::from(index < extra);
            if let Some(entry) = plan.get_mut(&member.member_id) {
                for partition in &partitions[cursor..cursor + take] {
                    entry.push((topic.clone(), *partition));
                }
            }
            cursor += take;
        }
    }
    for entry in plan.values_mut() {
        entry.sort();
    }
    plan
}

/// `RoundRobinAssignor` 语义：全部 topic 的全部分区统一排序后**轮转发牌**，
/// 遇到未订阅该 topic 的成员就跳到下一个（最多绕一圈，避免死循环）。
fn assign_round_robin(members: &[GroupMember], topic_partitions: &BTreeMap<String, Vec<i32>>) -> AssignmentPlan {
    let mut plan: AssignmentPlan = members.iter().map(|m| (m.member_id.clone(), Vec::new())).collect();
    let mut sorted: Vec<&GroupMember> = members.iter().collect();
    sorted.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    if sorted.is_empty() {
        return plan;
    }
    let mut all: Vec<(String, i32)> = Vec::new();
    for (topic, partitions) in topic_partitions {
        let mut partitions = partitions.clone();
        partitions.sort_unstable();
        for partition in partitions {
            all.push((topic.clone(), partition));
        }
    }
    all.sort();
    let mut cursor = 0_usize;
    for (topic, partition) in all {
        // 最多尝试 `sorted.len()` 次：一定存在订阅者（topic 来自成员订阅的并集）
        for _ in 0..sorted.len() {
            let member = sorted[cursor % sorted.len()];
            cursor += 1;
            if member.topics.contains(&topic) {
                if let Some(entry) = plan.get_mut(&member.member_id) {
                    entry.push((topic.clone(), partition));
                }
                break;
            }
        }
    }
    for entry in plan.values_mut() {
        entry.sort();
    }
    plan
}

/// 分配计划的**不变量自检**（无重叠、无遗漏）——组长在 SyncGroup 之前必须过这一步。
///
/// 返回 `Err` 说明分配器有 bug 或成员订阅集合与 `topic_partitions` 不一致：
/// 这时宁可**拒绝 SyncGroup**（协调器会重新 rebalance），也不下发一个会丢数据/重复消费的分配。
///
/// # Errors
/// 分区被重复分配或未被分配。
pub fn verify_plan(
    plan: &AssignmentPlan,
    members: &[GroupMember],
    topic_partitions: &BTreeMap<String, Vec<i32>>,
) -> DomainResult<()> {
    let mut seen: BTreeMap<(String, i32), String> = BTreeMap::new();
    for (member_id, assigned) in plan {
        for key in assigned {
            if let Some(previous) = seen.insert(key.clone(), member_id.clone()) {
                return Err(DomainError::Internal(format!(
                    "消费者组分配不变量被破坏：{}/{} 同时分给了 {previous} 与 {member_id}（重叠）",
                    key.0, key.1
                )));
            }
        }
    }
    for member in members {
        for topic in &member.topics {
            let Some(partitions) = topic_partitions.get(topic) else {
                continue;
            };
            for partition in partitions {
                if !seen.contains_key(&(topic.clone(), *partition)) {
                    return Err(DomainError::Internal(format!(
                        "消费者组分配不变量被破坏：{topic}/{partition} 没有任何成员负责（遗漏）"
                    )));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// rebalance / 心跳判据（纯函数）
// ---------------------------------------------------------------------------

/// Kafka 协议错误码：组协调相关（只看这几个，其余原样上报）。
pub mod error_code {
    /// 未知成员（成员 id 已失效，必须**清空 member_id 重新 JoinGroup**）。
    pub const UNKNOWN_MEMBER_ID: i16 = 25;
    /// 代际号过期（成员落后于当前代际，必须重新 JoinGroup）。
    pub const ILLEGAL_GENERATION: i16 = 22;
    /// 组正在 rebalance（协调器要求成员重新 JoinGroup）。
    pub const REBALANCE_IN_PROGRESS: i16 = 27;
    /// group.instance.id 被其它成员占用（静态成员被顶替）。
    pub const FENCED_INSTANCE_ID: i16 = 82;
    /// 协调器已迁移（新协调器在响应里给出）。
    pub const NOT_COORDINATOR: i16 = 16;
    /// 首轮 `JoinGroup` **必须**带非空 `member_id`（KIP-394，Kafka 2.3+）。
    ///
    /// 协调器会在错误响应里**顺带给出一个 member_id**，客户端拿它重发即可——
    /// 这正是"两步入组"：`MEMBER_ID_REQUIRED` → 带 id 重试。
    /// 老实现（KoP 等）直接接受空 member_id，因此两条路径都要能走。
    pub const MEMBER_ID_REQUIRED: i16 = 79;
}

/// 触发重新入组的原因（心跳/同步响应里读出来的）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebalanceTrigger {
    /// 协调器主动要求（`REBALANCE_IN_PROGRESS`）。
    RebalanceInProgress,
    /// 代际号过期（成员被踢出后重新加入）。
    IllegalGeneration,
    /// 成员 id 失效（协调器已忘记本成员 ⇒ 必须换新 member_id）。
    UnknownMemberId,
    /// 静态成员被顶替。
    FencedInstanceId,
}

impl RebalanceTrigger {
    /// 描述（日志用）。
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::RebalanceInProgress => "协调器要求 rebalance（REBALANCE_IN_PROGRESS）",
            Self::IllegalGeneration => "代际号过期（ILLEGAL_GENERATION）：成员落后于当前代际",
            Self::UnknownMemberId => "成员 id 失效（UNKNOWN_MEMBER_ID）：协调器已忘记本成员",
            Self::FencedInstanceId => "静态成员被顶替（FENCED_INSTANCE_ID）",
        }
    }

    /// 是否必须**丢弃现有 member_id** 后重新 JoinGroup（否则会一直撞同一个错误）。
    #[must_use]
    pub const fn requires_new_member_id(self) -> bool {
        matches!(self, Self::UnknownMemberId | Self::FencedInstanceId)
    }
}

/// 从协议错误码判定 rebalance 触发条件（`None` = 不触发）。
#[must_use]
pub const fn rebalance_trigger(code: i16) -> Option<RebalanceTrigger> {
    match code {
        error_code::REBALANCE_IN_PROGRESS => Some(RebalanceTrigger::RebalanceInProgress),
        error_code::ILLEGAL_GENERATION => Some(RebalanceTrigger::IllegalGeneration),
        error_code::UNKNOWN_MEMBER_ID => Some(RebalanceTrigger::UnknownMemberId),
        error_code::FENCED_INSTANCE_ID => Some(RebalanceTrigger::FencedInstanceId),
        _ => None,
    }
}

/// 是否到了该发心跳的时刻（`heartbeat.interval.ms` 到期）。
#[must_use]
pub fn heartbeat_due(elapsed_ms: u64, interval_ms: i32) -> bool {
    elapsed_ms >= u64::try_from(interval_ms.max(1)).unwrap_or(1)
}

/// 是否已超过 `max.poll.interval.ms`（超过就必须**主动退组**再重新加入：
/// 继续消费会撞 `REBALANCE_IN_PROGRESS`，而协调器已把本成员判死）。
#[must_use]
pub fn poll_interval_exceeded(elapsed_ms: u64, max_poll_interval_ms: i32) -> bool {
    max_poll_interval_ms > 0 && elapsed_ms > u64::try_from(max_poll_interval_ms).unwrap_or(u64::MAX)
}

/// 起始 offset 决策（纯函数，便于离线断言"重启不重复不丢"的口径）。
///
/// * `committed` = `OffsetFetch` 拿到的组内已提交 offset（`None` 或 `< 0` = 协调器里没有记录）；
/// * `resolved` = 没有已提交记录时，按 `start_from` 用 `ListOffsets` 定位出来的 offset。
///
/// 返回 `(offset, 来源描述)`。**已提交 offset 优先**是"重启进程从已提交 offset 续消费"的实现点：
/// 组协议路径下 broker 才是权威，本地游标只是镜像。
#[must_use]
pub fn choose_start_offset(committed: Option<i64>, resolved: i64) -> (i64, &'static str) {
    match committed.filter(|offset| *offset >= 0) {
        Some(offset) => (offset, "已提交 offset（broker 侧 __consumer_offsets）"),
        None => (resolved, "start_from（组内无已提交 offset）"),
    }
}

/// 组会话三个时长参数的合法性校验（**必须在建连前拦住**，否则表现为莫名其妙的 rebalance 循环）。
///
/// Kafka 的硬约束：`session.timeout.ms` 必须大于 `heartbeat.interval.ms`（Java 客户端还要求
/// `heartbeat.interval.ms < session.timeout.ms / 3`，这里按同一口径要求，避免网络抖动被误判成成员死亡）。
///
/// # Errors
/// 任一约束不满足。
pub fn validate_group_timing(
    session_timeout_ms: i32,
    heartbeat_interval_ms: i32,
    max_poll_interval_ms: i32,
) -> DomainResult<()> {
    if session_timeout_ms <= 0 {
        return Err(DomainError::Config("Kafka 消费者组 session.timeout.ms 必须为正数".to_string()));
    }
    if heartbeat_interval_ms <= 0 {
        return Err(DomainError::Config("Kafka 消费者组 heartbeat.interval.ms 必须为正数".to_string()));
    }
    if heartbeat_interval_ms.saturating_mul(3) >= session_timeout_ms {
        return Err(DomainError::Config(format!(
            "Kafka 消费者组 heartbeat.interval.ms（{heartbeat_interval_ms}）必须小于 session.timeout.ms（{session_timeout_ms}）的三分之一"
        )));
    }
    if max_poll_interval_ms > 0 && max_poll_interval_ms < session_timeout_ms {
        return Err(DomainError::Config(format!(
            "Kafka 消费者组 max.poll.interval.ms（{max_poll_interval_ms}）不能小于 session.timeout.ms（{session_timeout_ms}）"
        )));
    }
    Ok(())
}

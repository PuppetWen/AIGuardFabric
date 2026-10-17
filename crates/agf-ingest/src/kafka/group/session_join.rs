//! 成员生命周期：`JoinGroup` → `SyncGroup` → `Heartbeat`（含 rebalance）→ `LeaveGroup`。
//!
//! ## rebalance 的三种触发源（都必须在重新入组**之前**提交 offset）
//!
//! 1. **心跳响应**带回 `REBALANCE_IN_PROGRESS` / `ILLEGAL_GENERATION` / `UNKNOWN_MEMBER_ID`
//!    —— 成员增减或成员被判死时协调器这样通知；
//! 2. **`max.poll.interval.ms` 超时** —— 协调器已把本成员踢出组，继续消费只会拿到
//!    `ILLEGAL_GENERATION`，因此**主动退组再入组**；
//! 3. **`SyncGroup` 期间撞上 rebalance** —— 本轮作废，下一轮重新入组。
//!
//! "rebalance 前提交 offset" 落在 [`GroupSession::rejoin`] 的第一行：把内存镜像里的
//! 进度用**旧代际**提交一次，再销毁代际信息去 `JoinGroup`。

use std::time::Instant;

use agf_core::error::{DomainError, DomainResult};
use kafka_protocol::messages::join_group_request::JoinGroupRequestProtocol;
use kafka_protocol::messages::leave_group_request::MemberIdentity;
use kafka_protocol::messages::{
    GroupId, HeartbeatRequest, HeartbeatResponse, JoinGroupRequest, JoinGroupResponse, LeaveGroupRequest,
    SyncGroupRequest, SyncGroupResponse,
};
use kafka_protocol::protocol::{Request as _, StrBytes};
use tracing::{info, warn};

use super::assign::{
    AssignmentPlan, GroupMember, assign_partitions, error_code, heartbeat_due, poll_interval_exceeded,
    rebalance_trigger, verify_plan,
};
use super::codec::{decode_assignment, decode_subscription, encode_subscription, verify_and_encode};
use super::session::GroupSession;

/// `JoinGroup` 版本偏好（**v9**，与 Kafka 3.9 的 Java 客户端一致）。
///
/// 版本协商会把它夹到 broker 声明的最高版本（KoP 之类只支持低版本的实现会自动降到
/// 它支持的版本），因此 v9 只是"首选"而不是硬要求。
///
/// ⚠️ **真机排查记录（结论已修正）**：早先对 `apache/kafka:3.9.0`(KRaft) 发 `JoinGroup` 时，
/// 协调器会**扣住响应**、broker 日志只有 "Preparing to rebalance … Adding new member"、
/// **没有** "Stabilized group"，成员直到 300s 后才被回收并回 `UNKNOWN_MEMBER_ID(25)`。
/// 当时的"字节与协议规范一致 / 超时参数不对 / initial-rebalance-delay 作祟"都是**误判**：
/// 300s 既不是 `session.timeout.ms` 也不是 `max.poll.interval.ms`，而是协调器的
/// `GroupCoordinator.NewMemberJoinTimeoutMs`（5 分钟）；真正原因是**消费者协议少了 2 字节版本前缀**
/// —— 见 [`super::codec`] 模块文档与 `tools/simulators/out/kafka-group-blocker.md`。
/// 修好后（正文前补 `[version=0]`）真机入组、分配、提交、接管均已实测通过。
pub(super) const JOIN_GROUP_PREFERRED: i16 = 9;
/// `SyncGroup` 版本偏好（v4+ flexible）。
pub(super) const SYNC_GROUP_PREFERRED: i16 = 5;
/// `Heartbeat` 版本偏好（v4 flexible）。
pub(super) const HEARTBEAT_PREFERRED: i16 = 4;
/// `LeaveGroup` 版本偏好（v4+ flexible）。
pub(super) const LEAVE_GROUP_PREFERRED: i16 = 3;

impl GroupSession {
    /// 确保已入组并拿到分配（未入组 ⇒ 执行完整 JoinGroup + SyncGroup）。
    pub(super) async fn ensure_joined(&mut self, topics: &[String]) -> DomainResult<()> {
        if self.joined {
            return Ok(());
        }
        self.ensure_coordinator().await?;
        self.join(topics).await
    }

    /// 触发重新入组：**先补提交 offset，再入组**。
    pub(super) async fn rejoin(&mut self, topics: &[String], reason: &str) -> DomainResult<()> {
        info!(
            group = %self.group.group_id,
            reason,
            committed = self.committed.len(),
            "Kafka 消费者组：准备重新入组（rebalance）——先提交已知进度，再 JoinGroup"
        );
        if let Err(error) = self.commit_pending().await {
            warn!(error = %error, "Kafka 消费者组：rebalance 前补提交失败（继续入组；重放由流水线去重兜住）");
        }
        self.joined = false;
        self.ensure_coordinator().await?;
        self.join(topics).await
    }

    /// 心跳 + `max.poll.interval.ms` 检查（接收器每轮拉取前调用）。
    pub(super) async fn maintain(&mut self, topics: &[String]) -> DomainResult<()> {
        if !self.joined {
            return self.ensure_joined(topics).await;
        }
        let elapsed_poll = u64::try_from(self.last_poll.elapsed().as_millis()).unwrap_or(u64::MAX);
        if poll_interval_exceeded(elapsed_poll, self.group.max_poll_interval_ms) {
            warn!(
                group = %self.group.group_id,
                elapsed_ms = elapsed_poll,
                max_poll_interval_ms = self.group.max_poll_interval_ms,
                "Kafka 消费者组：单轮处理超过 max.poll.interval.ms，主动退组并重新加入（协调器已把本成员判死）"
            );
            self.leave().await;
            return self.rejoin(topics, "max.poll.interval.ms 超时").await;
        }
        let elapsed_heartbeat = u64::try_from(self.last_heartbeat.elapsed().as_millis()).unwrap_or(u64::MAX);
        if !heartbeat_due(elapsed_heartbeat, self.group.heartbeat_interval_ms) {
            return Ok(());
        }
        let mut request = HeartbeatRequest::default();
        request.group_id = GroupId(StrBytes::from_string(self.group.group_id.clone()));
        request.generation_id = self.generation_id;
        request.member_id = StrBytes::from_string(self.member_id.clone().unwrap_or_default());
        let response: HeartbeatResponse = self.coordinator_call(HEARTBEAT_PREFERRED, 0, &request).await?;
        self.last_heartbeat = Instant::now();
        self.heartbeats = self.heartbeats.saturating_add(1);
        if let Some(trigger) = rebalance_trigger(response.error_code) {
            info!(
                group = %self.group.group_id,
                generation = self.generation_id,
                trigger = trigger.describe(),
                "Kafka 消费者组：心跳触发 rebalance"
            );
            if trigger.requires_new_member_id() {
                self.member_id = None;
            }
            return self.rejoin(topics, trigger.describe()).await;
        }
        if response.error_code != 0 {
            warn!(
                group = %self.group.group_id,
                error_code = response.error_code,
                "Kafka 消费者组：心跳返回非零错误码（下一轮重试）"
            );
        }
        Ok(())
    }

    /// 一次完整入组（JoinGroup + SyncGroup）。
    async fn join(&mut self, topics: &[String]) -> DomainResult<()> {
        let mut protocol = JoinGroupRequestProtocol::default();
        protocol.name = StrBytes::from_static_str(self.group.assignor.as_str());
        protocol.metadata = encode_subscription(topics);
        let mut request = JoinGroupRequest::default();
        request.group_id = GroupId(StrBytes::from_string(self.group.group_id.clone()));
        request.session_timeout_ms = self.group.session_timeout_ms;
        request.rebalance_timeout_ms = self.group.rebalance_timeout_ms;
        request.member_id = StrBytes::from_string(self.member_id.clone().unwrap_or_default());
        request.protocol_type = StrBytes::from_static_str("consumer");
        request.protocols = vec![protocol];
        let mut response: JoinGroupResponse = self.coordinator_call(JOIN_GROUP_PREFERRED, 0, &request).await?;
        // 两步入组的两个"重试一次"分支（合计最多 3 次请求）：
        //   * `MEMBER_ID_REQUIRED`（KIP-394，Kafka 2.3+）：协调器在错误响应里给出 member_id，
        //     带上它重发；不带就永远入不了组（Kafka 3.9 的默认行为，**实测错误码 79**）；
        //   * `UNKNOWN_MEMBER_ID`：本成员已被协调器遗忘 ⇒ 清空 member_id 重新登记。
        // KoP 等老实现直接接受空 member_id，走不到这里（两条路径都能闭环）。
        for _ in 0..2 {
            if response.error_code == error_code::MEMBER_ID_REQUIRED {
                if response.member_id.is_empty() {
                    // 组处于 PreparingRebalance/CompletingRebalance/Stable：协调器**没有**给出
                    // member_id（Kafka 只在组为空时才回传新生成的 id）。此时立即重发只会空转，
                    // 应当让外层退避重连等组稳定下来 —— 这也是 Java 客户端"下一轮再入组"的口径。
                    return Err(DomainError::DependencyUnavailable {
                        dependency: "kafka".to_string(),
                        cause: format!(
                            "JoinGroup(group={}) 需要 member_id 但协调器未回传（组正在 rebalance 或非空），等下一轮重试",
                            self.group.group_id
                        ),
                    });
                }
                info!(
                    group = %self.group.group_id,
                    member_id = %response.member_id,
                    "Kafka 消费者组：协调器要求首轮 JoinGroup 带 member_id（KIP-394），带上它重发"
                );
                self.member_id = Some(response.member_id.to_string());
                request.member_id = response.member_id.clone();
                response = self.coordinator_call(JOIN_GROUP_PREFERRED, 0, &request).await?;
                continue;
            }
            if response.error_code == error_code::UNKNOWN_MEMBER_ID && self.member_id.is_some() {
                info!(group = %self.group.group_id, "Kafka 消费者组：member_id 失效，清空后重新 JoinGroup");
                self.member_id = None;
                request.member_id = StrBytes::default();
                response = self.coordinator_call(JOIN_GROUP_PREFERRED, 0, &request).await?;
                continue;
            }
            break;
        }
        if response.error_code != 0 {
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!(
                    "JoinGroup(group={}) 失败，错误码 {}（协调器回传 member_id={:?}，generation={}，leader={:?}，成员数 {}）",
                    self.group.group_id,
                    response.error_code,
                    response.member_id.to_string(),
                    response.generation_id,
                    response.leader.to_string(),
                    response.members.len()
                ),
            });
        }
        self.member_id = Some(response.member_id.to_string());
        self.generation_id = response.generation_id;
        self.leader = response.leader == response.member_id;
        self.member_count = response.members.len().max(1);
        let protocol_name = response
            .protocol_name
            .as_ref()
            .map_or_else(|| self.group.assignor.as_str().to_string(), ToString::to_string);
        info!(
            group = %self.group.group_id,
            member_id = self.member_id.as_deref().unwrap_or("-"),
            generation = self.generation_id,
            leader = self.leader,
            members = response.members.len(),
            assignor = %protocol_name,
            "Kafka 消费者组：JoinGroup 成功（协调器已确定代际与组长）"
        );
        // ---- SyncGroup：组长计算并下发分配；其余成员提交空表 ----
        let assignments = if self.leader {
            let (plan, members) = self.compute_plan(&response, topics).await?;
            verify_and_encode(&plan, &members, &self.topic_partitions)?
        } else {
            Vec::new()
        };
        let mut sync = SyncGroupRequest::default();
        sync.group_id = GroupId(StrBytes::from_string(self.group.group_id.clone()));
        sync.generation_id = self.generation_id;
        sync.member_id = StrBytes::from_string(self.member_id.clone().unwrap_or_default());
        sync.protocol_type = Some(StrBytes::from_static_str("consumer"));
        sync.protocol_name = Some(StrBytes::from_string(protocol_name));
        sync.assignments = assignments;
        let response: SyncGroupResponse = self.coordinator_call(SYNC_GROUP_PREFERRED, 0, &sync).await?;
        if let Some(trigger) = rebalance_trigger(response.error_code) {
            self.joined = false;
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!("SyncGroup 期间发生 rebalance（{}），本轮重新入组", trigger.describe()),
            });
        }
        if response.error_code != 0 {
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!("SyncGroup(group={}) 失败，错误码 {}", self.group.group_id, response.error_code),
            });
        }
        self.assignment = decode_assignment(&response.assignment)?;
        self.assignment.sort();
        self.joined = true;
        self.rebalances = self.rebalances.saturating_add(1);
        self.last_heartbeat = Instant::now();
        self.last_poll = Instant::now();
        info!(
            group = %self.group.group_id,
            member_id = self.member_id.as_deref().unwrap_or("-"),
            generation = self.generation_id,
            assignment = ?self.assignment,
            "Kafka 消费者组：SyncGroup 成功——**组协调器下发的分区分配已生效**"
        );
        Ok(())
    }

    /// 组长计算分配：先按全体成员订阅的并集刷新 Metadata，再套分配器。
    async fn compute_plan(
        &mut self,
        response: &JoinGroupResponse,
        own_topics: &[String],
    ) -> DomainResult<(AssignmentPlan, Vec<GroupMember>)> {
        let mut members = Vec::with_capacity(response.members.len());
        let mut topic_union: Vec<String> = own_topics.to_vec();
        for member in &response.members {
            let topics = decode_subscription(&member.metadata)?;
            for topic in &topics {
                if !topic_union.contains(topic) {
                    topic_union.push(topic.clone());
                }
            }
            members.push(GroupMember::new(member.member_id.to_string(), topics));
        }
        topic_union.sort();
        topic_union.dedup();
        self.refresh_metadata(&topic_union).await?;
        let plan = assign_partitions(self.group.assignor, &members, &self.topic_partitions);
        verify_plan(&plan, &members, &self.topic_partitions)?;
        Ok((plan, members))
    }

    /// 主动退组（优雅停机；触发**立即** rebalance，而不是等 `session.timeout.ms`）。
    pub(super) async fn leave(&mut self) {
        if !self.joined {
            return;
        }
        self.joined = false;
        let (Some(addr), Some(member_id)) = (self.coordinator.clone(), self.member_id.clone()) else {
            return;
        };
        if self.ensure_conn(&addr).await.is_err() {
            return;
        }
        let Ok(version) = self.version_for(&addr, LeaveGroupRequest::KEY, LEAVE_GROUP_PREFERRED, 0) else {
            return;
        };
        let member = StrBytes::from_string(member_id);
        let group_id = GroupId(StrBytes::from_string(self.group.group_id.clone()));
        let mut request = LeaveGroupRequest::default();
        request.group_id = group_id;
        if version >= 3 {
            // v3+：成员列表形态（member_id 字段被忽略）
            let mut identity = MemberIdentity::default();
            identity.member_id = member;
            identity.reason = Some(StrBytes::from_static_str("agf-ingest graceful shutdown"));
            request.members = vec![identity];
        } else {
            // v0~v2：单成员形态
            request.member_id = member;
        }
        match self.call(&addr, LEAVE_GROUP_PREFERRED, 0, &request).await {
            Ok(_) => {
                info!(group = %self.group.group_id, "Kafka 消费者组：LeaveGroup 已发送（同伴立即 rebalance 接管）");
            }
            Err(error) => warn!(error = %error, "Kafka 消费者组：LeaveGroup 失败（由 session.timeout.ms 兜底）"),
        }
        self.member_id = None;
        self.assignment.clear();
    }
}

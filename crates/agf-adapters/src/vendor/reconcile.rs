//! `sync` 的冲突裁决（**纯函数**，可离线完整覆盖）。
//!
//! `sync` = `pull` → 与本地快照比对 → 需要时 `push`。比对结果落在六种裁决上，
//! 每条裁决都写进 `SyncOutcome.warnings`（决策日志）并经 `tracing` 输出，
//! 因此"为什么这条没回写"永远可回答。
//!
//! ## 裁决规则（与 [`ConflictPolicy`] 的关系）
//!
//! | 内容 | 时间戳 | 外部优先（默认） | 本地优先 |
//! |---|---|---|---|
//! | 相同 | 任意 | `Skip`（无变化） | `Skip` |
//! | 不同 | 外部更新 | `TakeExternal`（本地采纳外部） | `TakeExternal` |
//! | 不同 | 本地更新 | `ConflictExternalWins`（冲突：策略压下本地） | `PushLocal`（无需裁决） |
//! | 不同 | 两者相同 | `ConflictExternalWins` | `ConflictLocalWins` |
//! | 不同 | 缺任一侧 | `ConflictExternalWins`（无法判定 ⇒ 策略裁决） | `ConflictLocalWins` |
//!
//! 即：**只有"时间戳明确显示本地更新，且策略允许"时才回写**；其余情况一律记录决策日志。

use agf_core::time::Timestamp;

use crate::contract::ConflictPolicy;

/// 单条对账裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReconcileDecision {
    /// 无变化（内容一致）。
    Skip,
    /// 外部更新（非冲突）：本地采纳外部状态，不回写。
    TakeExternal,
    /// 本地更新且外部未变（非冲突）：回写外部。
    PushLocal,
    /// 冲突：按外部优先压下本地变更（**不回写**，记决策日志）。
    ConflictExternalWins,
    /// 冲突：按本地优先回写外部（记决策日志）。
    ConflictLocalWins,
}

impl ReconcileDecision {
    /// 文本形式（落日志与断言用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::TakeExternal => "take-external",
            Self::PushLocal => "push-local",
            Self::ConflictExternalWins => "conflict-external-wins",
            Self::ConflictLocalWins => "conflict-local-wins",
        }
    }

    /// 是否需要回写外部。
    #[must_use]
    pub const fn should_push(self) -> bool {
        matches!(self, Self::PushLocal | Self::ConflictLocalWins)
    }

    /// 是否属于"冲突"（两侧状态不一致且需策略裁决）。
    #[must_use]
    pub const fn is_conflict(self) -> bool {
        matches!(self, Self::ConflictExternalWins | Self::ConflictLocalWins)
    }

    /// 决策日志文本（写入 `SyncOutcome.warnings`）。
    #[must_use]
    pub const fn log_text(self) -> &'static str {
        match self {
            Self::Skip => "外部与本地一致，跳过",
            Self::TakeExternal => "外部更新：本地采纳外部状态，不回写",
            Self::PushLocal => "本地更新且外部未变：回写外部",
            Self::ConflictExternalWins => "冲突：按「外部优先」保留外部状态，不回写",
            Self::ConflictLocalWins => "冲突：按「本地优先」回写本地状态",
        }
    }
}

/// 裁决（纯函数）。
///
/// `state_changed` 为 `false` 时无论时间戳如何都返回 [`ReconcileDecision::Skip`]
/// （内容一致 ⇒ 没有可同步的东西）。
#[must_use]
pub fn reconcile(
    external_updated_at: Option<Timestamp>,
    local_updated_at: Option<Timestamp>,
    state_changed: bool,
    policy: ConflictPolicy,
) -> ReconcileDecision {
    if !state_changed {
        return ReconcileDecision::Skip;
    }
    match (external_updated_at, local_updated_at) {
        (Some(external), Some(local)) if external > local => ReconcileDecision::TakeExternal,
        (Some(external), Some(local)) if local > external => match policy {
            ConflictPolicy::ExternalWins => ReconcileDecision::ConflictExternalWins,
            ConflictPolicy::LocalWins => ReconcileDecision::PushLocal,
        },
        // 时间戳相同但内容不同，或任一侧缺时间戳 ⇒ 无法判定先后，交给策略
        _ => match policy {
            ConflictPolicy::ExternalWins => ReconcileDecision::ConflictExternalWins,
            ConflictPolicy::LocalWins => ReconcileDecision::ConflictLocalWins,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix_secs(secs).expect("合法时间戳")
    }

    #[test]
    fn identical_state_is_skipped_regardless_of_policy_and_time() {
        for policy in ConflictPolicy::ALL {
            assert_eq!(reconcile(Some(at(10)), Some(at(20)), false, policy), ReconcileDecision::Skip);
            assert_eq!(reconcile(None, None, false, policy), ReconcileDecision::Skip);
        }
        assert!(!ReconcileDecision::Skip.should_push());
        assert!(!ReconcileDecision::Skip.is_conflict());
    }

    #[test]
    fn external_newer_is_taken_without_conflict() {
        for policy in ConflictPolicy::ALL {
            assert_eq!(reconcile(Some(at(20)), Some(at(10)), true, policy), ReconcileDecision::TakeExternal);
        }
    }

    #[test]
    fn local_newer_pushes_only_when_policy_allows() {
        assert_eq!(
            reconcile(Some(at(10)), Some(at(20)), true, ConflictPolicy::LocalWins),
            ReconcileDecision::PushLocal
        );
        assert!(!ReconcileDecision::PushLocal.is_conflict());
        assert!(ReconcileDecision::PushLocal.should_push());

        let conflict = reconcile(Some(at(10)), Some(at(20)), true, ConflictPolicy::ExternalWins);
        assert_eq!(conflict, ReconcileDecision::ConflictExternalWins);
        assert!(conflict.is_conflict());
        assert!(!conflict.should_push(), "外部优先必须压住本地变更（不回写）");
    }

    #[test]
    fn missing_or_equal_timestamps_are_decided_by_policy() {
        for (external, local) in [(None, Some(at(5))), (Some(at(5)), None), (None, None), (Some(at(5)), Some(at(5)))] {
            assert_eq!(
                reconcile(external, local, true, ConflictPolicy::ExternalWins),
                ReconcileDecision::ConflictExternalWins
            );
            let local_wins = reconcile(external, local, true, ConflictPolicy::LocalWins);
            assert_eq!(local_wins, ReconcileDecision::ConflictLocalWins);
            assert!(local_wins.should_push());
        }
    }

    #[test]
    fn decision_texts_are_stable_and_informative() {
        let mut seen = Vec::new();
        for decision in [
            ReconcileDecision::Skip,
            ReconcileDecision::TakeExternal,
            ReconcileDecision::PushLocal,
            ReconcileDecision::ConflictExternalWins,
            ReconcileDecision::ConflictLocalWins,
        ] {
            assert!(!decision.as_str().is_empty());
            assert!(!decision.log_text().is_empty());
            assert!(!seen.contains(&decision.as_str()), "文本必须唯一（落日志可辨识）");
            seen.push(decision.as_str());
        }
        assert!(ReconcileDecision::ConflictLocalWins.log_text().contains("本地优先"));
    }
}

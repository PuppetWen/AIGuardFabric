//! 外部同步语义契约：`send` / `push` / `pull` / `sync` 的**语义边界**与**能力登记**。
//!
//! 本模块是 `docs/adapter-spec.md` §1 统一契约里"写入/读取/对账"三条语义在
//! `agf-adapters` 的落地形态。**先定义语义，再谈实现**——12 个适配器不是每个都
//! 该有三个方法，做不到的必须登记为 [`SemanticSupport::Unsupported`] 并给出原因。
//!
//! ## 四条语义的契约
//!
//! | 语义 | 方向 | 入参 | 出参 | 远端对象 id | 说明 |
//! |---|---|---|---|---|---|
//! | `send` | 平台 → 外部（**单向投递**） | [`AdapterMessage`](crate::contract::AdapterMessage) | [`AdapterReceipt`](crate::contract::AdapterReceipt)（含 `remote_id`） | **由本方法产生** | 通知 / 建单 / 隔离下发；`send` 是唯一"创建远端对象"的入口 |
//! | `push` | 平台 → 外部（**状态变更回写**） | [`PushPayload`](agf_core::adapter::PushPayload)（`entity` + `entity_id` + `body`） | [`PushOutcome`](crate::contract::PushOutcome) | **必须已存在**（取自 `send` 的 `remote_id`） | 工单状态/评论回写、消息更新与撤回、EDR 处置状态回写 |
//! | `pull` | 外部 → 平台（**增量读取**） | [`PullRequest`](agf_core::adapter::PullRequest)（`resource` + `cursor` + `limit`） | [`PullResponse`](agf_core::adapter::PullResponse)（`items` + `next_cursor`） | 逐条读取 | 拉工单当前状态/评论、拉设备事件与主机清单 |
//! | `sync` | **双向对账** | [`SyncRequest`](crate::contract::SyncRequest)（资源 + 游标 + 本地快照 + 冲突策略） | [`SyncOutcome`](agf_core::adapter::SyncOutcome)（计数 + 变化摘要 + 决策日志） | 双方都有 | 本地案件 ↔ 外部工单对账 |
//!
//! ### 边界与不变式（实现必须遵守）
//!
//! 1. **`send` 与 `push` 不重叠**：`send` 只负责创建/投递并**产生** `remote_id`；
//!    `push` 只针对**已存在的**远端对象回写，`entity_id` 缺失一律 `Validation` 拒绝——
//!    绝不对模糊目标回写（与 EDR 隔离"缺 host 即拒绝"同一原则）。
//! 2. **`pull` 是增量语义**：`cursor` 为空表示首轮全量，返回的 `next_cursor` 供下一轮使用；
//!    同一适配器实例内按 `resource` 维度去重（[`crate::vendor::IncrementalWindow`]），
//!    上游分页边界重复返回同一条目时不会二次计入。
//! 3. **`sync` 不是第三套逻辑**：`sync` = `pull` → 与本地快照比对 → 需要时 `push` 的组合，
//!    冲突由 [`ConflictPolicy`] 裁决，每条裁决都写入 `SyncOutcome.warnings`（决策日志）
//!    并同时经 `tracing` 输出。
//! 4. **`Unsupported` ≠ "未实现"**：语义上不适用（如通知渠道没有读取接口）登记为
//!    [`SemanticSupport::Unsupported`] 并给出**具体原因**，运行时返回**不可重试**的
//!    `DomainError::Validation`（重试不会让语义变得可用，进死信队列只会空转）。
//!    真正"还没写"的代码路径（新增适配器脚手架）走 `adapter-spec` 的 TODO 锚点，
//!    **内置 12 个适配器不得留 `NotImplemented` 占位**（有单测守住）。
//!
//! ## 能力矩阵是真源
//!
//! [`AdapterMetadata::semantics`](crate::contract::AdapterMetadata) 保存每个适配器声明的
//! [`SemanticProfile`]；能力矩阵的一行（[`crate::contract::SemanticCapability`]，实现见
//! `semantic_capability` 子模块）把它渲染成「适配器 | send | push | pull | sync | 是否真测 | 证据」表，
//! 由 [`crate::vendors::capability_matrix`] 组装，文档（`docs/adapter-spec.md`）与控制台都以该表为准。

use std::fmt;

use crate::settings::AdapterSettings;

/// 设置键：`sync` 的冲突裁决策略（`external-wins` / `local-wins`）。
pub const SETTING_CONFLICT_POLICY: &str = "sync_conflict_policy";

/// "未登记"档位的原因文本（新增适配器脚手架阶段的默认值）。
pub const UNDECLARED_REASON: &str =
    "该适配器未登记此语义（新增适配器的脚手架阶段：只声明 send，不声称 push/pull/sync 能力）";

/// 外部同步语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Semantic {
    /// 状态回写（平台 → 外部已存在的对象）。
    Push,
    /// 增量读取（外部 → 平台）。
    Pull,
    /// 双向对账（`pull` + 比对 + `push`）。
    Sync,
}

impl Semantic {
    /// 全部语义（固定顺序：push / pull / sync；能力矩阵与文档按此渲染）。
    pub const ALL: [Self; 3] = [Self::Push, Self::Pull, Self::Sync];

    /// 文本形式（与 `agf_core::adapter` 的方法名一致）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
            Self::Sync => "sync",
        }
    }

    /// 中文显示名（控制台能力矩阵用）。
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Push => "状态回写（平台→外部）",
            Self::Pull => "增量读取（外部→平台）",
            Self::Sync => "双向对账",
        }
    }
}

impl fmt::Display for Semantic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 语义支持档位。
///
/// **只有两档**：`Implemented`（真实往返 + 往返测试）与 `Unsupported`（语义不适用 + 原因）。
/// 刻意不设第三档"待实现"——那正是本轮要消灭的 `NotImplemented` 占位。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticSupport {
    /// 已实现（真实往返；有 wiremock/本地服务端往返测试守住）。
    Implemented,
    /// 语义不适用（原因必填，不得为空）。
    Unsupported {
        /// 不适用的具体原因（协议/权限/接口层面的客观依据，不是"还没做"）。
        reason: String,
    },
}

impl SemanticSupport {
    /// 已实现。
    #[must_use]
    pub const fn implemented() -> Self {
        Self::Implemented
    }

    /// 语义不适用（原因必填）。
    #[must_use]
    pub fn unsupported(reason: &str) -> Self {
        Self::Unsupported { reason: reason.to_string() }
    }

    /// 是否已实现。
    #[must_use]
    pub const fn is_implemented(&self) -> bool {
        matches!(self, Self::Implemented)
    }

    /// 不适用原因（已实现时为 `None`）。
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Implemented => None,
            Self::Unsupported { reason } => Some(reason.as_str()),
        }
    }

    /// 文本形式（`implemented` / `unsupported`）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// 能力矩阵单元格文本：**Unsupported 必须带原因**。
    #[must_use]
    pub fn markdown_cell(&self) -> String {
        match self {
            Self::Implemented => "✅ 已实现".to_string(),
            Self::Unsupported { reason } => format!("⛔ Unsupported：{reason}"),
        }
    }
}

impl fmt::Display for SemanticSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented => f.write_str("implemented"),
            Self::Unsupported { reason } => write!(f, "Unsupported（{reason}）"),
        }
    }
}

/// 一个适配器对 `push` / `pull` / `sync` 三条语义的声明。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SemanticProfile {
    /// 状态回写档位。
    pub push: SemanticSupport,
    /// 增量读取档位。
    pub pull: SemanticSupport,
    /// 双向对账档位。
    pub sync: SemanticSupport,
}

impl SemanticProfile {
    /// 仅 `send`：三条语义都不适用（**必须逐条给出原因**）。
    #[must_use]
    pub fn send_only(push: &str, pull: &str, sync: &str) -> Self {
        Self {
            push: SemanticSupport::unsupported(push),
            pull: SemanticSupport::unsupported(pull),
            sync: SemanticSupport::unsupported(sync),
        }
    }

    /// 三条语义全部已实现（工单类 / 设备类）。
    #[must_use]
    pub fn full() -> Self {
        Self {
            push: SemanticSupport::implemented(),
            pull: SemanticSupport::implemented(),
            sync: SemanticSupport::implemented(),
        }
    }

    /// 仅 `push` 已实现（通知类中确有消息更新/撤回接口的厂商）。
    #[must_use]
    pub fn push_only(pull: &str, sync: &str) -> Self {
        Self {
            push: SemanticSupport::implemented(),
            pull: SemanticSupport::unsupported(pull),
            sync: SemanticSupport::unsupported(sync),
        }
    }

    /// **未登记**档位（`AdapterMetadata::new` 的默认值）：不声称任何能力。
    #[must_use]
    pub fn undeclared() -> Self {
        Self::send_only(UNDECLARED_REASON, UNDECLARED_REASON, UNDECLARED_REASON)
    }

    /// 取某条语义的档位。
    #[must_use]
    pub const fn support(&self, semantic: Semantic) -> &SemanticSupport {
        match semantic {
            Semantic::Push => &self.push,
            Semantic::Pull => &self.pull,
            Semantic::Sync => &self.sync,
        }
    }

    /// 某条语义是否已实现。
    #[must_use]
    pub fn is_implemented(&self, semantic: Semantic) -> bool {
        self.support(semantic).is_implemented()
    }

    /// 已实现的语义清单。
    #[must_use]
    pub fn implemented(&self) -> Vec<Semantic> {
        Semantic::ALL.into_iter().filter(|s| self.is_implemented(*s)).collect()
    }

    /// 是否存在"未登记"档位（脚手架阶段的判据；内置适配器**不得**为 `true`）。
    #[must_use]
    pub fn has_undeclared(&self) -> bool {
        Semantic::ALL.into_iter().any(|s| self.support(s).reason() == Some(UNDECLARED_REASON))
    }

    /// 是否存在原因为空的不适用档位（自检用：不得出现）。
    #[must_use]
    pub fn has_empty_reason(&self) -> bool {
        Semantic::ALL.into_iter().any(|s| self.support(s).reason().is_some_and(|r| r.trim().is_empty()))
    }
}

impl Default for SemanticProfile {
    fn default() -> Self {
        Self::undeclared()
    }
}

/// `sync` 的冲突裁决策略。
///
/// 默认 [`ConflictPolicy::ExternalWins`]（**外部优先**）：外部系统是状态权威方，
/// 平台侧变更只在外部未更新时回写。`local-wins`（**本地优先**）用于平台是权威方的部署。
/// 由设置项 [`SETTING_CONFLICT_POLICY`] 配置，合法值见 [`ConflictPolicy::parse`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictPolicy {
    /// 外部优先（默认）：冲突时以外部为准，**不回写**，并记录决策日志。
    ExternalWins,
    /// 本地优先：冲突时以本地为准，**回写外部**，并记录决策日志。
    LocalWins,
}

impl ConflictPolicy {
    /// 默认策略（外部优先）。
    pub const DEFAULT: Self = Self::ExternalWins;

    /// 全部策略（控制台下拉用）。
    pub const ALL: [Self; 2] = [Self::ExternalWins, Self::LocalWins];

    /// 文本形式（设置值口径）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalWins => "external-wins",
            Self::LocalWins => "local-wins",
        }
    }

    /// 中文显示名。
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::ExternalWins => "外部优先",
            Self::LocalWins => "本地优先",
        }
    }

    /// 解析设置值（容忍中英文常见写法；无法识别返回 `None`）。
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "external-wins" | "external" | "remote-wins" | "外部优先" | "以外部为准" => {
                Some(Self::ExternalWins)
            }
            "local-wins" | "local" | "platform-wins" | "本地优先" | "以本地为准" => Some(Self::LocalWins),
            _ => None,
        }
    }

    /// 从适配器设置解析（缺省为 [`Self::DEFAULT`]；非法值由 `AdapterSettings::validate` 拒绝）。
    #[must_use]
    pub fn from_settings(settings: &AdapterSettings) -> Self {
        settings.get_str(SETTING_CONFLICT_POLICY).and_then(Self::parse).unwrap_or(Self::DEFAULT)
    }
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for ConflictPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::AdapterCategory;
    use crate::contract::AdapterMetadata;
    use crate::test_support::{config_for, secrets};

    #[test]
    fn semantic_keys_and_display_names_are_stable() {
        assert_eq!(Semantic::ALL.map(Semantic::as_str), ["push", "pull", "sync"]);
        for semantic in Semantic::ALL {
            assert!(!semantic.display_name().is_empty());
            assert_eq!(semantic.to_string(), semantic.as_str());
        }
    }

    #[test]
    fn support_matrix_requires_reason_for_unsupported() {
        let implemented = SemanticSupport::implemented();
        assert!(implemented.is_implemented());
        assert_eq!(implemented.reason(), None);
        assert_eq!(implemented.markdown_cell(), "✅ 已实现");

        let unsupported = SemanticSupport::unsupported("无读取接口");
        assert!(!unsupported.is_implemented());
        assert_eq!(unsupported.reason(), Some("无读取接口"));
        assert_eq!(unsupported.markdown_cell(), "⛔ Unsupported：无读取接口");
        assert!(unsupported.to_string().contains("无读取接口"));
    }

    #[test]
    fn profiles_report_implemented_and_undeclared() {
        let full = SemanticProfile::full();
        assert_eq!(full.implemented(), Semantic::ALL.to_vec());
        assert!(!full.has_undeclared());
        assert!(!full.has_empty_reason());

        let push_only = SemanticProfile::push_only("无读取语义", "无对账语义");
        assert_eq!(push_only.implemented(), vec![Semantic::Push]);
        assert!(!push_only.is_implemented(Semantic::Pull));

        let undeclared = SemanticProfile::default();
        assert!(undeclared.has_undeclared(), "默认档位必须如实标注为未登记");
        assert!(!undeclared.has_empty_reason());

        let empty = SemanticProfile::send_only("", "", "");
        assert!(empty.has_empty_reason(), "空原因必须能被自检发现");
    }

    #[test]
    fn conflict_policy_parsing_and_settings_default() {
        assert_eq!(ConflictPolicy::default(), ConflictPolicy::ExternalWins);
        assert_eq!(ConflictPolicy::DEFAULT.as_str(), "external-wins");
        assert_eq!(ConflictPolicy::parse("local-wins"), Some(ConflictPolicy::LocalWins));
        assert_eq!(ConflictPolicy::parse("  LOCAL  "), Some(ConflictPolicy::LocalWins));
        assert_eq!(ConflictPolicy::parse("本地优先"), Some(ConflictPolicy::LocalWins));
        assert_eq!(ConflictPolicy::parse("外部优先"), Some(ConflictPolicy::ExternalWins));
        assert_eq!(ConflictPolicy::parse("whatever"), None);
        assert_eq!(ConflictPolicy::ALL.len(), 2);

        let meta = AdapterMetadata::new("t", "T", "t", AdapterCategory::Itsm);
        let bare = AdapterSettings::defaults(&meta);
        assert_eq!(ConflictPolicy::from_settings(&bare), ConflictPolicy::ExternalWins, "缺省必须外部优先");
        let configured = AdapterSettings::from_config(
            &meta,
            &config_for("t", &[(SETTING_CONFLICT_POLICY, serde_json::json!("local-wins"))], false),
            &secrets(&[]),
        )
        .expect("合法设置");
        assert_eq!(ConflictPolicy::from_settings(&configured), ConflictPolicy::LocalWins);
    }
}

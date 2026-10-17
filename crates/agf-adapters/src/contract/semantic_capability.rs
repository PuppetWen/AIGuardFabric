//! 能力矩阵的**一行**（[`SemanticCapability`]）与其 Markdown 渲染。
//!
//! 由 `semantics.rs` 拆分（单文件行数守卫）：[`crate::contract::semantics`] 只放
//! 语义契约与档位定义，本模块放"能力矩阵的一行"这一展示/对账形态。
//! 真源仍是各厂商的 [`AdapterMetadata::semantics`]（本类型只是它的只读投影 + 测试证据）。

use crate::contract::AdapterCategory;
use crate::contract::AdapterMetadata;
use crate::contract::Semantic;
use crate::contract::SemanticSupport;

/// 单适配器的语义能力行（能力矩阵的一行）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SemanticCapability {
    /// 注册名。
    pub adapter: String,
    /// 显示名。
    pub display_name: String,
    /// 分类。
    pub category: AdapterCategory,
    /// `send` 主路径档位（`real_transport=false` 的脚手架适配器为 `Unsupported`）。
    pub send: SemanticSupport,
    /// `push` 档位。
    pub push: SemanticSupport,
    /// `pull` 档位。
    pub pull: SemanticSupport,
    /// `sync` 档位。
    pub sync: SemanticSupport,
    /// 是否有**真实往返测试**（wiremock / 本地假服务端）守住。
    pub tested: bool,
    /// 测试证据（集成测试函数名；`Unsupported` 时写明"未测（语义不适用）"）。
    pub evidence: String,
}

impl SemanticCapability {
    /// 由元信息 + 测试证据构造。
    #[must_use]
    pub fn from_metadata(meta: &AdapterMetadata, tested: bool, evidence: &str) -> Self {
        let send = if meta.real_transport {
            SemanticSupport::implemented()
        } else {
            SemanticSupport::unsupported("真实传输未实现（脚手架阶段，见 TODO 锚点）")
        };
        Self {
            adapter: meta.name.clone(),
            display_name: meta.display_name.clone(),
            category: meta.category,
            send,
            push: meta.semantics.push.clone(),
            pull: meta.semantics.pull.clone(),
            sync: meta.semantics.sync.clone(),
            tested,
            evidence: evidence.to_string(),
        }
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

    /// 该适配器是否有任一条外部语义已实现。
    #[must_use]
    pub fn has_implemented_semantics(&self) -> bool {
        Semantic::ALL.into_iter().any(|s| self.support(s).is_implemented())
    }

    /// 该适配器是否**所有**外部语义都不适用（纯投递通道）。
    #[must_use]
    pub fn is_send_only(&self) -> bool {
        !self.has_implemented_semantics()
    }

    /// Markdown 表格行：`适配器 | send | push | pull | sync | 是否真测 | 证据`。
    #[must_use]
    pub fn markdown_row(&self) -> String {
        format!(
            "| `{}`（{}） | {} | {} | {} | {} | {} | {} |",
            self.adapter,
            self.display_name,
            self.send.markdown_cell(),
            self.push.markdown_cell(),
            self.pull.markdown_cell(),
            self.sync.markdown_cell(),
            if self.tested { "是" } else { "否" },
            self.evidence,
        )
    }

    /// Markdown 表头。
    #[must_use]
    pub fn markdown_header() -> &'static str {
        "| 适配器 | send | push | pull | sync | 是否真测 | 证据 |\n|---|---|---|---|---|---|---|"
    }

    /// 渲染整张能力矩阵表。
    #[must_use]
    pub fn markdown_table(rows: &[Self]) -> String {
        let mut out = String::from(Self::markdown_header());
        out.push('\n');
        for row in rows {
            out.push_str(&row.markdown_row());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::SemanticProfile;

    #[test]
    fn capability_row_and_table_render_reasons() {
        let meta = AdapterMetadata::new("feishu", "飞书", "字节跳动", AdapterCategory::Notification)
            .with_real_transport(true)
            .with_semantics(SemanticProfile::send_only("无更新接口", "无读取接口", "无对账语义"));
        let row = SemanticCapability::from_metadata(&meta, false, "未测（语义不适用）");
        assert!(row.send.is_implemented());
        assert!(row.is_send_only());
        assert!(!row.has_implemented_semantics());
        let text = row.markdown_row();
        assert!(text.contains("⛔ Unsupported：无更新接口"), "{text}");
        assert!(text.contains("| 否 |"), "{text}");

        let table = SemanticCapability::markdown_table(&[row]);
        assert!(table.contains("| 适配器 | send | push | pull | sync | 是否真测 | 证据 |"));
        assert!(table.lines().count() >= 3);
    }

    #[test]
    fn scaffold_metadata_reports_send_as_unsupported() {
        let meta = AdapterMetadata::new("brand-new", "自研", "自研", AdapterCategory::SecurityPlatform);
        let row = SemanticCapability::from_metadata(&meta, false, "无");
        assert!(!row.send.is_implemented(), "真实传输未实现时 send 必须如实标注 Unsupported");
        assert!(!row.send.reason().unwrap_or_default().is_empty());
    }

    #[test]
    fn fully_implemented_row_serializes_and_roundtrips() {
        let meta = AdapterMetadata::new("jira", "Jira", "Atlassian", AdapterCategory::Itsm)
            .with_real_transport(true)
            .with_semantics(SemanticProfile::full());
        let row = SemanticCapability::from_metadata(&meta, true, "#jira_push");
        assert!(row.has_implemented_semantics() && !row.is_send_only());
        let text = serde_json::to_string(&row).unwrap_or_default();
        let back: Option<SemanticCapability> = serde_json::from_str(&text).ok();
        assert_eq!(back, Some(row));
        assert!(SemanticCapability::markdown_header().starts_with("| 适配器 | send |"));
    }
}

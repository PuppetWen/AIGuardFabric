//! 拓扑血缘构建与查询（§4.1 拓扑血缘：Agent → MCP Server → Tool → 数据源 → 模型）。
//!
//! 本模块是[`agf_core::topology`]之上的**构建层**：把资产台账与依赖关系
//! 转换成拓扑图，并提供安全语义相关的查询（外传路径、影响面、影子资产）。

use std::collections::BTreeMap;

use agf_core::asset::Asset;
use agf_core::enums::{AssetKind, Severity};
use agf_core::ids::Id;
use agf_core::time::Timestamp;
use agf_core::topology::{EdgeKind, Topology, TopologyEdge, TopologyNode, TopologyStats};

/// 拓扑构建器。
#[derive(Debug, Clone, Default)]
pub struct TopologyBuilder {
    include_isolated: bool,
    include_archived: bool,
}

impl TopologyBuilder {
    /// 默认配置：包含孤立节点（便于发现未纳管资产），排除已归档资产。
    #[must_use]
    pub fn new() -> Self {
        Self { include_isolated: true, include_archived: false }
    }

    /// 是否包含孤立节点。
    #[must_use]
    pub const fn with_isolated(mut self, include: bool) -> Self {
        self.include_isolated = include;
        self
    }

    /// 是否包含已归档资产。
    #[must_use]
    pub const fn with_archived(mut self, include: bool) -> Self {
        self.include_archived = include;
        self
    }

    /// 由资产列表与依赖关系构图。
    ///
    /// `dependencies`：`(下游资产, 上游资产, 边类型)` 三元组列表。
    /// 平台主要依赖 `assets.dependencies` 字段，但 MCP→Tool、Tool→DataSource
    /// 这类关系由发现器显式产出，因此这里接收显式边。
    #[must_use]
    pub fn build(&self, assets: &[Asset], dependencies: &[(Id, Id, EdgeKind)]) -> Topology {
        let mut topo = Topology {
            tenant_id: assets.first().map(|a| a.tenant_id),
            generated_at: Some(Timestamp::now()),
            ..Topology::default()
        };
        for a in assets {
            if !self.include_archived && a.lifecycle == agf_core::enums::LifecycleState::Archived {
                continue;
            }
            topo.upsert_node(TopologyNode {
                id: a.id,
                kind: a.kind,
                label: a.name.clone(),
                zone: a.network_zone.clone(),
                exposure_score: a.exposure_score,
                risk_score: a.risk_score,
                shadow: matches!(a.lifecycle, agf_core::enums::LifecycleState::Trial)
                    && a.discovery_source != agf_core::enums::DiscoverySource::Manual,
            });
        }

        // 显式边
        let known: std::collections::BTreeSet<Id> = topo.nodes.iter().map(|n| n.id).collect();
        for (from, to, kind) in dependencies {
            if known.contains(from) && known.contains(to) {
                topo.add_edge(TopologyEdge {
                    from: *from,
                    to: *to,
                    kind: *kind,
                    discovered_at: Timestamp::now(),
                    note: None,
                });
            }
        }

        // 由 assets.dependencies 补充 DependsOn 边（去重由 add_edge 保证）
        let kind_of: BTreeMap<Id, AssetKind> = assets.iter().map(|a| (a.id, a.kind)).collect();
        for a in assets {
            for dep in &a.dependencies {
                if !known.contains(dep) || !known.contains(&a.id) {
                    continue;
                }
                let edge_kind = match (a.kind, kind_of.get(dep).copied()) {
                    (AssetKind::Agent, Some(AssetKind::McpServer)) => EdgeKind::AgentUsesMcp,
                    (AssetKind::McpServer, Some(AssetKind::Skill)) => EdgeKind::McpExposesTool,
                    (AssetKind::Skill, Some(AssetKind::DataSource)) => EdgeKind::ToolAccessesData,
                    (_, Some(AssetKind::ModelEndpoint)) => EdgeKind::CallsModel,
                    (_, Some(AssetKind::RagKb)) => EdgeKind::RagFeedsContext,
                    (_, Some(AssetKind::Credential)) => EdgeKind::UsesCredential,
                    _ => EdgeKind::DependsOn,
                };
                topo.add_edge(TopologyEdge {
                    from: a.id,
                    to: *dep,
                    kind: edge_kind,
                    discovered_at: Timestamp::now(),
                    note: None,
                });
            }
        }

        if !self.include_isolated {
            let linked: std::collections::BTreeSet<Id> = topo.edges.iter().flat_map(|e| [e.from, e.to]).collect();
            topo.nodes.retain(|n| linked.contains(&n.id));
        }
        topo
    }
}

/// 拓扑摘要（控制台顶栏与报表使用）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TopologySummary {
    /// 基础统计。
    pub stats: TopologyStats,
    /// 按类型统计的节点数。
    pub by_kind: BTreeMap<String, usize>,
    /// 影子资产（发现但未评审）的 id 与名称。
    pub shadow_assets: Vec<(Id, String)>,
    /// 高风险节点（暴露面 ≥ 70）的 id 与评分。
    pub high_exposure: Vec<(Id, u8)>,
    /// 数据外传路径数量（受限数据 → 模型/外网）。
    pub exfil_path_count: usize,
    /// 最长的外传路径长度。
    pub longest_exfil_path: usize,
}

impl TopologySummary {
    /// 由拓扑计算摘要。
    #[must_use]
    pub fn from_topology(topo: &Topology) -> Self {
        let stats = topo.stats();
        let shadow_assets: Vec<(Id, String)> =
            topo.nodes.iter().filter(|n| n.shadow).map(|n| (n.id, n.label.clone())).collect();
        let mut high_exposure: Vec<(Id, u8)> =
            topo.nodes.iter().filter(|n| n.exposure_score >= 70).map(|n| (n.id, n.exposure_score)).collect();
        high_exposure.sort_by_key(|(_, s)| std::cmp::Reverse(*s));

        // 外传路径：受限数据类资产 → 模型端点 / 外部资产
        let sources: Vec<Id> = topo
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, AssetKind::DataSource | AssetKind::RagKb | AssetKind::VectorStore))
            .map(|n| n.id)
            .collect();
        let sinks: Vec<Id> =
            topo.nodes.iter().filter(|n| matches!(n.kind, AssetKind::ModelEndpoint)).map(|n| n.id).collect();
        let paths = topo.find_exfil_paths(&sources, &sinks, 64);
        let longest = paths.iter().map(Vec::len).max().unwrap_or(0);
        Self {
            by_kind: stats.by_kind.clone(),
            stats,
            shadow_assets,
            high_exposure,
            exfil_path_count: paths.len(),
            longest_exfil_path: longest,
        }
    }

    /// 是否存在需要立即处置的拓扑风险（影子资产或高暴露）。
    #[must_use]
    pub fn has_urgent_risk(&self) -> bool {
        !self.shadow_assets.is_empty() || self.high_exposure.iter().any(|(_, s)| *s >= 85)
    }

    /// 综合风险等级（用于总览大屏配色）。
    #[must_use]
    pub fn risk_level(&self) -> Severity {
        if self.high_exposure.iter().any(|(_, s)| *s >= 85) || self.exfil_path_count > 5 {
            Severity::Critical
        } else if !self.shadow_assets.is_empty() || self.high_exposure.len() > 3 {
            Severity::High
        } else if self.exfil_path_count > 0 || !self.high_exposure.is_empty() {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::enums::{DiscoverySource, LifecycleState};
    use agf_core::ids::TenantId;

    fn asset(kind: AssetKind, name: &str, deps: Vec<Id>) -> Asset {
        let mut a = Asset::new(TenantId::default_tenant(), kind, name, format!("fp-{name}"));
        a.dependencies = deps;
        a
    }

    #[test]
    fn build_infers_edge_kinds_from_dependencies() {
        let mcp = asset(AssetKind::McpServer, "fs-mcp", vec![]);
        let tool = asset(AssetKind::Skill, "read_file", vec![]);
        let data = asset(AssetKind::DataSource, "本地文档库", vec![]);
        let model = asset(AssetKind::ModelEndpoint, "gpt-4o", vec![]);
        let agent = asset(AssetKind::Agent, "claude-code", vec![mcp.id, model.id]);

        let edges = vec![(mcp.id, tool.id, EdgeKind::McpExposesTool), (tool.id, data.id, EdgeKind::ToolAccessesData)];
        let topo = TopologyBuilder::new().build(&[agent, mcp, tool, data, model], &edges);
        assert_eq!(topo.nodes.len(), 5);
        assert!(topo.edges.iter().any(|e| e.kind == EdgeKind::McpExposesTool));
        assert!(topo.edges.iter().any(|e| e.kind == EdgeKind::ToolAccessesData));
        // from dependencies 字段推断
        assert!(topo.edges.iter().any(|e| e.kind == EdgeKind::AgentUsesMcp));
        assert!(topo.edges.iter().any(|e| e.kind == EdgeKind::CallsModel));
    }

    #[test]
    fn archived_assets_excluded_by_default() {
        let mut a = asset(AssetKind::McpServer, "old-mcp", vec![]);
        a.lifecycle = LifecycleState::Archived;
        let b = asset(AssetKind::Agent, "agent", vec![]);
        let topo = TopologyBuilder::new().build(&[a, b], &[]);
        assert_eq!(topo.nodes.len(), 1);
        let all = TopologyBuilder::new().with_archived(true).build(
            &[
                {
                    let mut x = asset(AssetKind::McpServer, "old-mcp", vec![]);
                    x.lifecycle = LifecycleState::Archived;
                    x
                },
                asset(AssetKind::Agent, "agent", vec![]),
            ],
            &[],
        );
        assert_eq!(all.nodes.len(), 2);
    }

    #[test]
    fn isolated_nodes_can_be_excluded() {
        let linked_a = asset(AssetKind::Agent, "a", vec![]);
        let linked_b = asset(AssetKind::McpServer, "b", vec![]);
        let orphan = asset(AssetKind::IdePlugin, "orphan", vec![]);
        let edges = vec![(linked_a.id, linked_b.id, EdgeKind::AgentUsesMcp)];
        let with_isolated = TopologyBuilder::new().build(&[linked_a.clone(), linked_b.clone(), orphan.clone()], &edges);
        assert_eq!(with_isolated.nodes.len(), 3);
        let without = TopologyBuilder::new().with_isolated(false).build(&[linked_a, linked_b, orphan], &edges);
        assert_eq!(without.nodes.len(), 2);
    }

    #[test]
    fn edges_to_unknown_nodes_are_dropped() {
        let a = asset(AssetKind::Agent, "a", vec![]);
        let nodes = vec![a.clone()];
        let topo = TopologyBuilder::new().build(&nodes, &[(a.id, Id::new(), EdgeKind::DependsOn)]);
        assert!(topo.edges.is_empty(), "指向未知节点的边必须被丢弃（避免悬挂引用）");
    }

    #[test]
    fn shadow_detection_uses_lifecycle_and_source() {
        let mut shadow = asset(AssetKind::McpServer, "shadow", vec![]);
        shadow.lifecycle = LifecycleState::Trial;
        shadow.discovery_source = DiscoverySource::NetworkScan;
        let mut manual = asset(AssetKind::McpServer, "manual", vec![]);
        manual.lifecycle = LifecycleState::Trial;
        manual.discovery_source = DiscoverySource::Manual;
        let topo = TopologyBuilder::new().build(&[shadow, manual], &[]);
        let summary = TopologySummary::from_topology(&topo);
        assert_eq!(summary.shadow_assets.len(), 1);
        assert_eq!(summary.shadow_assets[0].1, "shadow");
    }

    #[test]
    fn exfil_paths_detected_and_summarized() {
        let kb = asset(AssetKind::RagKb, "kb", vec![]);
        let tool = asset(AssetKind::Skill, "search", vec![kb.id]);
        let model = asset(AssetKind::ModelEndpoint, "external-gpt", vec![]);
        let edges = vec![(kb.id, tool.id, EdgeKind::RagFeedsContext), (tool.id, model.id, EdgeKind::CallsModel)];
        let topo = TopologyBuilder::new().build(&[kb, tool, model], &edges);
        let summary = TopologySummary::from_topology(&topo);
        assert_eq!(summary.exfil_path_count, 1);
        assert_eq!(summary.longest_exfil_path, 3);
        assert!(summary.risk_level() >= Severity::Medium);
    }

    #[test]
    fn summary_risk_level_escalates_with_high_exposure() {
        let mut risky = asset(AssetKind::McpServer, "risky", vec![]);
        risky.exposure_score = 92;
        let topo = TopologyBuilder::new().build(&[risky], &[]);
        let summary = TopologySummary::from_topology(&topo);
        assert_eq!(summary.risk_level(), Severity::Critical);
        assert!(summary.has_urgent_risk());
        assert_eq!(summary.high_exposure.len(), 1);
    }

    #[test]
    fn clean_topology_is_low_risk() {
        let a = asset(AssetKind::Agent, "agent", vec![]);
        let topo = TopologyBuilder::new().build(&[a], &[]);
        let summary = TopologySummary::from_topology(&topo);
        assert_eq!(summary.risk_level(), Severity::Low);
        assert!(!summary.has_urgent_risk());
        assert_eq!(summary.exfil_path_count, 0);
        assert_eq!(summary.longest_exfil_path, 0);
    }

    #[test]
    fn by_kind_counts_match_nodes() {
        let assets = vec![
            asset(AssetKind::Agent, "a1", vec![]),
            asset(AssetKind::Agent, "a2", vec![]),
            asset(AssetKind::McpServer, "m1", vec![]),
        ];
        let topo = TopologyBuilder::new().build(&assets, &[]);
        let summary = TopologySummary::from_topology(&topo);
        assert_eq!(summary.by_kind.get("agent"), Some(&2));
        assert_eq!(summary.by_kind.get("mcp-server"), Some(&1));
        assert_eq!(summary.stats.node_count, 3);
    }
}

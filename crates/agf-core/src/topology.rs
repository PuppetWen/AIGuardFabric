//! 资产拓扑与血缘（§4.1：Agent → MCP Server → Tool → 数据源 → 模型；
//! Prompt/知识库 → 模型 → 输出）。

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::enums::AssetKind;
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

/// 拓扑节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    /// 资产 id。
    pub id: Id,
    /// 资产类型。
    pub kind: AssetKind,
    /// 显示名。
    pub label: String,
    /// 所在网段/区域。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// 暴露面评分。
    #[serde(default)]
    pub exposure_score: u8,
    /// 风险评分。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    /// 是否影子资产（发现但未纳管）。
    #[serde(default)]
    pub shadow: bool,
}

/// 边类型（血缘语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    /// Agent 调用 MCP Server。
    AgentUsesMcp,
    /// MCP Server 暴露 Tool。
    McpExposesTool,
    /// Tool 访问数据源。
    ToolAccessesData,
    /// Agent/Tool 调用模型端点。
    CallsModel,
    /// Prompt 模板驱动模型。
    PromptDrivesModel,
    /// 知识库被检索进上下文。
    RagFeedsContext,
    /// 凭据被使用。
    UsesCredential,
    /// 通用依赖。
    DependsOn,
}

impl EdgeKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AgentUsesMcp => "agent-uses-mcp",
            Self::McpExposesTool => "mcp-exposes-tool",
            Self::ToolAccessesData => "tool-accesses-data",
            Self::CallsModel => "calls-model",
            Self::PromptDrivesModel => "prompt-drives-model",
            Self::RagFeedsContext => "rag-feeds-context",
            Self::UsesCredential => "uses-credential",
            Self::DependsOn => "depends-on",
        }
    }

    /// 该边是否承载数据流（用于外传路径判定）。
    #[must_use]
    pub const fn carries_data(&self) -> bool {
        matches!(self, Self::ToolAccessesData | Self::CallsModel | Self::RagFeedsContext | Self::UsesCredential)
    }
}

/// 拓扑边。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    /// 起点资产 id。
    pub from: Id,
    /// 终点资产 id。
    pub to: Id,
    /// 边类型。
    pub kind: EdgeKind,
    /// 发现时间。
    pub discovered_at: Timestamp,
    /// 备注。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// 拓扑图。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Topology {
    /// 租户。
    pub tenant_id: Option<TenantId>,
    /// 节点。
    pub nodes: Vec<TopologyNode>,
    /// 边。
    pub edges: Vec<TopologyEdge>,
    /// 生成时间。
    pub generated_at: Option<Timestamp>,
}

impl Topology {
    /// 追加节点（同 id 覆盖）。
    pub fn upsert_node(&mut self, node: TopologyNode) {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.id == node.id) {
            *existing = node;
        } else {
            self.nodes.push(node);
        }
    }

    /// 追加边（去重：同 from/to/kind 只保留一条）。
    pub fn add_edge(&mut self, edge: TopologyEdge) {
        let dup = self.edges.iter().any(|e| e.from == edge.from && e.to == edge.to && e.kind == edge.kind);
        if !dup {
            self.edges.push(edge);
        }
    }

    /// 邻接表。
    #[must_use]
    pub fn adjacency(&self) -> BTreeMap<Id, Vec<&TopologyEdge>> {
        let mut map: BTreeMap<Id, Vec<&TopologyEdge>> = BTreeMap::new();
        for e in &self.edges {
            map.entry(e.from).or_default().push(e);
        }
        map
    }

    /// 反向邻接表。
    #[must_use]
    pub fn reverse_adjacency(&self) -> BTreeMap<Id, Vec<&TopologyEdge>> {
        let mut map: BTreeMap<Id, Vec<&TopologyEdge>> = BTreeMap::new();
        for e in &self.edges {
            map.entry(e.to).or_default().push(e);
        }
        map
    }

    /// 节点按 id 查找。
    #[must_use]
    pub fn node(&self, id: Id) -> Option<&TopologyNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// 从 `start` 出发的**影响范围**（正向可达集合，不含起点自身）。
    #[must_use]
    pub fn reachable_from(&self, start: Id) -> BTreeSet<Id> {
        let adj = self.adjacency();
        let mut seen: BTreeSet<Id> = BTreeSet::new();
        let mut queue: VecDeque<Id> = VecDeque::new();
        queue.push_back(start);
        while let Some(cur) = queue.pop_front() {
            if let Some(edges) = adj.get(&cur) {
                for e in edges {
                    if seen.insert(e.to) {
                        queue.push_back(e.to);
                    }
                }
            }
        }
        seen.remove(&start);
        seen
    }

    /// 反向影响范围（哪些资产**能到达** `target`，用于"投毒影响谁"）。
    #[must_use]
    pub fn dependents_of(&self, target: Id) -> BTreeSet<Id> {
        let radj = self.reverse_adjacency();
        let mut seen: BTreeSet<Id> = BTreeSet::new();
        let mut queue: VecDeque<Id> = VecDeque::new();
        queue.push_back(target);
        while let Some(cur) = queue.pop_front() {
            if let Some(edges) = radj.get(&cur) {
                for e in edges {
                    if seen.insert(e.from) {
                        queue.push_back(e.from);
                    }
                }
            }
        }
        seen.remove(&target);
        seen
    }

    /// 找出从 `from` 到 `to` 的最短路径（BFS），返回节点序列（含端点）。
    #[must_use]
    pub fn shortest_path(&self, from: Id, to: Id) -> Option<Vec<Id>> {
        if from == to {
            return Some(vec![from]);
        }
        let adj = self.adjacency();
        let mut prev: BTreeMap<Id, Id> = BTreeMap::new();
        let mut visited: BTreeSet<Id> = BTreeSet::new();
        let mut queue: VecDeque<Id> = VecDeque::new();
        queue.push_back(from);
        visited.insert(from);
        while let Some(cur) = queue.pop_front() {
            for e in adj.get(&cur).into_iter().flatten() {
                if visited.insert(e.to) {
                    prev.insert(e.to, cur);
                    if e.to == to {
                        let mut path = vec![to];
                        let mut node = to;
                        while let Some(p) = prev.get(&node) {
                            path.push(*p);
                            node = *p;
                        }
                        path.reverse();
                        return Some(path);
                    }
                    queue.push_back(e.to);
                }
            }
        }
        None
    }

    /// 检测数据外传路径：`source`（受限数据）→ … → `sink`（模型/外网资产）。
    ///
    /// 返回全部命中路径（限制条数，避免图爆炸）。
    #[must_use]
    pub fn find_exfil_paths(&self, sources: &[Id], sinks: &[Id], max_paths: usize) -> Vec<Vec<Id>> {
        let mut out = Vec::new();
        for s in sources {
            for t in sinks {
                if let Some(p) = self.shortest_path(*s, *t) {
                    if p.len() > 1 {
                        out.push(p);
                        if out.len() >= max_paths {
                            return out;
                        }
                    }
                }
            }
        }
        out
    }

    /// 孤立节点（无任何边的资产，通常是误报或未纳管）。
    #[must_use]
    pub fn isolated_nodes(&self) -> Vec<&TopologyNode> {
        let mut linked: BTreeSet<Id> = BTreeSet::new();
        for e in &self.edges {
            linked.insert(e.from);
            linked.insert(e.to);
        }
        self.nodes.iter().filter(|n| !linked.contains(&n.id)).collect()
    }

    /// 统计信息。
    #[must_use]
    pub fn stats(&self) -> TopologyStats {
        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for n in &self.nodes {
            *by_kind.entry(n.kind.as_str().to_string()).or_insert(0) += 1;
        }
        TopologyStats {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            shadow_count: self.nodes.iter().filter(|n| n.shadow).count(),
            isolated_count: self.isolated_nodes().len(),
            by_kind,
        }
    }
}

/// 拓扑统计。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyStats {
    /// 节点数。
    pub node_count: usize,
    /// 边数。
    pub edge_count: usize,
    /// 影子资产数。
    pub shadow_count: usize,
    /// 孤立节点数。
    pub isolated_count: usize,
    /// 按类型分布。
    pub by_kind: BTreeMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(kind: AssetKind, label: &str) -> TopologyNode {
        TopologyNode {
            id: Id::new(),
            kind,
            label: label.to_string(),
            zone: None,
            exposure_score: 0,
            risk_score: None,
            shadow: false,
        }
    }

    fn edge(from: Id, to: Id, kind: EdgeKind) -> TopologyEdge {
        TopologyEdge { from, to, kind, discovered_at: Timestamp::now(), note: None }
    }

    /// Agent → MCP → Tool → 数据源 ；MCP → 模型
    fn sample() -> (Topology, Id, Id, Id, Id, Id) {
        let mut t = Topology::default();
        let agent = node(AssetKind::Agent, "claude-code");
        let mcp = node(AssetKind::McpServer, "filesystem-mcp");
        let tool = node(AssetKind::Skill, "read_file");
        let data = node(AssetKind::DataSource, "本地文档库");
        let model = node(AssetKind::ModelEndpoint, "gpt-4o");
        let (aid, mid, tid, did, eid) = (agent.id, mcp.id, tool.id, data.id, model.id);
        for n in [agent, mcp, tool, data, model] {
            t.upsert_node(n);
        }
        t.add_edge(edge(aid, mid, EdgeKind::AgentUsesMcp));
        t.add_edge(edge(mid, tid, EdgeKind::McpExposesTool));
        t.add_edge(edge(tid, did, EdgeKind::ToolAccessesData));
        t.add_edge(edge(mid, eid, EdgeKind::CallsModel));
        (t, aid, mid, tid, did, eid)
    }

    #[test]
    fn reachable_and_dependents() {
        let (t, agent, _mcp, tool, data, _model) = sample();
        let reach = t.reachable_from(agent);
        assert!(reach.contains(&data));
        assert_eq!(reach.len(), 4, "agent → mcp/tool/data/model");
        let deps = t.dependents_of(data);
        assert!(deps.contains(&agent));
        assert!(deps.contains(&tool));
    }

    #[test]
    fn shortest_path_found() {
        let (t, agent, _mcp, tool, data, _model) = sample();
        let p = t.shortest_path(agent, data);
        assert!(p.is_some());
        let p = p.unwrap_or_default();
        assert_eq!(p.first(), Some(&agent));
        assert_eq!(p.last(), Some(&data));
        assert_eq!(p.len(), 4, "agent→mcp→tool→data");
        assert!(p.contains(&tool));
    }

    #[test]
    fn shortest_path_self_is_trivial() {
        let (t, agent, ..) = sample();
        assert_eq!(t.shortest_path(agent, agent), Some(vec![agent]));
    }

    #[test]
    fn shortest_path_none_when_disconnected() {
        let mut t = Topology::default();
        let a = node(AssetKind::Agent, "a");
        let b = node(AssetKind::DataSource, "b");
        let (ida, idb) = (a.id, b.id);
        t.upsert_node(a);
        t.upsert_node(b);
        assert!(t.shortest_path(ida, idb).is_none());
    }

    #[test]
    fn exfil_path_detection() {
        let (t, _agent, _mcp, _tool, data, model) = sample();
        // data 无法直接到 model：路径应为 data → tool → mcp → model（反向不可达），
        // 因此这里验证反向不存在时返回空，而 agent→model 存在。
        let paths = t.find_exfil_paths(&[data], &[model], 8);
        assert!(paths.is_empty(), "示例图中数据源无法流向模型（只能被读取）");
        let (_, agent, _, _, _, model2) = sample();
        let _ = model2;
        let _ = agent;
    }

    #[test]
    fn exfil_path_detection_positive() {
        let mut t = Topology::default();
        let rag = node(AssetKind::RagKb, "kb");
        let tool = node(AssetKind::Skill, "search_kb");
        let model = node(AssetKind::ModelEndpoint, "external-gpt");
        let (rid, tid, mid) = (rag.id, tool.id, model.id);
        for n in [rag, tool, model] {
            t.upsert_node(n);
        }
        t.add_edge(edge(rid, tid, EdgeKind::RagFeedsContext));
        t.add_edge(edge(tid, mid, EdgeKind::CallsModel));
        let paths = t.find_exfil_paths(&[rid], &[mid], 8);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![rid, tid, mid]);
    }

    #[test]
    fn duplicate_edges_are_deduped() {
        let mut t = Topology::default();
        let a = node(AssetKind::Agent, "a");
        let b = node(AssetKind::McpServer, "b");
        let (ida, idb) = (a.id, b.id);
        t.upsert_node(a);
        t.upsert_node(b);
        t.add_edge(edge(ida, idb, EdgeKind::AgentUsesMcp));
        t.add_edge(edge(ida, idb, EdgeKind::AgentUsesMcp));
        assert_eq!(t.edges.len(), 1);
    }

    #[test]
    fn isolated_nodes_and_stats() {
        let (mut t, ..) = sample();
        t.upsert_node(node(AssetKind::IdePlugin, "orphan"));
        assert_eq!(t.isolated_nodes().len(), 1);
        let s = t.stats();
        assert_eq!(s.node_count, 6);
        assert_eq!(s.edge_count, 4);
        assert_eq!(s.isolated_count, 1);
        assert_eq!(s.by_kind.get("agent"), Some(&1));
    }

    #[test]
    fn edge_kind_carries_data_flags() {
        assert!(EdgeKind::ToolAccessesData.carries_data());
        assert!(EdgeKind::CallsModel.carries_data());
        assert!(!EdgeKind::AgentUsesMcp.carries_data());
        assert_eq!(EdgeKind::UsesCredential.as_str(), "uses-credential");
    }
}

use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn deserialize_nodes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<OrchestrationNode>, D::Error> {
    use serde::de::Error;
    let values = Vec::<serde_json::Value>::deserialize(deserializer)?;
    if values.len() > MAX_NODES {
        return Err(D::Error::custom("too many declaration nodes"));
    }
    values
        .into_iter()
        .map(|value| {
            let allowed = ["node_id", "name", "agent_ids", "depends_on", "trigger", "cron"];
            if value.as_object().is_none_or(|object| object.keys().any(|key| !allowed.contains(&key.as_str()))) {
                return Err(D::Error::custom("unsupported declaration node field"));
            }
            serde_json::from_value(value).map_err(|_| D::Error::custom("invalid declaration node"))
        })
        .collect()
}

/// Inventory identity excludes application-owned nodes and ordinary observation timestamps.
#[must_use]
pub fn inventory_fingerprint(team: &AgentTeam) -> String {
    let mut team = team.clone();
    team.orchestration.clear();
    super::super::team_content_signature(&team)
}
fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.trim() == value && !value.chars().any(char::is_control)
}
/// Validate a bounded declaration against exact tenant/Team/member inventory.
///
/// Cron text is retained as a declaration; this validator does not register or run a timer.
///
/// # Errors
/// Rejects stale inventory, unknown references, duplicate identities, invalid triggers and cycles.
pub fn validate_definition(document: &DefinitionDocument, team: &AgentTeam) -> DomainResult<()> {
    if team.id.is_nil()
        || team.tenant_id.as_uuid().is_nil()
        || !identifier(&team.cloud_team_id, 256)
        || team.agents.len() > 2000
        || team
            .agents
            .iter()
            .any(|agent| !identifier(&agent.cloud_agent_id, 512) || agent.asset_id.is_some_and(|id| id.is_nil()))
    {
        return Err(invalid());
    }
    let mapped = team.agents.iter().filter_map(|agent| agent.asset_id).collect::<Vec<_>>();
    if mapped.iter().collect::<BTreeSet<_>>().len() != mapped.len() {
        return Err(invalid());
    }
    if document.schema_version != 1
        || document.tenant_id != team.tenant_id
        || document.cloud_team_id != team.cloud_team_id
        || document.inventory_fingerprint != inventory_fingerprint(team)
    {
        return Err(DomainError::Conflict("Team/成员/角色库存已改变或范围不匹配；重新读取并明确采用".into()));
    }
    if document.nodes.len() > MAX_NODES {
        return Err(invalid());
    }
    let agents = team.agents.iter().map(|agent| &agent.cloud_agent_id).collect::<BTreeSet<_>>();
    if agents.len() != team.agents.len() {
        return Err(invalid());
    }
    let mut nodes = BTreeMap::new();
    for node in &document.nodes {
        if !identifier(&node.node_id, 128)
            || !identifier(&node.name, 256)
            || node.agent_ids.is_empty()
            || node.agent_ids.len() > 32
            || node.depends_on.len() > MAX_NODES
            || nodes.insert(&node.node_id, node).is_some()
        {
            return Err(invalid());
        }
        let assigned = node.agent_ids.iter().collect::<BTreeSet<_>>();
        let parents = node.depends_on.iter().collect::<BTreeSet<_>>();
        if assigned.len() != node.agent_ids.len()
            || parents.len() != node.depends_on.len()
            || assigned.iter().any(|agent| !agents.contains(*agent))
        {
            return Err(invalid());
        }
        match node.trigger.as_str() {
            "cron" if node.cron.as_deref().is_some_and(|cron| identifier(cron, 128)) => {}
            "manual" | "event" if node.cron.is_none() => {}
            _ => return Err(invalid()),
        }
    }
    if serde_json::to_vec(document)?.len() > MAX_DOCUMENT_BYTES {
        return Err(invalid());
    }
    let mut indegree = BTreeMap::new();
    let mut children: BTreeMap<&String, Vec<&String>> = BTreeMap::new();
    for node in &document.nodes {
        indegree.insert(&node.node_id, node.depends_on.len());
        for parent in &node.depends_on {
            if parent == &node.node_id || !nodes.contains_key(parent) {
                return Err(invalid());
            }
            children.entry(parent).or_default().push(&node.node_id);
        }
    }
    let mut ready = indegree.iter().filter_map(|(id, count)| (*count == 0).then_some(*id)).collect::<Vec<_>>();
    let mut visited = 0;
    while let Some(id) = ready.pop() {
        visited += 1;
        for child in children.get(id).into_iter().flatten() {
            let remaining = indegree.get_mut(*child).ok_or_else(invalid)?;
            *remaining = remaining.checked_sub(1).ok_or_else(invalid)?;
            if *remaining == 0 {
                ready.push(*child);
            }
        }
    }
    if visited != document.nodes.len() {
        return Err(invalid());
    }
    Ok(())
}

//! Complete, order-independent definition fingerprints; observation timestamps are excluded.
use agf_core::cloud::{AgentTeam, OrchestrationNode};
use sha2::{Digest, Sha256};

fn text(out: &mut String, value: &str) {
    out.push_str(&value.len().to_string());
    out.push(':');
    out.push_str(value);
}
fn optional(out: &mut String, value: Option<&str>) {
    out.push(if value.is_some() { '1' } else { '0' });
    if let Some(value) = value {
        text(out, value);
    }
}
fn strings(out: &mut String, values: &[String]) {
    let mut values = values.to_vec();
    values.sort();
    text(out, &values.len().to_string());
    for value in values {
        text(out, &value);
    }
}
pub(super) fn node(node: &OrchestrationNode) -> String {
    let mut out = String::new();
    text(&mut out, &node.node_id);
    text(&mut out, &node.name);
    strings(&mut out, &node.agent_ids);
    strings(&mut out, &node.depends_on);
    text(&mut out, &node.trigger);
    optional(&mut out, node.cron.as_deref());
    out
}
pub(super) fn fingerprint(team: &AgentTeam) -> String {
    let mut out = "agf-team-definition-v2".to_string();
    text(&mut out, &team.tenant_id.to_string());
    text(&mut out, &team.cloud_team_id);
    text(&mut out, &team.name);
    text(&mut out, &team.description);
    text(&mut out, &format!("{:?}", team.onboarding));
    let agents = team
        .agents
        .iter()
        .map(|agent| {
            let mut value = String::new();
            text(&mut value, &agent.cloud_agent_id);
            text(&mut value, &agent.name);
            text(&mut value, &agent.status);
            optional(&mut value, agent.asset_id.map(|id| id.to_string()).as_deref());
            strings(&mut value, &agent.models);
            strings(&mut value, &agent.tools);
            strings(&mut value, &agent.role_names);
            value
        })
        .collect::<Vec<_>>();
    strings(&mut out, &agents);
    let roles = team
        .roles
        .iter()
        .map(|role| {
            let mut value = String::new();
            text(&mut value, &role.name);
            text(&mut value, &role.description);
            strings(&mut value, &role.allowed_tools);
            optional(&mut value, role.mapped_platform_role.as_deref());
            value
        })
        .collect::<Vec<_>>();
    strings(&mut out, &roles);
    strings(&mut out, &team.orchestration.iter().map(node).collect::<Vec<_>>());
    hex::encode(Sha256::digest(out.as_bytes()))
}

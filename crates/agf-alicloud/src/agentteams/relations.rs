//! One conservative interpretation of public Team/Worker relationships for all consumers.
use super::relations_fields::{self as fields, Groups};
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Evidence for a team's observed Worker membership; it never grants permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationshipEvidence {
    /// Explicit Team.WorkerNames, checked against every known Worker.Groups.
    TeamWorkerNames,
    /// Inferred from complete, explicit Groups for every Worker in the instance.
    WorkerGroups,
    /// The cloud did not provide enough evidence to determine membership.
    Unverified,
}
impl RelationshipEvidence {
    /// Stable console DTO value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TeamWorkerNames => "team-worker-names",
            Self::WorkerGroups => "worker-groups",
            Self::Unverified => "unverified",
        }
    }
}

/// Observed relationships for one Team. `None` differs from an explicitly empty map/set.
#[derive(Debug, Clone)]
pub struct TeamRelationships {
    /// Worker name → raw cloud role, or unknown role. Humans are never inserted here.
    pub workers: Option<BTreeMap<String, Option<String>>>,
    /// Evidence used to determine Worker membership.
    pub evidence: RelationshipEvidence,
    /// Human user names, independently observed through TeamMembers.
    pub humans: Option<BTreeSet<String>>,
}

/// A complete resource set with validated identities and any safely observed relationships.
#[derive(Debug, Clone)]
pub struct InventoryRelationships {
    /// Team name → observed relationships.
    pub teams: BTreeMap<String, TeamRelationships>,
    /// Complete Worker identities, including Workers belonging to no Team.
    pub workers: BTreeSet<String>,
}
impl InventoryRelationships {
    /// Require every Team membership to be observed before publishing or binding audit sources.
    ///
    /// # Errors
    /// Some Team lacks WorkerNames and at least one Worker lacks Groups.
    pub fn require_complete(&self) -> DomainResult<()> {
        if self.teams.values().any(|team| team.workers.is_none()) {
            return Err(DomainError::PreconditionFailed(
                "团队关系未验证：需要明确 WorkerNames，或全部 Worker 提供完整 Groups；上次完整快照保持不变".into(),
            ));
        }
        Ok(())
    }
}

/// Resource kind controls which explicitly returned list/detail fields are compared.
#[derive(Debug, Clone, Copy)]
pub enum ResourceKind {
    /// Team.WorkerNames and independent human TeamMembers.
    Team,
    /// Worker.Groups, including raw Role when both responses provide it.
    Worker,
}

/// Validate detail identity and compare every relationship field supplied by both responses.
/// Missing/null fields are unknown rather than evidence that a collection is empty.
///
/// # Errors
/// Bad types, inconsistent identities, or a list/detail collection changed during inventory.
pub fn verify_detail(listed: &Value, detail: &Value, instance: &str, kind: ResourceKind) -> DomainResult<()> {
    if fields::identity(listed, instance, true)? != fields::identity(detail, instance, false)? {
        return Err(fields::invalid("详情 Name 与列表请求不一致"));
    }
    match kind {
        ResourceKind::Team => {
            for (field, objects) in [("WorkerNames", false), ("TeamMembers", true)] {
                if fields::names(listed, field, objects)?
                    .zip(fields::names(detail, field, objects)?)
                    .is_some_and(|(a, b)| a != b)
                {
                    return Err(fields::invalid(&format!("ListTeams/GetTeam 的 {field} 不一致，请重新盘点")));
                }
            }
        }
        ResourceKind::Worker => {
            if let Some((a, b)) = fields::groups(listed)?.zip(fields::groups(detail)?) {
                if !a.keys().eq(b.keys())
                    || a.iter().any(|(key, role)| {
                        role.as_ref().zip(b.get(key).and_then(Option::as_ref)).is_some_and(|(a, b)| a != b)
                    })
                {
                    return Err(fields::invalid("ListWorkers/GetWorker 的 Groups 不一致，请重新盘点"));
                }
            }
        }
    }
    Ok(())
}

/// Check list-only references against the complete details, including fields absent in a detail.
///
/// # Errors
/// A list references an unknown resource or contradicts an observed detail relationship.
pub fn verify_list_references(
    teams: &[Value],
    workers: &[Value],
    relationships: &InventoryRelationships,
) -> DomainResult<()> {
    for team in teams {
        let name = fields::text(&team["Name"], "Name")?;
        if let Some(names) = fields::names(team, "WorkerNames", false)? {
            if names.iter().any(|worker| !relationships.workers.contains(worker))
                || relationships
                    .teams
                    .get(name)
                    .and_then(|team| team.workers.as_ref())
                    .is_some_and(|observed| !names.iter().eq(observed.keys()))
            {
                return Err(fields::invalid("ListTeams.WorkerNames 与完整详情不一致"));
            }
        }
    }
    for worker in workers {
        let name = fields::text(&worker["Name"], "Name")?;
        if let Some(groups) = fields::groups(worker)? {
            for (kind, team) in groups.keys() {
                if kind == "team" && !relationships.teams.contains_key(team) {
                    return Err(fields::invalid("ListWorkers.Groups 引用未知 Team"));
                }
            }
            for (team_name, team) in &relationships.teams {
                if team.workers.as_ref().is_some_and(|members| {
                    members.contains_key(name) != groups.contains_key(&("team".into(), team_name.clone()))
                }) {
                    return Err(fields::invalid("ListWorkers.Groups 与完整团队详情矛盾"));
                }
            }
        }
    }
    Ok(())
}

/// Parse complete GetTeam/GetWorker resources without silently dropping malformed entries.
/// Unknown relationship fields stay unknown; references must belong to the complete resource set.
///
/// # Errors
/// Invalid field types, duplicate resource identities, unknown references or explicit contradictions.
pub fn parse_inventory(instance: &str, teams: &[Value], workers: &[Value]) -> DomainResult<InventoryRelationships> {
    let mut team_names = BTreeSet::new();
    for team in teams {
        if !team_names.insert(fields::identity(team, instance, false)?.to_owned()) {
            return Err(fields::invalid("返回重复 Team Name"));
        }
    }
    let mut worker_groups: BTreeMap<String, Option<Groups>> = BTreeMap::new();
    for worker in workers {
        let name = fields::identity(worker, instance, false)?;
        if worker_groups.contains_key(name) {
            return Err(fields::invalid("返回重复 Worker Name"));
        }
        let groups = fields::groups(worker)?;
        if let Some(groups) = &groups {
            for (kind, team) in groups.keys() {
                if kind == "team" && !team_names.contains(team) {
                    return Err(fields::invalid("Worker.Groups 引用完整盘点中不存在的 Team"));
                }
            }
        }
        worker_groups.insert(name.to_owned(), groups);
    }
    let all_groups_known = worker_groups.values().all(Option::is_some);
    let mut result =
        InventoryRelationships { teams: BTreeMap::new(), workers: worker_groups.keys().cloned().collect() };
    for team in teams {
        let name = fields::identity(team, instance, false)?;
        let explicit = fields::names(team, "WorkerNames", false)?;
        let humans = fields::names(team, "TeamMembers", true)?;
        let (members, evidence) = match explicit {
            Some(names) => {
                validate_members(name, &names, &worker_groups)?;
                (Some(names), RelationshipEvidence::TeamWorkerNames)
            }
            None if all_groups_known => (
                Some(
                    worker_groups
                        .iter()
                        .filter(|(_, groups)| membership(groups, name).is_some())
                        .map(|(name, _)| name.clone())
                        .collect(),
                ),
                RelationshipEvidence::WorkerGroups,
            ),
            None => (None, RelationshipEvidence::Unverified),
        };
        let workers = members.map(|members| {
            members
                .into_iter()
                .map(|worker| {
                    let role =
                        worker_groups.get(&worker).and_then(|groups| membership(groups, name)).cloned().flatten();
                    (worker, role)
                })
                .collect()
        });
        result.teams.insert(name.to_owned(), TeamRelationships { workers, evidence, humans });
    }
    Ok(result)
}

fn membership<'a>(groups: &'a Option<Groups>, team: &str) -> Option<&'a Option<String>> {
    groups.as_ref()?.get(&("team".into(), team.into()))
}

fn validate_members(
    team: &str,
    names: &BTreeSet<String>,
    groups: &BTreeMap<String, Option<Groups>>,
) -> DomainResult<()> {
    if names.iter().any(|name| !groups.contains_key(name)) {
        return Err(fields::invalid("Team.WorkerNames 引用完整盘点中不存在的 Worker"));
    }
    for (worker, groups) in groups {
        if groups.is_some() && names.contains(worker) != membership(groups, team).is_some() {
            return Err(fields::invalid("Team.WorkerNames 与 Worker.Groups 明确矛盾，请重新盘点"));
        }
    }
    Ok(())
}

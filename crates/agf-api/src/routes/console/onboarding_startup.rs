//! Exact current inventory, never example UUIDs, implicit seeding or a vendor auto-detection promise.
use super::onboarding_types::{OnboardingSource, OnboardingStartup, OnboardingTarget, OnboardingWorker};
use crate::{agentteams_audit::binding, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use agf_storage::configuration::BoundedConfigurationList;
use serde_json::{Value, json};

pub(super) async fn choices(state: &AppState, tenant: TenantId) -> DomainResult<Vec<OnboardingSource>> {
    let rows =
        match state.configurations.list_bounded::<binding::Binding>(tenant, binding::KIND, 100, 2 * 1024 * 1024).await?
        {
            BoundedConfigurationList::Complete(rows) => rows,
            _ => return Err(DomainError::PreconditionFailed("Audit bindings exceed the plan selection budget".into())),
        };
    let mut choices = Vec::new();
    for row in rows.into_iter().filter(|row| row.enabled) {
        let (current, source, _) = match binding::verified(state, tenant, row.source_id, row.binding_id).await {
            Ok(value) => value,
            Err(DomainError::Conflict(_) | DomainError::PreconditionFailed(_) | DomainError::NotFound { .. }) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if current.members.len() > 256 {
            return Err(DomainError::PreconditionFailed("Worker inventory exceeds the plan selection budget".into()));
        }
        choices.push(OnboardingSource {
            source_id: current.source_id,
            binding_id: current.binding_id,
            scope_id: current.scope_id,
            mocked: current.mocked,
            name: source.name,
            workers: current
                .members
                .into_iter()
                .filter(|(name, _)| sdk_name(name))
                .map(|(name, member)| OnboardingWorker {
                    name,
                    teams: member.teams.into_iter().filter(|name| sdk_name(name)).collect(),
                })
                .collect(),
        });
        if serde_json::to_vec(&choices).map_err(|_| invalid())?.len() > 256 * 1024 {
            return Err(DomainError::PreconditionFailed("Worker inventory exceeds the plan response budget".into()));
        }
    }
    Ok(choices)
}

pub(super) async fn configuration(
    state: &AppState,
    tenant: TenantId,
    target: OnboardingTarget,
    input: &OnboardingStartup,
    base: &str,
) -> DomainResult<(Value, OnboardingSource)> {
    validate(target, input)?;
    let (current, source, _) = binding::verified(state, tenant, input.source_id, input.binding_id).await?;
    let member = |name: &str, team: Option<&str>| -> DomainResult<Value> {
        if !sdk_name(name) || team.is_some_and(|value| !sdk_name(value)) {
            return Err(invalid());
        }
        let row = current.members.get(name).ok_or_else(invalid)?;
        if row.teams.len() > 1 && team.is_none() {
            return Err(DomainError::Validation(
                "Worker belongs to multiple Teams; explicitly select its inventoried Team".into(),
            ));
        }
        if team.is_some_and(|team| !row.teams.contains(team)) {
            return Err(invalid());
        }
        Ok(json!({"name":name,"team":team}))
    };
    let worker = member(&input.worker, input.team.as_deref())?;
    let callee = match input.kind.as_str() {
        "task" if input.callee_worker.is_none() && input.callee_team.is_none() => None,
        "call" => Some(member(input.callee_worker.as_deref().ok_or_else(invalid)?, input.callee_team.as_deref())?),
        _ => return Err(invalid()),
    };
    let value = if target == OnboardingTarget::PythonStartup {
        let mut descriptor = json!({"module":input.module,"attribute":input.callable,"kind":input.kind,
            "worker":worker,"operation":input.operation});
        if let Some(callee) = callee {
            descriptor["callee"] = callee;
        }
        json!({"version":1,"collector":{"platform_url":base,"source_id":current.source_id,
            "binding_id":current.binding_id,"expected_scope":current.scope_id,"expected_mocked":current.mocked,
            "spool_dir":input.spool_directory},"targets":[descriptor],"shutdown_timeout":6.0})
    } else {
        let mut descriptor = json!({"file":input.target_file,"export":input.callable.split('.').collect::<Vec<_>>(),
            "kind":input.kind,"worker":worker,"operation":input.operation,"mode":input.async_mode,"capture":"omit"});
        if let Some(callee) = callee {
            descriptor["to"] = callee;
        }
        json!({"version":1,"keyEnv":"AGF_STARTUP_KEY","targets":[descriptor]})
    };
    let selected = OnboardingSource {
        source_id: current.source_id,
        binding_id: current.binding_id,
        scope_id: current.scope_id,
        mocked: current.mocked,
        name: source.name,
        workers: current
            .members
            .into_iter()
            .filter(|(name, _)| sdk_name(name))
            .map(|(name, member)| OnboardingWorker {
                name,
                teams: member.teams.into_iter().filter(|name| sdk_name(name)).collect(),
            })
            .collect(),
    };
    Ok((value, selected))
}

fn sdk_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}
fn invalid() -> DomainError {
    DomainError::Validation("Select a current Worker/team and a supported noncredential startup descriptor".into())
}
fn qualified(value: &str, node: bool) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split('.').count() <= if node { 4 } else { 16 }
        && value.split('.').all(|part| {
            !part.is_empty()
                && (!node || part.len() <= 128)
                && !part.starts_with("__")
                && !["constructor", "prototype"].contains(&part)
                && part.chars().enumerate().all(|(i, c)| {
                    c.is_ascii_alphabetic() || c == '_' || (node && c == '$') || (i > 0 && c.is_ascii_digit())
                })
        })
}
fn absolute(value: &str) -> bool {
    value.len() <= 2048
        && !value.chars().any(char::is_control)
        && !value.contains("://")
        && (value.starts_with('/')
            || (value.as_bytes().get(1) == Some(&b':')
                && value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && value.as_bytes().get(2).is_some_and(|c| *c == b'\\' || *c == b'/')))
        && !value.split(['/', '\\']).any(|part| part == "..")
}
fn validate(target: OnboardingTarget, input: &OnboardingStartup) -> DomainResult<()> {
    super::onboarding_targets::plain(&input.operation, 64)?;
    if !input.operation.chars().all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c)) {
        return Err(invalid());
    }
    if !absolute(&input.sdk_directory) || !absolute(&input.spool_directory) || !absolute(&input.configuration_file) {
        return Err(invalid());
    }
    if target == OnboardingTarget::PythonStartup {
        if !qualified(&input.module, false)
            || !qualified(&input.callable, false)
            || !qualified(&input.entry, false)
            || input.module == input.entry
            || input.module == format!("{}.__main__", input.entry)
            || input.module.starts_with("agf_agentteams")
            || input.target_file.is_some()
            || input.async_mode.is_some()
        {
            return Err(invalid());
        }
    } else if !input.module.is_empty()
        || !qualified(&input.callable, true)
        || !absolute(&input.entry)
        || !input
            .target_file
            .as_deref()
            .is_some_and(|value| absolute(value) && (value.ends_with(".cjs") || value.ends_with(".js")))
        || !(input.entry.ends_with(".cjs") || input.entry.ends_with(".js"))
        || !matches!(input.async_mode.as_deref(), Some("sync" | "promise" | "iterator" | "asyncIterator"))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualified_targets_reject_executable_paths_and_unsafe_exports() {
        for input in ["", "foo..bar", "foo;exit", "__proto__.x", "x.constructor", "1name"] {
            assert!(!qualified(input, true));
        }
        assert!(qualified("worker.run", false));
        assert!(qualified("$export.task", true));
    }
    #[test]
    fn local_paths_reject_relative_escape_uris_and_controls() {
        for input in ["work/config.json", "/work/../key", "https://example.test/a", "C:\\x\nkey"] {
            assert!(!absolute(input));
        }
        assert!(absolute("E:\\owned\\config.json"));
        assert!(absolute("/owned/config.json"));
    }
}

use super::{
    authority::Authority,
    records::Fact,
    source::{self, Loaded},
    store, transport,
    types::{Status, StepEvidence, hash},
};
use crate::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    redact::{RedactionMap, RedactionMode, redact_text},
};
use agf_scan::redteam::ToolCallOutcome;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Playbook {
    version: String,
    reference: String,
    query: String,
    summary: String,
    steps: Vec<String>,
}
fn playbook() -> DomainResult<Playbook> {
    let value: Playbook = serde_yaml::from_str(include_str!("playbook.yaml"))
        .map_err(|_| DomainError::Config("Embedded multi-target playbook is invalid".into()))?;
    if value.version != super::VERSION
        || value.steps != ["agent-public-reference", "mcp-readonly-context", "agent-untrusted-context-summary"]
        || !value.query.contains("{{reference}}")
        || !value.summary.contains("{{context}}")
        || [&value.reference, &value.query, &value.summary].iter().any(|text| text.len() > 2048)
    {
        return Err(DomainError::Config("Embedded bounded playbook does not match its executor".into()));
    }
    Ok(value)
}
pub(super) fn playbook_view() -> DomainResult<Value> {
    let value = playbook()?;
    Ok(json!({"version":value.version,"steps":value.steps,"maximumTargets":3,"maximumSteps":3,
        "declarativeYamlSha256":hash(&include_str!("playbook.yaml"))?,"arbitraryYamlAccepted":false,
        "protectedCanaryOnly":true,"externalDefenseVerified":false}))
}
pub(super) async fn ensure(state: &AppState, authority: &Authority, original: &Fact) -> DomainResult<()> {
    authority.check(state).await?;
    let current = store::get(state, original.tenant, original.request_id).await?.ok_or_else(super::records::corrupt)?;
    current.owns(&authority.principal)?;
    if current.status != Status::Running
        || current.known_terminal.is_some()
        || current.input_sha256 != original.input_sha256
    {
        return Err(DomainError::Conflict("Original run is cancelled, published or no longer dispatchable".into()));
    }
    let targets = source::capture(state, original.tenant, &original.input.targets).await?;
    if hash(&targets.iter().map(|loaded| &loaded.target).collect::<Vec<_>>())? != hash(&original.targets)? {
        return Err(DomainError::Conflict("Original registered targets changed".into()));
    }
    authority.check(state).await
}
pub(super) async fn run(
    state: &AppState,
    authority: &Authority,
    mut fact: Fact,
    targets: Vec<Loaded>,
) -> DomainResult<Fact> {
    let playbook = playbook()?;
    let mut relay = String::new();
    for step in 0..3_u8 {
        let target = &targets[usize::from(step)];
        let prompt = match step {
            0 => playbook.reference.clone(),
            1 => playbook.query.replace("{{reference}}", &relay),
            _ => playbook.summary.replace("{{context}}", &relay),
        };
        let result =
            tokio::time::timeout_at(authority.deadline, step_read(state, authority, &fact, target, step, &prompt))
                .await;
        let (mut evidence, text) = match result {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => (failure(step, target, reason(&error)), None),
            Err(_) => (failure(step, target, "original_deadline"), None),
        };
        let next_relay = if let Some(text) = text {
            match sanitize(&text, &targets) {
                Ok(relay) => {
                    evidence.relay_sha256 = Some(hash(&relay)?);
                    Some(relay)
                }
                Err(_) => {
                    evidence.completed = false;
                    evidence.reason = Some("unsafe_or_empty_relay".into());
                    None
                }
            }
        } else {
            None
        };
        let terminal = if !evidence.completed {
            Some(Status::Failed)
        } else if step == 2 {
            Some(Status::Completed)
        } else {
            None
        };
        // Own the already-known digest while staging; a caller disconnect must not lose a known result.
        let owned_state = state.clone();
        let original = fact.clone();
        let task = tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(110),
                store::stage(&owned_state, &original, evidence, terminal),
            )
            .await
            .map_err(|_| DomainError::Timeout("Known evidence local staging budget".into()))?
        });
        fact = tokio::time::timeout_at(authority.deadline, task)
            .await
            .map_err(|_| {
                DomainError::Timeout("Original outbound execution deadline; known local staging owns its result".into())
            })?
            .map_err(|_| DomainError::Internal("Safe evidence staging task did not complete".into()))??;
        if fact.status != Status::Running {
            return Ok(fact);
        }
        if terminal.is_some() {
            break;
        }
        relay = next_relay.ok_or_else(super::records::corrupt)?;
    }
    match tokio::time::timeout_at(authority.deadline, store::finish(state, authority, &fact, false, false)).await {
        Ok(Ok(published)) => Ok(published),
        _ => Ok(fact), // Safe staged evidence remains pending; neither retry nor a fake success audit.
    }
}
async fn step_read(
    state: &AppState,
    authority: &Authority,
    fact: &Fact,
    target: &Loaded,
    step: u8,
    prompt: &str,
) -> DomainResult<(StepEvidence, Option<String>)> {
    ensure(state, authority, fact).await?;
    let (client, url, transport_proof) =
        transport::client(state, fact.tenant, target.target.profile_id, &target.url, target.private_network.as_ref())
            .await?;
    ensure(state, authority, fact).await?;
    let session = if step == 1 {
        let session = match target.mcp_revision {
            super::mcp::Revision::Modern => super::mcp::Session::modern(),
            super::mcp::Revision::Legacy => {
                ensure(state, authority, fact).await?;
                let session = super::mcp::Session::initialize(&client, &url, target.secret.as_deref()).await?;
                ensure(state, authority, fact).await?;
                session.initialized(&client, &url, target.secret.as_deref()).await?;
                session
            }
        };
        Some(session)
    } else {
        None
    };
    let mut tool_header = None;
    let body = if let Some(session) = &session {
        tool_header = verify_tool(state, authority, fact, target, &client, &url, session).await?;
        let argument = target.argument.as_deref().ok_or_else(super::records::corrupt)?;
        session.body("tools/call", json!({"name":target.model_or_tool,"arguments":{(argument):prompt}}))?
    } else {
        json!({"model":target.model_or_tool,"messages":[{"role":"user","content":prompt}],"stream":false,"max_tokens":256})
    };
    let call_headers = if session.is_some() {
        super::mcp_headers::parameters(tool_header.as_ref(), prompt)?
    } else {
        reqwest::header::HeaderMap::new()
    };
    let mut receipt = if step == 1 {
        Some(
            super::super::mcp_tool_meter::reserve(
                state,
                fact.tenant,
                fact.request_id,
                target.target.profile_id,
                target.model_or_tool.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    if let Err(error) = ensure(state, authority, fact).await {
        if let Some(receipt) = receipt {
            receipt.finish(ToolCallOutcome::NotDelivered).await?;
        }
        return Err(error);
    }
    if let Some(receipt) = &mut receipt {
        receipt.mark_sending();
    }
    let response = if let Some(session) = &session {
        session.request(&client, &url, target.secret.as_deref(), &body, call_headers).await
    } else {
        transport::exchange(&client, &url, target.secret.as_deref(), &body, None).await
    };
    if let Some(receipt) = receipt {
        receipt
            .finish(match &response {
                Ok(wire) if mcp_text(&wire.content).is_some() => ToolCallOutcome::Succeeded,
                Ok(_) => ToolCallOutcome::Failed,
                Err(_) => ToolCallOutcome::Unknown,
            })
            .await?;
    }
    let wire = match response {
        Ok(wire) => wire,
        Err(_) => {
            return Ok((
                StepEvidence {
                    request_sha256: Some(hash(&body)?),
                    transport_proof_sha256: Some(transport_proof),
                    ..failure(step, target, "response_unknown")
                },
                None,
            ));
        }
    };
    let text = if step == 1 {
        mcp_text(&wire.content).map(ToOwned::to_owned)
    } else if wire.content.pointer("/choices/0/finish_reason").and_then(Value::as_str) != Some("stop") {
        None
    } else {
        wire.content.pointer("/choices/0/message/content").and_then(Value::as_str).map(ToOwned::to_owned)
    };
    let observed = text.as_ref().map(|text| text.contains(&target.canary));
    let completed = text.is_some();
    let evidence = StepEvidence {
        step,
        profile_id: target.target.profile_id,
        request_sha256: Some(hash(&body)?),
        response_sha256: Some(wire.response_sha256),
        response_bytes: Some(wire.response_bytes),
        transport_proof_sha256: Some(transport_proof),
        relay_sha256: None,
        completed,
        protected_canary_observed: observed,
        dispatch: "known_response".into(),
        reason: if completed { None } else { Some("incomplete_response_contract".into()) },
    };
    Ok((evidence, text))
}
async fn verify_tool(
    state: &AppState,
    authority: &Authority,
    fact: &Fact,
    target: &Loaded,
    client: &reqwest::Client,
    url: &reqwest::Url,
    session: &super::mcp::Session,
) -> DomainResult<Option<reqwest::header::HeaderName>> {
    let mut cursor: Option<String> = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut selected = 0;
    let mut selected_header = None;
    for _ in 0..4 {
        ensure(state, authority, fact).await?;
        let mut params = json!({});
        if let Some(cursor) = &cursor {
            params["cursor"] = json!(cursor);
        }
        let body = session.body("tools/list", params)?;
        let wire =
            session.request(client, url, target.secret.as_deref(), &body, reqwest::header::HeaderMap::new()).await?;
        if wire.content["jsonrpc"] != "2.0" || wire.content["id"] != 1 || wire.content.get("error").is_some() {
            return Err(tool_error());
        }
        let result = &wire.content["result"];
        let tools = result["tools"].as_array().filter(|items| items.len() <= 128).ok_or_else(tool_error)?;
        for tool in tools.iter().filter(|tool| tool["name"].as_str() == Some(target.model_or_tool.as_str())) {
            selected += 1;
            let schema = &tool["inputSchema"];
            let argument = target.argument.as_deref().ok_or_else(tool_error)?;
            if tool["annotations"]["readOnlyHint"] != true
                || tool["annotations"]["destructiveHint"] == true
                || schema["type"] != "object"
                || schema["properties"].as_object().is_none_or(|props| props.len() != 1)
                || schema["properties"][argument]["type"] != "string"
                || schema["required"] != json!([argument])
            {
                return Err(tool_error());
            }
            selected_header = super::mcp_headers::tool(schema, argument)?;
        }
        cursor = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) if value.len() <= 256 && !value.chars().any(char::is_control) => {
                Some(value.clone())
            }
            _ => return Err(tool_error()),
        };
        let Some(next) = &cursor else {
            return if selected == 1 { Ok(selected_header) } else { Err(tool_error()) };
        };
        if !seen.insert(next.clone()) {
            return Err(tool_error());
        }
    }
    Err(tool_error())
}
pub(super) fn sanitize(text: &str, targets: &[Loaded]) -> DomainResult<String> {
    let mut clean = text.to_owned();
    for target in targets {
        clean = clean.replace(&target.canary, "[protected-value-redacted]");
        if let Some(secret) = &target.secret {
            if !secret.is_empty() {
                clean = clean.replace(secret, "[credential-redacted]");
            }
        }
    }
    clean = redact_text(&clean, RedactionMode::CredentialsOnly, &mut RedactionMap::default()).text;
    let mut bounded = String::new();
    for c in clean.chars().filter(|c| !c.is_control()) {
        if bounded.len() + c.len_utf8() > 256 {
            break;
        }
        bounded.push(c);
    }
    if bounded.trim().is_empty() {
        return Err(DomainError::Validation("Relay was empty or unsafe".into()));
    }
    Ok(bounded)
}
fn failure(step: u8, target: &Loaded, reason: &str) -> StepEvidence {
    StepEvidence {
        step,
        profile_id: target.target.profile_id,
        request_sha256: None,
        response_sha256: None,
        response_bytes: None,
        transport_proof_sha256: None,
        relay_sha256: None,
        completed: false,
        protected_canary_observed: None,
        dispatch: "not_confirmed".into(),
        reason: Some(reason.into()),
    }
}
fn reason(error: &DomainError) -> &'static str {
    match error {
        DomainError::Forbidden(_) | DomainError::Unauthenticated(_) => "authority_changed",
        DomainError::Conflict(_) => "target_changed_or_cancelled",
        DomainError::Timeout(_) => "original_deadline",
        DomainError::PreconditionFailed(_) => "mcp_contract_unsupported",
        DomainError::QuotaExceeded { .. } | DomainError::RateLimited(_) => "quota",
        _ => "read_or_contract_unavailable",
    }
}
fn tool_error() -> DomainError {
    DomainError::PreconditionFailed(
        "MCP complete tool inventory must prove exactly one configured read-only string query".into(),
    )
}
pub(super) fn mcp_text(value: &Value) -> Option<&str> {
    if value["jsonrpc"] != "2.0"
        || value["id"] != 1
        || value.get("error").is_some()
        || value.get("method").is_some()
        || value["result"].get("isError").is_some_and(|flag| flag != false)
    {
        return None;
    }
    let items = value["result"]["content"].as_array()?;
    if items.len() != 1 || items[0]["type"] != "text" {
        return None;
    }
    items[0]["text"].as_str()
}

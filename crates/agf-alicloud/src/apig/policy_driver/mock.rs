use super::{
    Binding,
    contract::Action,
    json,
    observe::{self, evidence},
};
use crate::http::RpcResponse;
use agf_core::error::DomainResult;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, fmt};

/// Pure state for a future durable API ConfigStore bridge, isolated by its authenticated scope key.
///
/// This type is not itself durable; the API must atomically persist each successful mutation.
/// A provider-style Mock revision is internal bookkeeping and cannot be used as live CAS evidence.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockState {
    scope: String,
    binding: Binding,
    responses: BTreeMap<String, Value>,
    calls: BTreeMap<String, u64>,
    revision: u64,
}

impl fmt::Debug for MockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockState")
            .field("scope", &self.scope)
            .field("binding", &self.binding)
            .field("revision", &self.revision)
            .field("calls", &self.calls)
            .field("configuration", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl MockState {
    /// Seed only the explicit owned demo target; unrelated resource identities are never invented.
    /// The future API must call this only for explicit observation initialization, never pure receipt GET.
    ///
    /// # Errors
    /// The authenticated scope, selected target or owned fixture is invalid.
    pub fn seed(scope: &str, binding: &Binding) -> DomainResult<Self> {
        if scope.len() != 64 || !scope.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(evidence("Mock requires an authenticated SHA256 scope key"));
        }
        let fixture: Value =
            serde_json::from_str(include_str!("../../../../../tests/fixtures/alicloud/apig-policy-driver.json"))?;
        let expected: Binding = serde_json::from_value(fixture["binding"].clone())?;
        if &expected != binding {
            return Err(evidence("This Mock fixture does not own the selected target"));
        }
        let responses = serde_json::from_value(fixture["responses"].clone())?;
        let state =
            Self { scope: scope.into(), binding: binding.clone(), responses, calls: BTreeMap::new(), revision: 0 };
        state.validate()?;
        Ok(state)
    }

    /// Execute one read or write against the selected state, with candidate preparation before publication.
    /// The API bridge must verify tenant/source/config/mode and `scope`, then persist this with ConfigStore.mutate.
    /// There is no ClientToken on UpdatePolicy; permanent workflow facts prevent repeated invocation.
    ///
    /// # Errors
    /// The scope, input, stored evidence, counters or bounded candidate is invalid.
    pub fn respond(&mut self, scope: &str, action: &str, input: &Value) -> DomainResult<RpcResponse> {
        if self.scope != scope {
            return Err(evidence("Mock scope differs from the authenticated source"));
        }
        self.validate()?;
        let action = match action {
            "GetHttpApi" => Action::HttpApi,
            "GetPolicy" => Action::Policy,
            "GetPolicyAttachment" => Action::Attachment,
            "UpdatePolicy" => Action::Update,
            _ => return Err(evidence("Mock does not own this action")),
        };
        action.definition()?.validate(input)?;
        self.matches_input(action, input)?;
        let mut candidate = self.clone();
        let count = candidate.calls.entry(action.name().into()).or_default();
        *count = count.checked_add(1).ok_or_else(|| evidence("Mock call counter is exhausted"))?;
        let request_id = format!("mock-{}-{}", action.name(), *count);
        if action == Action::Update {
            candidate.update(input)?;
        }
        let mut response = candidate.response(action)?;
        response.body["requestId"] = value!(request_id);
        if serde_json::to_vec(&candidate)?.len() > 512 * 1024 {
            return Err(evidence("Mock state exceeds 512 KiB"));
        }
        *self = candidate;
        Ok(response)
    }

    /// Count actual invocations; the future bridge persists this with the state, across API instances.
    pub fn call_count(&self, action: &str) -> u64 {
        self.calls.get(action).copied().unwrap_or(0)
    }

    pub(super) fn check_scope(&self, scope: &str, binding: &Binding) -> DomainResult<()> {
        if self.scope != scope || &self.binding != binding {
            return Err(evidence("Stored APIG Mock belongs to another source/target"));
        }
        self.validate()
    }

    fn validate(&self) -> DomainResult<()> {
        super::mock_scope::check_hash(&self.scope)?;
        if self.calls.keys().any(|action| {
            !matches!(action.as_str(), "GetHttpApi" | "GetPolicy" | "GetPolicyAttachment" | "UpdatePolicy")
        }) || self.revision != self.call_count("UpdatePolicy")
        {
            return Err(evidence("Stored APIG Mock call facts are invalid"));
        }
        observe::parse_current(
            &self.binding,
            &self.response(Action::HttpApi)?,
            &self.response(Action::Policy)?,
            &self.response(Action::Attachment)?,
        )?;
        Ok(())
    }

    fn response(&self, action: Action) -> DomainResult<RpcResponse> {
        self.responses
            .get(action.name())
            .cloned()
            .map(|body| RpcResponse { status: 200, body, raw: String::new() })
            .ok_or_else(|| evidence("Mock is missing an owned action response"))
    }

    fn matches_input(&self, action: Action, input: &Value) -> DomainResult<()> {
        let (field, expected) = match action {
            Action::HttpApi => ("httpApiId", &self.binding.http_api_id),
            Action::Policy | Action::Update => ("policyId", &self.binding.policy_id),
            Action::Attachment => ("policyAttachmentId", &self.binding.attachment_id),
        };
        if input[field].as_str() != Some(expected.as_str()) {
            return Err(evidence("Mock requested a foreign resource"));
        }
        if action == Action::HttpApi && input["expandPolicyConfigs"] != Value::Bool(false) {
            return Err(evidence("This restricted Mock reads the independent-policy reference view"));
        }
        Ok(())
    }

    fn update(&mut self, input: &Value) -> DomainResult<()> {
        super::profile::writable_attachment(&self.response(Action::Attachment)?.body["data"])?;
        let body = &input["body"];
        observe::text(body, "name", 512)?;
        observe::optional_text(body, "description", 8192)?;
        let config = json::parse(observe::configuration(body)?)?;
        self.revision = self.revision.checked_add(1).ok_or_else(|| evidence("Mock revision is exhausted"))?;
        let policy =
            &mut self.responses.get_mut(Action::Policy.name()).ok_or_else(|| evidence("Missing Mock policy"))?["data"];
        policy["name"] = body["name"].clone();
        policy["config"] = value!(json::canonical(&config).to_string());
        if let Some(description) = body.get("description") {
            policy["description"] = description.clone();
        }
        // UpdatePolicy has no proven effect on attachment.config; preserve its exact original value.
        self.validate()?;
        Ok(())
    }
}

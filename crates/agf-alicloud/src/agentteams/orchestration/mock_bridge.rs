use super::*;
use std::{collections::BTreeMap, sync::Mutex};

/// Safe preview of explicit declaration differences; never performs synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preview {
    /// State revision reviewed by the caller.
    pub version: u64,
    /// Node IDs that would be added.
    pub added: Vec<String>,
    /// Node IDs that would be removed.
    pub removed: Vec<String>,
    /// Node IDs whose actual declared fields differ.
    pub changed: Vec<String>,
}
/// Process-local Mock state, not proof of application or cloud activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockDefinitionView {
    /// Current local/Mock receiver revision.
    pub version: u64,
    /// Local application-owned declaration, if explicitly adopted.
    pub local: Option<DefinitionDocument>,
    /// Synthetic receiver declaration; never a vendor-returned DAG.
    pub receiver: DefinitionDocument,
    /// Always true for this independent test bridge.
    pub mocked: bool,
    /// Always false: this library bridge does not persist across process restart.
    pub durable: bool,
    /// Always unknown; a successful declaration does not mean an application ran it.
    pub consumer_applied: Option<bool>,
}
/// Immutable receipt. Reading or replaying it never reapplies a declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockDefinitionReceipt {
    /// Original request identity.
    pub request_id: Id,
    /// Exact immutable request body hash.
    pub body_hash: String,
    /// Explicit direction that was confirmed.
    pub direction: DefinitionDirection,
    /// Original differences before applying.
    pub preview: Preview,
    /// Result at the time of original application, not a current-state projection.
    pub result: MockDefinitionView,
    /// Always false; no network path exists in this bridge.
    pub provider_called: bool,
}
struct State {
    view: MockDefinitionView,
    receipts: BTreeMap<Id, MockDefinitionReceipt>,
}
/// Bounded Mock receiver used to prove declaration synchronization independently from vendor APIs.
pub struct MockDefinitionBridge {
    team: AgentTeam,
    state: Mutex<State>,
}
impl std::fmt::Debug for MockDefinitionBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockDefinitionBridge").field("mocked", &true).field("durable", &false).finish_non_exhaustive()
    }
}
fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "mock-definition-state".into(), cause: "状态锁不可用".into()
    }
}
impl MockDefinitionBridge {
    /// Create an isolated Mock receiver from an explicitly supplied Team fixture.
    ///
    /// # Errors
    /// Rejects inconsistent or unbounded fixture declarations.
    pub fn new(team: AgentTeam) -> DomainResult<Self> {
        let receiver = DefinitionDocument::from_application(&team, team.orchestration.clone());
        validate_definition(&receiver, &team)?;
        Ok(Self {
            team,
            state: Mutex::new(State {
                view: MockDefinitionView {
                    version: 0,
                    local: None,
                    receiver,
                    mocked: true,
                    durable: false,
                    consumer_applied: None,
                },
                receipts: BTreeMap::new(),
            }),
        })
    }
    /// Read state without modifying revisions or receipt facts.
    ///
    /// # Errors
    /// A poisoned state lock is unavailable.
    pub fn read(&self) -> DomainResult<MockDefinitionView> {
        Ok(self.state.lock().map_err(|_| unavailable())?.view.clone())
    }
    fn desired(&self, input: &DefinitionIntent, state: &State) -> DomainResult<DefinitionDocument> {
        if input.request_id.is_nil() || input.expected_version != state.view.version {
            return Err(DomainError::Conflict("编号无效或声明版本已改变；保留草稿，重新读取并明确采用".into()));
        }
        let document = match (&input.direction, &input.definition) {
            (DefinitionDirection::Pull, None) => state.view.receiver.clone(),
            (DefinitionDirection::Push | DefinitionDirection::Both, Some(document)) => document.clone(),
            _ => return Err(invalid()),
        };
        validate_definition(&document, &self.team)?;
        Ok(document)
    }
    fn difference(view: &MockDefinitionView, desired: &DefinitionDocument, direction: DefinitionDirection) -> Preview {
        let before = if direction == DefinitionDirection::Pull {
            view.local.as_ref().map(|document| &document.nodes).unwrap_or(&view.receiver.nodes)
        } else {
            &view.receiver.nodes
        };
        let old = before
            .iter()
            .map(|node| (&node.node_id, super::super::definition_signature::node(node)))
            .collect::<BTreeMap<_, _>>();
        let new = desired
            .nodes
            .iter()
            .map(|node| (&node.node_id, super::super::definition_signature::node(node)))
            .collect::<BTreeMap<_, _>>();
        Preview {
            version: view.version,
            added: new.keys().filter(|id| !old.contains_key(*id)).map(|id| (*id).clone()).collect(),
            removed: old.keys().filter(|id| !new.contains_key(*id)).map(|id| (*id).clone()).collect(),
            changed: new
                .iter()
                .filter(|(id, value)| old.get(*id).is_some_and(|old| old != *value))
                .map(|(id, _)| (*id).clone())
                .collect(),
        }
    }
    /// Preview exact field differences without publishing or allocating a receipt.
    ///
    /// # Errors
    /// Invalid references, stale revisions or inconsistent intent fields.
    pub fn preview(&self, input: &DefinitionIntent) -> DomainResult<Preview> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        let desired = self.desired(input, &state)?;
        Ok(Self::difference(&state.view, &desired, input.direction))
    }
    /// Apply exactly one confirmed Mock intent; identical UUID/body replays return the original fact.
    ///
    /// # Errors
    /// Missing confirmation, stale revision, reused UUID/body mismatch, invalid DAG or full ledger.
    pub fn apply(&self, input: &DefinitionIntent) -> DomainResult<MockDefinitionReceipt> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let body_hash = hash(input)?;
        if let Some(receipt) = state.receipts.get(&input.request_id) {
            return if receipt.body_hash == body_hash {
                Ok(receipt.clone())
            } else {
                Err(DomainError::Conflict("原编号已绑定另一不可变声明；不会重新派发".into()))
            };
        }
        if !input.confirm_mock {
            return Err(DomainError::Validation("需要明确确认 Mock 声明同步，不是云端或业务执行".into()));
        }
        if state.receipts.len() >= MAX_MOCK_INTENTS {
            return Err(DomainError::Validation("Mock 请求事实容量已满；不会删除旧编号以重派".into()));
        }
        let desired = self.desired(input, &state)?;
        let preview = Self::difference(&state.view, &desired, input.direction);
        let version = state.view.version.checked_add(1).ok_or_else(invalid)?;
        let mut result = state.view.clone();
        result.version = version;
        result.local = Some(desired.clone());
        if input.direction != DefinitionDirection::Pull {
            result.receiver = desired;
        }
        let receipt = MockDefinitionReceipt {
            request_id: input.request_id,
            body_hash,
            direction: input.direction,
            preview,
            result: result.clone(),
            provider_called: false,
        };
        state.view = result;
        state.receipts.insert(input.request_id, receipt.clone());
        Ok(receipt)
    }
    /// Read the original immutable receipt without any reapplication.
    ///
    /// # Errors
    /// Unknown request or a poisoned state lock.
    pub fn receipt(&self, request_id: Id) -> DomainResult<MockDefinitionReceipt> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .receipts
            .get(&request_id)
            .cloned()
            .ok_or_else(|| DomainError::NotFound { entity: "Mock definition intent", id: request_id.to_string() })
    }
}

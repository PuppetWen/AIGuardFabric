//! 黑名单编辑与持久化；自定义规则和启停覆盖严格限制在当前租户。
use crate::{model_routes::tenant_record_id, state::AppState};
use agf_core::{
    enums::{RiskDomain, Severity},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_runtime::blocklist::{Blocklist, RuleAction, RuleKind, RuleRule};
use serde::{Deserialize, Serialize};
mod authority;
mod publication;
pub(crate) use authority::Submission;
pub const KIND: &str = "runtime-blacklists";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub rule: RuleRule,
    pub enabled: bool,
    pub updated_at: Timestamp,
    #[serde(default)]
    pub version: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rules {
    pub rules: Vec<Entry>,
}
impl Default for Rules {
    fn default() -> Self {
        Self {
            rules: agf_runtime::blocklist::default_rules()
                .into_iter()
                .map(|rule| Entry { rule, enabled: true, updated_at: Timestamp::now(), version: 0 })
                .collect(),
        }
    }
}
pub async fn load(state: &AppState, tenant: TenantId) -> DomainResult<Rules> {
    Ok(state.configurations.get(tenant, KIND, tenant_record_id(tenant)).await?.unwrap_or_default())
}
#[derive(Debug, Deserialize)]
pub struct NewRule {
    pub kind: RuleKind,
    pub pattern: String,
    pub action: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub scope: Option<String>,
}
pub(crate) async fn add(state: &AppState, submission: &Submission, body: NewRule) -> DomainResult<Entry> {
    if body.pattern.trim().is_empty()
        || body.pattern.len() > 4096
        || body.note.len() > 1024
        || body.scope.as_deref().is_some_and(|s| s != "tenant")
    {
        return Err(DomainError::Validation(
            "黑名单模式不能为空、长度须合理；作用域为当前租户，Agent/会话条件请使用策略中心".into(),
        ));
    }
    let action = match body.action.as_str() {
        "deny" => RuleAction::Deny,
        "allow" => RuleAction::Allow,
        "alert" | "audit" => RuleAction::Audit,
        _ => return Err(DomainError::Validation("无效黑名单动作".into())),
    };
    let rule = RuleRule {
        id: Id::new().to_string(),
        kind: body.kind,
        pattern: body.pattern,
        action,
        reason: body.note,
        domain: RiskDomain::ToolAbuse,
        severity: Severity::High,
    };
    Blocklist::from_rules(vec![rule.clone()])
        .map_err(|error| DomainError::Validation(format!("黑名单规则无效：{error}")))?;
    publication::execute(
        state,
        submission,
        publication::Change::Add(Entry { rule, enabled: true, updated_at: Timestamp::now(), version: 1 }),
    )
    .await
}
pub(crate) async fn update(
    state: &AppState,
    submission: &Submission,
    id: String,
    enabled: Option<bool>,
    expected_version: u64,
) -> DomainResult<Entry> {
    publication::execute(state, submission, publication::Change::Update { id, enabled, expected_version }).await
}

fn expired() -> DomainError {
    DomainError::Conflict("黑名单提交已超过原时限，请重新加载后确认".into())
}

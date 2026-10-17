use super::ownership::Scratch;
use agf_core::{
    config::AppConfig,
    enums::Severity,
    ids::TenantId,
    redteam::{AttackCategory, AttackTurn, ExecutionMode, RedteamCase},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) const RULE: &str = include_str!("../../../../rules/tool-abuse/ta-path-003.yaml");
pub(super) const PASSWORD: &str = "P8#CallbackLocal!Sql9";
pub(super) const APP: &str = "9007199254740993";
pub(super) const JOBS: [(&str, &str); 6] = [
    ("asset-inventory", "9007199254741001"),
    ("log-pull", "9007199254741002"),
    ("redteam-cruise", "9007199254741003"),
    ("rule-hot-reload", "9007199254741004"),
    ("report", "9007199254741005"),
    ("archive", "9007199254741006"),
];
pub(super) fn config(scratch: &Scratch) -> anyhow::Result<AppConfig> {
    anyhow::ensure!(
        std::env::var("AGF_SEED_FIXTURES").ok().as_deref() != Some("1"),
        "fixture requires seeding disabled"
    );
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "0"),
        ("AGF_JWT_SECRET", "callback-business-fixture-secret-at-least-32bytes"),
        ("AGF_JWT_ISSUER", "aiguardfabric"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_FORCE_PASSWORD_CHANGE", "0"),
        ("AGF_NATS_ENABLED", "0"),
        ("AGF_SEED_FIXTURES", "0"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    env.insert("AGF_PROJECT_ROOT".into(), scratch.root.to_string_lossy().into_owned());
    env.insert("AGF_DATA_DIR".into(), scratch.path("data").to_string_lossy().into_owned());
    Ok(agf_core::config::from_env_map(&env)?)
}
pub(super) fn case() -> RedteamCase {
    RedteamCase {
        key: "CB-OWNED-ONE".into(),
        title: "Owned local simulator case".into(),
        category: AttackCategory::DirectInjection,
        severity: Severity::High,
        mode: ExecutionMode::SingleTurn,
        turns: vec![AttackTurn { role: "user".into(), content: "Local marker".into(), expect: vec![] }],
        applies_to: vec![],
        success_signals: vec!["marker_echo".into()],
        required_tools: vec![],
        tags: vec![],
        references: vec![],
        public_poc: false,
        remediation: "Review local evidence".into(),
        author: "owned-test".into(),
        version: 1,
    }
}
pub(super) fn files(scratch: &Scratch) -> anyhow::Result<()> {
    std::fs::write(scratch.path("rules").join("owned.yaml"), RULE)?;
    // JSON is valid YAML; CaseLibrary deliberately only discovers .yaml/.yml files.
    std::fs::write(scratch.path("cases").join("owned.yaml"), serde_json::to_vec_pretty(&case())?)?;
    Ok(())
}
pub(super) fn policy() -> Value {
    json!({"name":"owned-callback-policy","language":"cel","source":"{\"action\":\"deny\",\"reason\":\"owned callback rule\"}",
        "action":"deny","priority":1,"enabled":true,"intercept_points":["ai-gateway","mcp-proxy"],"expected_version":0})
}
pub(super) fn parser() -> Value {
    json!({"definition":{"key":"owned-callback-parser","name":"Owned callback event","engine":"json-path","pattern":"$",
        "required_fields":["callback_signal"],"mapping":{"action_field":"callback_signal"}},
        "sample":"{\"callback_signal\":\"pulled\"}","enabled":true,"priority":1})
}
pub(super) fn settings(endpoint: &str, tenant: TenantId) -> Value {
    json!({"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo","account_id":format!("owned-{tenant}"),"endpoint":endpoint})
}

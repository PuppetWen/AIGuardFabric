//! A metadata-only adapter sync cannot claim actual platform permission grants.
#![allow(clippy::unwrap_used)]
use agf_alicloud::agentteams::AgentTeamsAdapter;
use agf_core::adapter::{Adapter, PullRequest, SyncDirection};

#[tokio::test]
async fn mock_role_name_hints_are_reported_separately_from_committed_role_mappings() {
    let adapter = AgentTeamsAdapter::mocked();
    let report = adapter.sync(SyncDirection::Both, &PullRequest::default()).await.unwrap();
    assert!(report.changes["role_mapping_hints"] > 0);
    assert_eq!(report.changes["role_mapped"], 0);
    assert!(report.warnings.iter().any(|warning| warning.contains("未保存或授予平台权限")));
    assert_eq!(adapter.transport().call_count().unwrap(), 0);
}

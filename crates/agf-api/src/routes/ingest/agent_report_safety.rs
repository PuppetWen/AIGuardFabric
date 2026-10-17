//! 终端报告在进入原始日志流水线和资产台账前统一净化。

use agf_asset::discovery::DiscoveryBatch;
use agf_core::{
    agent::AgentReport,
    error::{DomainError, DomainResult},
    ids::TenantId,
    mcp_config_safety::sanitize_detected_mcp,
};
use serde_json::Value;

pub(super) fn prepare(tenant: TenantId, value: &Value, extras: &Value) -> DomainResult<(String, DiscoveryBatch)> {
    let mut report: AgentReport = serde_json::from_value(value.clone())
        .map_err(|error| DomainError::Validation(format!("report 不是合法的 AgentReport: {error}")))?;
    for mcp in &mut report.mcp_configs {
        sanitize_detected_mcp(mcp);
    }
    for hit in &mut report.credential_hits {
        if hit.masked.len() > 128 {
            hit.masked = "<redacted>".into();
        } else {
            hit.masked = agf_core::secret::mask_default(&hit.masked);
        }
        hit.context = None;
    }
    let mut batch = DiscoveryBatch::from_agent_report(tenant, &report);
    super::agent_extras::append(&mut batch, &report, extras)?;
    let text =
        serde_json::to_string(&report).map_err(|_| DomainError::Internal("无法序列化已脱敏的 Agent 报告".into()))?;
    Ok((text, batch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::{
        agent::{DetectedCredential, DetectedMcp},
        enums::AssetKind,
        time::Timestamp,
    };
    use serde_json::json;

    #[test]
    fn legacy_mcp_and_model_urls_are_safe_in_pipeline_and_ledger() {
        let report = AgentReport {
            collector_id: "collector-test".into(),
            collected_at: Timestamp::now(),
            hostname: "test-host".into(),
            os: "windows".into(),
            os_user: None,
            agents: Vec::new(),
            mcp_configs: vec![DetectedMcp {
                source_file: "mcp.json".into(),
                server_name: "remote".into(),
                transport: "http".into(),
                command: None,
                args: vec!["--api-key".into(), "private-argument".into()],
                url: Some("https://user:private-password@mcp.example.invalid/mcp?token=private-query".into()),
                env_keys: Vec::new(),
                has_plaintext_secret: false,
                auth_configured: false,
            }],
            credential_hits: vec![DetectedCredential {
                source_file: "config.json".into(),
                line: 1,
                kind: "generic".into(),
                masked: "private-credential".into(),
                context: Some("raw context with private-credential".into()),
                confidence: 0.9,
            }],
            scan_scope: Vec::new(),
            agent_version: "0.1.0".into(),
        };
        let value = serde_json::to_value(report).unwrap_or_default();
        let extras = json!({
            "model_endpoints": [{
                "url": "https://user:private-model@model.example.invalid/v1?api_key=private-model-query",
                "key": "MODEL_BASE_URL", "source_file": "settings.json", "has_plaintext_key": false
            }],
            "processes": [{"pid": 8, "name": "cursor.exe", "flavor": "cursor", "command_line": "private-process"}],
            "listening_ports": [{"protocol":"tcp", "local_addr":"127.0.0.1", "port":8091,
                                  "pid":8, "process":"cursor.exe", "env":"private-port"}]
        });
        let prepared = prepare(TenantId::default_tenant(), &value, &extras);
        assert!(prepared.is_ok());
        let Ok((text, batch)) = prepared else { return };
        let serialized = serde_json::to_string(&batch).unwrap_or_default();
        for secret in [
            "private-password",
            "private-query",
            "private-argument",
            "private-model",
            "private-model-query",
            "private-credential",
            "private-process",
            "private-port",
        ] {
            assert!(!text.contains(secret), "原始接入流水线不得留有 MCP 凭据");
            assert!(!serialized.contains(secret), "资产台账不得留有端点凭据");
        }
        let model = batch.assets.iter().find(|asset| asset.kind == AssetKind::ModelEndpoint);
        assert!(model.is_some());
        let Some(model) = model else { return };
        assert_eq!(model.endpoint.as_deref(), Some("https://model.example.invalid/v1"));
        assert!(model.has_plaintext_secret);
    }
}

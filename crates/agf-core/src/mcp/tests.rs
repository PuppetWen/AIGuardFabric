//! 由 `mcp.rs` 拆分：`transport_roundtrip_and_protocol_mapping` 等 6 个函数（纯搬移，逻辑不变）。

use crate::enums::Protocol;
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

#[test]
pub(crate) fn transport_roundtrip_and_protocol_mapping() {
    for (t, s) in [
        (McpTransport::Stdio, "stdio"),
        (McpTransport::Sse, "sse"),
        (McpTransport::Http, "http"),
        (McpTransport::WebSocket, "websocket"),
    ] {
        assert_eq!(t.as_str(), s);
        assert_eq!(McpTransport::parse(s), Ok(t));
    }
    assert_eq!(McpTransport::parse("streamable-http"), Ok(McpTransport::Http));
    assert!(McpTransport::parse("carrier-pigeon").is_err());
    assert_eq!(McpTransport::Stdio.as_protocol(), Protocol::McpStdio);
    assert!(!McpTransport::Stdio.is_remote());
    assert!(McpTransport::Http.is_remote());
}

#[test]
pub(crate) fn capabilities_exfil_channel_detection() {
    let c = McpCapabilities { resources: true, sampling: true, ..McpCapabilities::default() };
    assert!(c.has_exfil_channel());
    let c2 = McpCapabilities { resources: true, ..McpCapabilities::default() };
    assert!(!c2.has_exfil_channel());
    assert_eq!(c.enabled_names(), vec!["resources", "sampling"]);
}

#[test]
pub(crate) fn tool_traits_inference_filesystem_and_network() {
    let t = ToolTraits::infer("read_file", "Read a file from disk");
    assert!(t.filesystem_read);
    let t2 = ToolTraits::infer("http_request", "Fetch a URL over HTTP");
    assert!(t2.network_egress);
    let t3 = ToolTraits::infer("execute_shell", "Run a shell command");
    assert!(t3.shell_exec);
    let t4 = ToolTraits::infer("get_weather", "Return forecast");
    assert!(!t4.is_exfil_capable());
    assert!(!t4.is_rce_capable());
}

#[test]
pub(crate) fn exfil_and_rce_capability_combinations() {
    let exfil = ToolTraits { filesystem_read: true, network_egress: true, ..ToolTraits::default() };
    assert!(exfil.is_exfil_capable());
    let rce = ToolTraits { shell_exec: true, ..ToolTraits::default() };
    assert!(rce.is_rce_capable());
    let persist = ToolTraits { filesystem_write: true, network_egress: true, ..ToolTraits::default() };
    assert!(persist.is_rce_capable());
}

#[test]
pub(crate) fn tool_risk_levels() {
    let high = McpTool {
        name: "run".into(),
        description: String::new(),
        input_schema: serde_json::Value::Null,
        traits: ToolTraits { shell_exec: true, ..ToolTraits::default() },
        sensitive_params: vec![],
    };
    assert_eq!(high.risk_level(), crate::enums::Severity::High);
    let medium = McpTool {
        name: "read".into(),
        description: String::new(),
        input_schema: serde_json::Value::Null,
        traits: ToolTraits { filesystem_read: true, ..ToolTraits::default() },
        sensitive_params: vec![],
    };
    assert_eq!(medium.risk_level(), crate::enums::Severity::Medium);
    let info = McpTool {
        name: "weather".into(),
        description: String::new(),
        input_schema: serde_json::Value::Null,
        traits: ToolTraits::default(),
        sensitive_params: vec![],
    };
    assert_eq!(info.risk_level(), crate::enums::Severity::Info);
}

#[test]
pub(crate) fn shadow_mcp_detection_and_high_risk_count() {
    let mut s = McpServer {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: "fs".into(),
        transport: McpTransport::Stdio,
        command: Some("npx".into()),
        args: vec!["-y".into(), "@modelcontextprotocol/server-filesystem".into()],
        url: None,
        protocol_version: None,
        server_info: None,
        capabilities: McpCapabilities::default(),
        tools: vec![McpTool {
            name: "write_file".into(),
            description: String::new(),
            input_schema: serde_json::Value::Null,
            traits: ToolTraits { filesystem_write: true, ..ToolTraits::default() },
            sensitive_params: vec![],
        }],
        resources: vec![],
        prompts: vec![],
        env_keys: vec![],
        has_plaintext_secret: false,
        requires_auth: false,
        owner: None,
        department: None,
        registered: false,
        last_handshake_at: None,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    assert!(s.is_shadow());
    assert_eq!(s.high_risk_tool_count(), 1);
    s.registered = true;
    assert!(!s.is_shadow());
}

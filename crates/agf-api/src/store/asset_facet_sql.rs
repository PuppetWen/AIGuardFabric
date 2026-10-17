//! SQL equivalents of the typed facets; expressions contain only static keys.
use super::asset_facets::{FLAVORS, MODES, TRANSPORTS};

fn string(key: &str) -> String {
    format!("CASE WHEN jsonb_typeof(a.attributes->'{key}')='string' THEN a.attributes->>'{key}' END")
}
fn normalized(value: &str) -> String {
    format!("replace(lower(trim({value})),'_','-')")
}
fn allowed(value: &str, choices: &[&str], fallback: &str) -> String {
    let choices = choices.iter().map(|v| format!("'{v}'")).collect::<Vec<_>>().join(",");
    format!("CASE WHEN ({value}) IN ({choices}) THEN ({value}) ELSE {fallback} END")
}
pub(super) fn facet(key: &str) -> String {
    match key {
        "flavor" => allowed(&normalized(&format!("COALESCE({}, {}, a.vendor)", string("flavor"), string("vendor"))), FLAVORS, "'custom'"),
        "management" => allowed(&normalized(&string("onboarding_mode")), MODES, "'unmanaged'"),
        "transport" => allowed(&normalized(&string("transport")), &TRANSPORTS[..4],
            "CASE a.protocol WHEN 'mcp-stdio' THEN 'stdio' WHEN 'mcp-sse' THEN 'sse' WHEN 'mcp-http' THEN 'streamable-http' WHEN 'websocket' THEN 'websocket' ELSE CASE WHEN a.protocol IS NULL AND trim(a.endpoint) LIKE 'stdio:%' THEN 'stdio' ELSE 'unknown' END END"),
        "shadow" => "(a.lifecycle='trial' AND a.discovery_source<>'manual')::text".into(),
        "plaintext" => "CASE WHEN jsonb_typeof(a.attributes->'has_plaintext_secret')='boolean' THEN a.attributes->>'has_plaintext_secret' WHEN jsonb_typeof(a.attributes->'hasPlaintextSecret')='boolean' THEN a.attributes->>'hasPlaintextSecret' ELSE 'false' END".into(),
        "observed" => {
            let interval = unsigned("heartbeat_interval_secs", "9223372036854775807");
            format!("CASE WHEN a.lifecycle NOT IN ('production','trial') THEN 'false' WHEN a.last_seen_at IS NULL OR a.last_seen_at>CURRENT_TIMESTAMP THEN 'unknown' ELSE (floor(extract(epoch FROM CURRENT_TIMESTAMP-a.last_seen_at)) <= CASE WHEN ({interval})>0 THEN least(({interval})*3,9223372036854775807) ELSE 300 END)::text END")
        }
        _ => "NULL".into(),
    }
}
pub(super) fn unsigned(key: &str, max: &str) -> String {
    format!(
        "CASE WHEN jsonb_typeof(a.attributes->'{key}')='number' AND (a.attributes->>'{key}')~'^[0-9]+$' THEN CASE WHEN (a.attributes->>'{key}')::numeric <= {max} THEN (a.attributes->>'{key}')::numeric END END"
    )
}

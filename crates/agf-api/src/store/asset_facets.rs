//! Typed inventory facets shared by projection and filtering.
use agf_core::{
    asset::Asset,
    enums::{DiscoverySource, LifecycleState, Protocol},
    time::Timestamp,
};

pub(crate) const FLAVORS: &[&str] =
    &["langchain", "langgraph", "autogen", "crewai", "dify", "coze", "qwen-agent", "custom"];
pub(crate) const MODES: &[&str] = &["sidecar", "sdk-inject", "gateway-register", "unmanaged"];
pub(crate) const TRANSPORTS: &[&str] = &["stdio", "sse", "streamable-http", "websocket", "unknown"];

fn string<'a>(asset: &'a Asset, key: &str) -> Option<&'a str> {
    asset.attributes.get(key).and_then(serde_json::Value::as_str)
}
fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}
pub(crate) fn flavor(asset: &Asset) -> String {
    string(asset, "flavor")
        .or_else(|| string(asset, "vendor"))
        .or(asset.vendor.as_deref())
        .map(normalize)
        .filter(|v| FLAVORS.contains(&v.as_str()))
        .unwrap_or_else(|| "custom".into())
}
pub(crate) fn management(asset: &Asset) -> String {
    string(asset, "onboarding_mode")
        .map(normalize)
        .filter(|v| MODES.contains(&v.as_str()))
        .unwrap_or_else(|| "unmanaged".into())
}
pub(crate) fn transport(asset: &Asset) -> String {
    if let Some(value) = string(asset, "transport").map(normalize).filter(|v| TRANSPORTS[..4].contains(&v.as_str())) {
        return value;
    }
    match asset.protocol {
        Some(Protocol::McpStdio) => "stdio",
        Some(Protocol::McpSse) => "sse",
        Some(Protocol::McpHttp) => "streamable-http",
        Some(Protocol::WebSocket) => "websocket",
        None if asset.endpoint.as_deref().is_some_and(|v| v.trim().starts_with("stdio:")) => "stdio",
        _ => "unknown",
    }
    .into()
}
pub(crate) fn shadow(asset: &Asset) -> bool {
    asset.lifecycle == LifecycleState::Trial && asset.discovery_source != DiscoverySource::Manual
}
pub(crate) fn plaintext(asset: &Asset) -> bool {
    asset
        .attributes
        .get("has_plaintext_secret")
        .and_then(serde_json::Value::as_bool)
        .or_else(|| asset.attributes.get("hasPlaintextSecret").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}
pub(crate) fn online(asset: &Asset, now: Timestamp) -> Option<bool> {
    if !asset.is_live() {
        return Some(false);
    }
    let seen = asset.last_seen_at?;
    if seen > now {
        return None;
    }
    let interval =
        asset.attributes.get("heartbeat_interval_secs").and_then(serde_json::Value::as_i64).filter(|v| *v > 0);
    Some(now.since_secs(&seen) <= interval.map_or(300, |v| v.saturating_mul(3)))
}

#[derive(Clone, Default)]
pub(crate) struct FacetSelection {
    pub values: Vec<(&'static str, Vec<String>)>,
}
impl FacetSelection {
    pub(crate) fn from_query(query: &crate::query::ListQuery) -> agf_core::error::DomainResult<Self> {
        let mut values = Vec::new();
        for (name, allowed) in [
            ("flavor", FLAVORS),
            ("management", MODES),
            ("transport", TRANSPORTS),
            ("shadow", &["true", "false"][..]),
            ("plaintext", &["true", "false"][..]),
            ("observed", &["true", "false", "unknown"][..]),
        ] {
            let rows = query.filter_many(name);
            if rows.len() > 100 || rows.iter().any(|v| !allowed.contains(&v.as_str())) {
                return Err(agf_core::error::DomainError::Validation(format!("Invalid {name} inventory filter")));
            }
            if !rows.is_empty() {
                values.push((name, rows));
            }
        }
        Ok(Self { values })
    }
    pub(crate) fn matches(&self, asset: &Asset) -> bool {
        self.values.iter().all(|(key, values)| {
            let value = match *key {
                "flavor" => flavor(asset),
                "management" => management(asset),
                "transport" => transport(asset),
                "shadow" => shadow(asset).to_string(),
                "plaintext" => plaintext(asset).to_string(),
                "observed" => online(asset, Timestamp::now()).map_or_else(|| "unknown".into(), |v| v.to_string()),
                _ => return false,
            };
            values.contains(&value)
        })
    }
}

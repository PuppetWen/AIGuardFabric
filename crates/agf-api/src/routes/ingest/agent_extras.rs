//! 将终端模型、Skill、进程和监听信息纳入资产发现，端点 URL 剥离凭据。
use agf_asset::discovery::{DiscoveredAsset, DiscoveryBatch};
use agf_core::{
    agent::AgentReport,
    enums::{AssetKind, DiscoverySource},
    error::{DomainError, DomainResult},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Default, Deserialize)]
struct Extras {
    #[serde(default)]
    model_endpoints: Vec<Model>,
    #[serde(default)]
    skills: Vec<Skill>,
    #[serde(default)]
    processes: Vec<ProcessObservation>,
    #[serde(default)]
    listening_ports: Vec<PortObservation>,
}
#[derive(Deserialize, Serialize)]
struct ProcessObservation {
    pid: u32,
    name: String,
    flavor: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct PortObservation {
    protocol: String,
    local_addr: String,
    port: u16,
    pid: Option<u32>,
    process: Option<String>,
}
#[derive(Deserialize)]
struct Model {
    url: String,
    key: String,
    source_file: String,
    provider_hint: Option<String>,
    #[serde(default)]
    has_plaintext_key: bool,
}
#[derive(Deserialize)]
struct Skill {
    #[serde(default)]
    package: Option<agf_core::skill_package::PackageObservation>,
    #[serde(default)]
    content_sha256: Option<String>,
    #[serde(default)]
    content_hash_status: Option<String>,
    name: String,
    source_path: String,
    kind: String,
}

pub(super) fn append(batch: &mut DiscoveryBatch, report: &AgentReport, raw: &Value) -> DomainResult<()> {
    if raw.is_null() {
        return Ok(());
    }
    let extras: Extras = serde_json::from_value(raw.clone())
        .map_err(|_| DomainError::Validation("extras 不是有效的终端扩展资产".into()))?;
    if extras.model_endpoints.len() + extras.skills.len() > 4096
        || extras.processes.len() + extras.listening_ports.len() > 16384
    {
        return Err(DomainError::Validation("单次终端扩展资产超过容量上限".into()));
    }
    for asset in &mut batch.assets {
        if asset.kind == AssetKind::Agent {
            asset.attributes["processes"] = json!(extras.processes);
            asset.attributes["listening_ports"] = json!(extras.listening_ports);
        }
    }
    for detected in extras.model_endpoints {
        let (endpoint, private_url) = agf_core::mcp_config_safety::safe_report_url(&detected.url)
            .ok_or_else(|| DomainError::Validation("模型端点仅接受安全的 HTTP(S) URL".into()))?;
        let fp = agf_core::secret::content_hash(&format!("model:{}:{}", report.hostname, endpoint));
        let mut asset = DiscoveredAsset::new(AssetKind::ModelEndpoint, detected.key, fp, DiscoverySource::AgentReport);
        asset.endpoint = Some(endpoint);
        asset.vendor = detected.provider_hint;
        asset.host = Some(report.hostname.clone());
        asset.owner.clone_from(&report.os_user);
        asset.evidence_ref = detected.source_file;
        asset.has_plaintext_secret = detected.has_plaintext_key || private_url;
        asset.attributes = json!({"collector_id":report.collector_id,"discovered_only":true});
        batch.assets.push(asset);
    }
    for detected in extras.skills {
        let fp = agf_core::secret::content_hash(&format!("skill:{}:{}", report.hostname, detected.source_path));
        let mut asset = DiscoveredAsset::new(AssetKind::Skill, detected.name, fp, DiscoverySource::AgentReport);
        asset.host = Some(report.hostname.clone());
        asset.owner.clone_from(&report.os_user);
        asset.evidence_ref = detected.source_path;
        asset.attributes = json!({"collector_id":report.collector_id,"kind":detected.kind});
        if let Some(mut package) = detected.package {
            package.validate().map_err(|message| DomainError::Validation(message.into()))?;
            if detected.kind != "skill" {
                return Err(DomainError::Validation("Package observation is only valid for a Skill directory".into()));
            }
            if let Some(hash) = &mut package.sha256 {
                hash.make_ascii_lowercase();
            }
            asset.attributes["skill_package"] = json!(package);
            asset.attributes["skill_package_received_at"] = json!(agf_core::time::Timestamp::now());
        }
        if let Some(hash) = &detected.content_sha256 {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(DomainError::Validation("Skill content_sha256 must contain 64 hexadecimal digits".into()));
            }
            asset.attributes["content_sha256"] = json!(hash.to_ascii_lowercase());
            asset.attributes["content_hash_observed_at"] = json!(agf_core::time::Timestamp::now());
        }
        if let Some(status) = detected.content_hash_status {
            if !["verified", "unreadable", "too-large", "not-regular-file", "changed-during-read"]
                .contains(&status.as_str())
                || (status == "verified") != detected.content_sha256.is_some()
            {
                return Err(DomainError::Validation("Skill content hash status is inconsistent".into()));
            }
            asset.attributes["content_hash_status"] = json!(status);
            asset.attributes["content_hash_observed_at"] = json!(agf_core::time::Timestamp::now());
            if detected.content_sha256.is_none() {
                asset.attributes["content_sha256"] = Value::Null;
            }
        }
        batch.assets.push(asset);
    }
    Ok(())
}

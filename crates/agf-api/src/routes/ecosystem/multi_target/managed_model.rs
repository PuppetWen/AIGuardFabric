//! Server-authenticated per-profile transport approval; absent configuration grants no private access.
use super::{
    mcp::Revision,
    records::corrupt,
    types::{Kind, hash},
};
use crate::AppState;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
pub(super) const KIND: &str = "redteam-multi-managed-profile";

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PrivateNetwork {
    pub(super) addresses: Vec<IpAddr>,
    pub(super) port: u16,
    pub(super) allow_plain_http: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) expected_version: u64,
    pub(super) profile_version: u64,
    pub(super) url: String,
    pub(super) enabled: bool,
    pub(super) mcp_protocol_revision: Revision,
    pub(super) private_network: Option<PrivateInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateInput {
    pub(super) addresses: Vec<IpAddr>,
    pub(super) port: u16,
    pub(super) allow_plain_http: bool,
    pub(super) confirm_exact_private_network: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Control {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) kind: Kind,
    pub(super) profile: Id,
    pub(super) profile_version: u64,
    pub(super) version: u64,
    pub(super) url: String,
    pub(super) enabled: bool,
    pub(super) revision: Revision,
    pub(super) private: Option<PrivateNetwork>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Envelope {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) body: SecretMaterial,
}
pub(super) fn key(tenant: TenantId, kind: Kind, profile: Id) -> Id {
    deterministic_id("agf.redteam.multi.managed-profile", &format!("{tenant}:{}:{profile}", kind.registry()))
}
pub(super) fn private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none() && (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}
impl PrivateNetwork {
    pub(super) fn validate(&self, url: &reqwest::Url) -> DomainResult<()> {
        if self.addresses.is_empty()
            || self.addresses.len() > 8
            || self.port == 0
            || self.port != url.port_or_known_default().ok_or_else(invalid)?
            || self.addresses.iter().any(|ip| !private_address(*ip))
            || self.addresses.iter().collect::<std::collections::BTreeSet<_>>().len() != self.addresses.len()
            || !matches!(url.scheme(), "http" | "https")
            || (url.scheme() == "http" && !self.allow_plain_http)
            || super::transport::literal_ip(url).is_some_and(|ip| !self.addresses.contains(&ip))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Control {
    pub(super) fn validate(&self, tenant: TenantId, kind: Kind, profile: Id) -> DomainResult<()> {
        if self.tenant != tenant
            || self.kind != kind
            || self.profile != profile
            || profile.is_nil()
            || self.id != key(tenant, kind, profile)
            || self.profile_version == 0
            || self.version == 0
            || (kind == Kind::AgentHttp && self.revision != Revision::Modern)
        {
            return Err(corrupt());
        }
        let url = super::transport::parse(&self.url)?;
        if let Some(private) = &self.private {
            private.validate(&url)?;
        }
        // Syntax is not permission. save/capture additionally require approved private
        // addresses, public HTTPS or the current default-off typed loopback capability.
        else if !matches!(url.scheme(), "http" | "https") {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn view(&self) -> serde_json::Value {
        serde_json::json!({"kind":self.kind,"profileId":self.profile,"profileVersion":self.profile_version,"version":self.version,
            "url":self.url,"enabled":self.enabled,"mcpProtocolRevision":self.revision,"privateNetwork":self.private.as_ref().map(|private|
            serde_json::json!({"addresses":private.addresses,"port":private.port,"allowPlainHttp":private.allow_plain_http})),
            "defaultPrivateAccess":false,"automaticProtocolFallback":false})
    }
}
pub(super) fn seal(state: &AppState, row: &Control) -> DomainResult<Envelope> {
    row.validate(row.tenant, row.kind, row.profile)?;
    let raw = serde_json::to_string(row)?;
    if raw.len() > 8 * 1024 {
        return Err(invalid());
    }
    Ok(Envelope {
        tenant: row.tenant,
        id: row.id,
        body: crate::model_gateway::encrypt(state, row.tenant, row.id, raw)?,
    })
}
pub(super) fn restore(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    profile: Id,
    envelope: &Envelope,
) -> DomainResult<Control> {
    let id = key(tenant, kind, profile);
    if envelope.tenant != tenant
        || envelope.id != id
        || envelope.body.aad.as_deref() != Some(agf_storage::crypto::FieldCipher::make_aad(&tenant, &id).as_str())
    {
        return Err(corrupt());
    }
    let raw = crate::model_gateway::cipher(state)?.decrypt(&envelope.body)?;
    if raw.expose_secret().len() > 8 * 1024 {
        return Err(corrupt());
    }
    let row: Control = serde_json::from_str(raw.expose_secret()).map_err(|_| corrupt())?;
    row.validate(tenant, kind, profile)?;
    Ok(row)
}
pub(super) async fn read(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    profile: Id,
) -> DomainResult<Option<Envelope>> {
    state.configurations.get(tenant, KIND, key(tenant, kind, profile)).await
}
pub(super) fn fingerprint(row: Option<&Envelope>) -> DomainResult<Option<String>> {
    row.map(hash).transpose()
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("Approve this exact current profile URL, version, private addresses and port; plain HTTP additionally requires explicit consent".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_private_addresses_exact_port_and_http_consent_are_eligible() -> DomainResult<()> {
        let url = reqwest::Url::parse("http://10.2.3.4:8080/mcp").map_err(|_| invalid())?;
        let mut network = PrivateNetwork {
            addresses: vec!["10.2.3.4".parse().map_err(|_| invalid())?],
            port: 8080,
            allow_plain_http: false,
        };
        assert!(network.validate(&url).is_err());
        network.allow_plain_http = true;
        assert!(network.validate(&url).is_ok());
        network.port = 8081;
        assert!(network.validate(&url).is_err());
        for raw in ["127.0.0.1", "169.254.169.254", "8.8.8.8", "::1", "fe80::1"] {
            assert!(!private_address(raw.parse().map_err(|_| invalid())?));
        }
        assert!(private_address("fd00::123".parse().map_err(|_| invalid())?));
        let ula = reqwest::Url::parse("http://[fd00::123]:8080/mcp").map_err(|_| invalid())?;
        network.addresses = vec!["fd00::123".parse().map_err(|_| invalid())?];
        network.port = 8080;
        assert!(network.validate(&ula).is_ok());
        let wrong = reqwest::Url::parse("http://[fd00::124]:8080/mcp").map_err(|_| invalid())?;
        assert!(network.validate(&wrong).is_err());
        Ok(())
    }
}

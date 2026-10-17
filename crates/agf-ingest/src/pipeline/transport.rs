//! Trusted connection attributes. Never deserialize these from a log or HTTP header.
use std::net::IpAddr;

use agf_core::{
    error::{DomainError, DomainResult},
    source::LogSource,
};
use ipnet::IpNet;

/// The receiver supplies socket metadata and the result of certificate verification.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransportPeer {
    /// Direct peer address. Forwarded headers and payload origins are not authoritative.
    pub ip: Option<IpAddr>,
    /// True only after the transport (or an authenticated gateway) verified the certificate.
    pub mutual_tls: bool,
}

impl TransportPeer {
    /// Reject before parsing, persistence or publication, including empty exports.
    ///
    /// # Errors
    /// A disabled source, unverifiable peer, invalid policy or denied connection.
    pub fn authorize(self, source: &LogSource) -> DomainResult<()> {
        if !source.enabled {
            return Err(DomainError::Forbidden("Log source is disabled".into()));
        }
        if source.require_mtls && !self.mutual_tls {
            return Err(DomainError::Forbidden("This log source requires a verified client certificate".into()));
        }
        if !source.allowed_cidrs.is_empty() {
            let networks = validate_cidrs(&source.allowed_cidrs)?;
            let allowed = self.ip.is_some_and(|ip| {
                let canonical = match ip {
                    IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
                    ip @ IpAddr::V4(_) => ip,
                };
                networks.iter().any(|network| network.contains(&ip) || network.contains(&canonical))
            });
            if !allowed {
                return Err(DomainError::Forbidden("Connection IP is outside this log source's allowed CIDRs".into()));
            }
        }
        Ok(())
    }
}

/// Parse bounded, explicit IPv4/IPv6 CIDRs; a malformed entry never becomes allow-all.
///
/// # Errors
/// More than 64 entries, invalid network notation or hostnames.
pub fn validate_cidrs(values: &[String]) -> DomainResult<Vec<IpNet>> {
    if values.len() > 64 {
        return Err(DomainError::Validation("At most 64 source CIDRs are supported".into()));
    }
    values
        .iter()
        .map(|value| {
            value.parse::<IpNet>().map_err(|_| DomainError::Validation(format!("Invalid source CIDR: {value}")))
        })
        .collect()
}

/// Capabilities of direct inbound native listeners, not publisher addresses in broker messages.
#[must_use]
pub fn source_transport_controls(receiver: &str) -> (bool, bool) {
    match receiver {
        "syslog-tls" | "otlp-grpc" | "otlp-grpc-traces" | "otlp-grpc-metrics" => (true, true),
        "syslog-udp" | "syslog-tcp" | "otlp" | "otlp-traces" | "otlp-metrics" => (true, false),
        _ => (false, false),
    }
}

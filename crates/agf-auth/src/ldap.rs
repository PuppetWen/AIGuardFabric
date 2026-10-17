//! LDAP/AD password verification over certificate-verified LDAPS or StartTLS.
//! The directory password is only sent to the directory and is never stored by AGF.

use std::{sync::Arc, time::Duration};

use agf_core::error::{DomainError, DomainResult};
use base64::{Engine, engine::general_purpose::STANDARD};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions, ldap_escape};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use url::Url;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Tenant-owned directory connection and attribute mapping. Secrets are supplied separately.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// LDAP server URL. Only `ldaps://` or `ldap://` with StartTLS is accepted.
    pub url: String,
    /// Enable StartTLS before any bind on an `ldap://` endpoint.
    pub start_tls: bool,
    /// Subtree in which an exact user search is performed.
    pub base_dn: String,
    /// Service account distinguished name used only for searching.
    pub bind_dn: String,
    /// LDAP filter with exactly one `{username}` placeholder.
    pub user_filter: String,
    /// Stable directory identifier, e.g. `entryUUID` or AD `objectGUID`.
    pub id_attribute: String,
    /// Optional verified directory email attribute.
    pub email_attribute: String,
    /// Optional directory display name attribute.
    pub name_attribute: String,
    /// PEM-encoded private CA; empty means system trust roots.
    #[serde(default)]
    pub ca_pem: String,
}

/// Authenticated immutable subject and optional profile data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Stable value of the configured unique directory attribute.
    pub subject: String,
    /// Directory email, if present.
    pub email: Option<String>,
    /// Directory display name, if present.
    pub name: Option<String>,
}

fn invalid(message: &str) -> DomainError {
    DomainError::Validation(message.into())
}

fn unavailable(phase: &str) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "ldap".into(), cause: phase.into() }
}

fn rejected() -> DomainError {
    DomainError::Unauthenticated("企业目录账号或口令无效".into())
}

fn ca_roots(pem: &str) -> DomainResult<RootCertStore> {
    let bad_ca = || invalid("CA 证书须为有效 PEM，且不能包含私钥");
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(bad_ca());
    }
    let mut roots = RootCertStore::empty();
    let mut input = pem.as_bytes();
    for item in rustls_pemfile::read_all(&mut input) {
        let item = item.map_err(|_| bad_ca())?;
        let rustls_pemfile::Item::X509Certificate(cert) = item else {
            return Err(bad_ca());
        };
        roots.add(cert).map_err(|_| bad_ca())?;
    }
    if roots.is_empty() {
        return Err(bad_ca());
    }
    Ok(roots)
}

impl Config {
    /// Validate the transport and filter before persisting a tenant configuration.
    pub fn validate(&self) -> DomainResult<()> {
        let url = Url::parse(&self.url).map_err(|_| invalid("目录地址须为完整 LDAPS 或 StartTLS URL"))?;
        if !matches!((url.scheme(), self.start_tls), ("ldaps", false) | ("ldap", true))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid("目录连接必须使用证书校验的 LDAPS 或 StartTLS，地址不得含凭据、路径或参数"));
        }
        if self.base_dn.trim().is_empty()
            || self.bind_dn.trim().is_empty()
            || self.base_dn.len() > 1024
            || self.bind_dn.len() > 1024
            || self.user_filter.len() > 1024
            || self.user_filter.matches("{username}").count() != 1
        {
            return Err(invalid("请填写搜索根、服务账号 DN 和包含一次 {username} 的用户过滤器"));
        }
        if self.id_attribute.is_empty() {
            return Err(invalid("唯一 ID 属性必填"));
        }
        for attr in [&self.id_attribute, &self.email_attribute, &self.name_attribute] {
            if attr.len() > 64 || !attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(invalid("目录属性名只能包含字母、数字和连字符；唯一 ID 属性必填"));
            }
        }
        if self.ca_pem.len() > 32_768 {
            return Err(invalid("CA 证书内容过大"));
        }
        if !self.ca_pem.is_empty() {
            ca_roots(&self.ca_pem)?;
        }
        Ok(())
    }
}

fn first_text(entry: &SearchEntry, attr: &str) -> Option<String> {
    entry
        .attrs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(attr))
        .and_then(|(_, values)| values.first())
        .filter(|v| !v.is_empty())
        .cloned()
}

fn subject(entry: &SearchEntry, attr: &str) -> Option<String> {
    first_text(entry, attr).or_else(|| {
        entry
            .bin_attrs
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(attr))
            .and_then(|(_, values)| values.first())
            .filter(|v| !v.is_empty())
            .map(|value| format!("base64:{}", STANDARD.encode(value)))
    })
}

/// Search a single directory account, then bind as that exact DN with the supplied password.
/// Ambiguous searches and missing immutable IDs fail closed.
pub async fn authenticate(
    config: &Config,
    service_password: &str,
    username: &str,
    password: &str,
) -> DomainResult<Identity> {
    config.validate()?;
    if username.is_empty()
        || username.len() > 256
        || username.contains('\0')
        || password.is_empty()
        || password.len() > 4096
        || service_password.is_empty()
    {
        return Err(rejected());
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(unavailable("目录 TLS 加密提供程序不可用"));
    }
    let mut settings = LdapConnSettings::new().set_conn_timeout(TIMEOUT).set_starttls(config.start_tls);
    if !config.ca_pem.is_empty() {
        let roots = ca_roots(&config.ca_pem)?;
        let tls = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        settings = settings.set_config(Arc::new(tls));
    }
    let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
        .await
        .map_err(|_| unavailable("目录连接或 TLS 握手失败"))?;
    ldap3::drive!(connection);
    let service_bind = ldap
        .with_timeout(TIMEOUT)
        .simple_bind(&config.bind_dn, service_password)
        .await
        .map_err(|_| unavailable("目录服务账号绑定失败"))?;
    if service_bind.rc != 0 {
        return Err(unavailable(&format!("目录服务账号被拒绝（LDAP 状态码 {}）", service_bind.rc)));
    }
    let filter = config.user_filter.replace("{username}", &ldap_escape(username));
    let attributes = [
        config.id_attribute.as_str(),
        config.email_attribute.as_str(),
        config.name_attribute.as_str(),
        "userAccountControl",
    ];
    let (entries, _) = ldap
        .with_search_options(SearchOptions::new().sizelimit(2).timelimit(10))
        .with_timeout(TIMEOUT)
        .search(&config.base_dn, Scope::Subtree, &filter, attributes)
        .await
        .map_err(|_| unavailable("目录搜索请求失败"))?
        .success()
        .map_err(|_| unavailable("目录搜索结果失败"))?;
    let [entry] = <[ldap3::ResultEntry; 1]>::try_from(entries).map_err(|_| rejected())?;
    let entry = SearchEntry::construct(entry);
    if first_text(&entry, "userAccountControl").and_then(|v| v.parse::<u32>().ok()).is_some_and(|flags| flags & 2 != 0)
    {
        return Err(rejected());
    }
    let id = subject(&entry, &config.id_attribute).ok_or_else(rejected)?;
    if entry.dn.is_empty() {
        return Err(rejected());
    }
    let email = first_text(&entry, &config.email_attribute);
    let name = first_text(&entry, &config.name_attribute);
    let result = ldap
        .with_timeout(TIMEOUT)
        .simple_bind(&entry.dn, password)
        .await
        .map_err(|_| unavailable("目录成员验证连接失败"))?;
    if result.rc != 0 {
        return Err(rejected());
    }
    let _ = ldap.unbind().await;
    Ok(Identity { subject: id, email, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            url: "ldaps://ad.example.test:636".into(),
            start_tls: false,
            base_dn: "dc=example,dc=test".into(),
            bind_dn: "cn=reader,dc=example,dc=test".into(),
            user_filter: "(&(objectClass=user)(sAMAccountName={username}))".into(),
            id_attribute: "objectGUID".into(),
            email_attribute: "mail".into(),
            name_attribute: "displayName".into(),
            ca_pem: String::new(),
        }
    }

    #[test]
    fn requires_encrypted_verified_transport_and_stable_mapping() {
        assert!(config().validate().is_ok());
        let mut bad = config();
        bad.url = "ldap://ad.example.test:389".into();
        assert!(bad.validate().is_err());
        bad.start_tls = true;
        assert!(bad.validate().is_ok());
        bad.user_filter = "(uid=*)".into();
        assert!(bad.validate().is_err());
        bad.user_filter = "(uid={username})".into();
        bad.id_attribute.clear();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn escapes_filter_injection() {
        assert_eq!(ldap_escape("a*)(|(uid=*))"), "a\\2a\\29\\28|\\28uid=\\2a\\29\\29");
    }
}

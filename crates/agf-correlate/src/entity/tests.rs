//! 由 `entity.rs` 拆分：`event_with` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn event_with(tenant: TenantId) -> Event {
    Event::new(tenant, Id::new(), IngestProtocol::Syslog)
}

#[test]
pub(crate) fn ipv4_normalization_strips_leading_zeros() {
    assert_eq!(normalize_ip("010.001.000.255"), Some("10.1.0.255".to_string()));
    assert_eq!(normalize_ip("10.0.0.1"), Some("10.0.0.1".to_string()));
    assert_eq!(normalize_ip("10.0.0.256"), None);
    assert_eq!(normalize_ip("10.0.0"), None);
    assert_eq!(normalize_ip(""), None);
}

#[test]
pub(crate) fn ipv6_compressed_and_expanded_match() {
    let a = normalize_ip("::1");
    let b = normalize_ip("0:0:0:0:0:0:0:1");
    assert_eq!(a, b);
    assert_eq!(a, Some("0000:0000:0000:0000:0000:0000:0000:0001".to_string()));
    assert_eq!(normalize_ip("2001:db8::1"), normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"));
    assert_eq!(normalize_ip("[::ffff:10.0.0.1]"), normalize_ip("::ffff:10.0.0.1"));
    assert_eq!(normalize_ip("::1::2"), None);
}

#[test]
pub(crate) fn hostname_normalization() {
    assert_eq!(normalize_hostname(" WorkStation-01.CORP.local. "), "workstation-01.corp.local");
    assert_eq!(normalize_hostname("https://HOST.A"), "host.a");
}

#[test]
pub(crate) fn domain_normalization() {
    assert_eq!(normalize_domain("WWW.Example.COM."), Some("example.com".to_string()));
    assert_eq!(normalize_domain("https://api.example.com:8443/v1/x?y=1"), Some("api.example.com".to_string()));
    assert_eq!(normalize_domain("not a domain"), None);
    assert_eq!(normalize_domain("1.2"), None);
    assert_eq!(normalize_domain("localhost"), None, "无点不算域名");
}

#[test]
pub(crate) fn email_normalization() {
    assert_eq!(normalize_email("<Alice@Example.COM>"), Some("alice@example.com".to_string()));
    assert_eq!(normalize_email("bad@@x.com"), None);
    assert_eq!(normalize_email("no-at-sign"), None);
}

#[test]
pub(crate) fn resource_identifier_normalization() {
    assert_eq!(normalize_resource_identifier("arn:aws:s3:::MyBucket/Key"), "mybucket/key");
    assert_eq!(normalize_resource_identifier("/Var/Log/App.log"), "var/log/app.log");
    assert_eq!(normalize_resource_identifier("a\\b"), "a/b");
}

#[test]
pub(crate) fn extract_structural_entities() {
    let tenant = TenantId::default_tenant();
    let mut e = event_with(tenant);
    e.source_name = "edr".into();
    e.host.name = Some("Workstation-01.CORP".into());
    e.host.id = Some("HOST-UUID-1".into());
    e.host.ips = vec!["10.0.0.7".into()];
    e.user.name = Some("Alice".into());
    e.user.email = Some("alice@example.com".into());
    e.network.destination_ip = Some("8.8.8.8".into());
    e.network.domain = Some("api.external.com".into());

    let aligner = EntityAligner::new();
    let ents = aligner.extract(&e);
    assert!(!ents.is_empty());
    assert_eq!(ents.strongest().map(|r| r.strength), Some(EntityRefStrength::Strong));
    assert!(ents.identifiers(EntityKind::Host).contains(&"workstation-01.corp".to_string()));
    assert!(ents.identifiers(EntityKind::Host).contains(&"10.0.0.7".to_string()), "IP 应被提升为主机指称");
    assert!(ents.identifiers(EntityKind::User).contains(&"alice@example.com".to_string()));
    assert!(ents.identifiers(EntityKind::Domain).contains(&"api.external.com".to_string()));
    assert_eq!(ents.identifiers(EntityKind::Ip).len(), 2);
}

#[test]
pub(crate) fn alignment_key_is_tenant_scoped_and_kind_scoped() {
    let t1 = TenantId::default_tenant();
    let t2 = TenantId::new();
    let a = entity_alignment_key(t1, Some(EntityKind::Host), "h1");
    let b = entity_alignment_key(t2, Some(EntityKind::Host), "h1");
    let c = entity_alignment_key(t1, Some(EntityKind::Ip), "h1");
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert!(a.contains("|host|h1"));
    assert!(entity_alignment_key(t1, None, "x").contains("|generic|x"));
}

#[test]
pub(crate) fn entity_id_is_deterministic() {
    let t = TenantId::default_tenant();
    let a = EntityRef::new(Some(EntityKind::Host), "h1", EntityRefStrength::Strong, "s");
    let b = EntityRef::new(Some(EntityKind::Host), "h1", EntityRefStrength::Weak, "other");
    assert_eq!(a.entity_id(t), b.entity_id(t), "对齐键相同则实体 id 相同（强度/来源不参与）");
    assert_ne!(a.entity_id(t), b.entity_id(TenantId::new()), "跨租户必须不同");
}

#[test]
pub(crate) fn message_scanning_is_bounded_and_optional() {
    let tenant = TenantId::default_tenant();
    let mut e = event_with(tenant);
    e.message = "blocked 10.1.1.1 and 10.1.1.2 and evil.example.net and bob@corp.com".into();
    let ents = EntityAligner::new().extract(&e);
    assert!(ents.identifiers(EntityKind::Ip).contains(&"10.1.1.1".to_string()));
    assert!(ents.identifiers(EntityKind::Domain).contains(&"evil.example.net".to_string()));
    assert!(ents.identifiers(EntityKind::User).contains(&"bob@corp.com".to_string()));

    let structural = EntityAligner::structural_only().extract(&e);
    assert!(structural.is_empty(), "关闭正文扫描后不应从 message 抽取");
}

#[test]
pub(crate) fn cross_source_alignment_finds_multi_source_entities() {
    let tenant = TenantId::default_tenant();
    let mut a = event_with(tenant);
    a.source_name = "edr".into();
    a.host.name = Some("ws-01".into());
    a.network.destination_ip = Some("203.0.113.9".into());

    let mut b = event_with(tenant);
    b.source_name = "gateway".into();
    b.network.source_ip = Some("203.0.113.9".into());
    b.network.domain = Some("c2.example.net".into());

    let aligner = EntityAligner::new();
    let alignment = CrossSourceAlignment::from_events(tenant, &aligner, &[a, b]);
    let multi = alignment.multi_source();
    assert!(multi.iter().any(|(k, n)| k.contains("203.0.113.9") && *n == 2), "同一 IP 应被两个来源观察到: {multi:?}");
    assert!(alignment.len() >= 3);
    assert!(!alignment.is_empty());
}

#[test]
pub(crate) fn shares_strong_entity_requires_strong_evidence() {
    let tenant = TenantId::default_tenant();
    let aligner = EntityAligner::new();

    let mut a = event_with(tenant);
    a.host.id = Some("HOST-1".into());
    let mut b = event_with(tenant);
    b.host.id = Some("HOST-1".into());
    let mut c = event_with(tenant);
    c.host.name = Some("other".into());

    let ea = CrossSourceAlignment::from_events(tenant, &aligner, std::slice::from_ref(&a));
    let eb = CrossSourceAlignment::from_events(tenant, &aligner, std::slice::from_ref(&b));
    let ec = CrossSourceAlignment::from_events(tenant, &aligner, std::slice::from_ref(&c));
    assert!(ea.shares_strong_entity(&eb));
    assert!(!ea.shares_strong_entity(&ec));
}

#[test]
pub(crate) fn empty_event_yields_no_entities() {
    let e = event_with(TenantId::default_tenant());
    let ents = EntityAligner::new().extract(&e);
    assert!(ents.is_empty());
    assert!(ents.alignment_keys(TenantId::default_tenant()).is_empty());
    assert!(ents.strongest().is_none());
}

#[test]
pub(crate) fn by_kind_and_alignment_keys_are_stable() {
    let tenant = TenantId::default_tenant();
    let mut e = event_with(tenant);
    e.severity = Severity::High;
    e.host.name = Some("a".into());
    e.host.id = Some("b".into());
    let ents = EntityAligner::new().extract(&e);
    let k1 = ents.alignment_keys(tenant);
    let k2 = ents.alignment_keys(tenant);
    assert_eq!(k1, k2);
    assert_eq!(k1.len(), 2);
    assert_eq!(ents.by_kind.get("host").map(BTreeSet::len), Some(2));
}

#[test]
pub(crate) fn entity_kind_str_matrix() {
    assert_eq!(EntityKind::all().len(), 7);
    assert_eq!(EntityKind::McpServer.as_str(), "mcp-server");
    for k in EntityKind::all() {
        assert!(!k.as_str().is_empty());
    }
}

#[test]
pub(crate) fn agents_and_mcp_are_extracted() {
    let tenant = TenantId::default_tenant();
    let mut e = event_with(tenant);
    e.ai.agent_id = Some(Id::new());
    e.ai.mcp_server_id = Some(Id::new());
    let ents = EntityAligner::new().extract(&e);
    assert_eq!(ents.identifiers(EntityKind::Agent).len(), 1);
    assert_eq!(ents.identifiers(EntityKind::McpServer).len(), 1);
}

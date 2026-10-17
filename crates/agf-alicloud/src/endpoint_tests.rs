use super::*;
use crate::test_support::fixture_integration;
use agf_core::cloud::CloudCredentialKind;

fn empty_overrides() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[test]
fn public_endpoint_uses_published_region() {
    let ep = resolve(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &empty_overrides());
    assert!(ep.is_ok());
    if let Ok(ep) = ep {
        assert_eq!(ep.host, "metrics.cn-hangzhou.aliyuncs.com");
        assert_eq!(ep.style, EndpointStyle::Public);
        assert_eq!(ep.origin, "public");
        assert!(!ep.is_private());
        assert_eq!(ep.url("/"), "https://metrics.cn-hangzhou.aliyuncs.com/");
        assert_eq!(ep.url("pop/2019-01-01/events"), "https://metrics.cn-hangzhou.aliyuncs.com/pop/2019-01-01/events");
    }
}

#[test]
fn public_endpoint_for_regional_service_includes_region() {
    let ep = resolve(AliCloudService::Apig, "cn-shanghai", EndpointStyle::Public, &empty_overrides());
    assert!(ep.is_ok());
    if let Ok(ep) = ep {
        assert_eq!(ep.host, "apig.cn-shanghai.aliyuncs.com");
    }
    let mse = resolve(AliCloudService::Mse, "cn-beijing", EndpointStyle::Public, &empty_overrides());
    assert_eq!(mse.ok().map(|e| e.host), Some("mse.cn-beijing.aliyuncs.com".to_string()));
}

#[test]
fn private_endpoint_uses_published_vpc_address() {
    let ep = resolve(AliCloudService::Mse, "cn-hangzhou", EndpointStyle::Private, &empty_overrides());
    assert!(ep.is_ok());
    if let Ok(ep) = ep {
        assert_eq!(ep.host, "mse-vpc.cn-hangzhou.aliyuncs.com");
        assert!(ep.is_private());
        assert_eq!(ep.origin, "privatelink");
        assert_eq!(ep.style.as_str(), "private");
    }
    let sch = resolve(AliCloudService::SchedulerX3, "cn-hangzhou", EndpointStyle::Private, &empty_overrides());
    assert_eq!(sch.ok().map(|e| e.host), Some("schedulerx3-vpc.cn-hangzhou.aliyuncs.com".to_string()));
}

#[test]
fn explicit_override_wins_and_infers_private() {
    let mut overrides = BTreeMap::new();
    overrides.insert("cms".to_string(), "https://metrics.cn-hangzhou.privatelink.aliyuncs.com/".to_string());
    // 即便请求公网风格，客户显式填的私网域名也必须生效
    let ep = resolve(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &overrides);
    assert!(ep.is_ok());
    if let Ok(ep) = ep {
        assert_eq!(ep.host, "metrics.cn-hangzhou.privatelink.aliyuncs.com", "必须去掉 scheme 与尾斜杠");
        assert_eq!(ep.origin, "override");
        assert!(ep.is_private(), "含 privatelink 的覆盖域名按私网处理");
    }
    // 空字符串覆盖 = 未配置，回落到推导值
    let mut blank = BTreeMap::new();
    blank.insert("cms".to_string(), "   ".to_string());
    let ep2 = resolve(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &blank);
    assert_eq!(ep2.ok().map(|e| e.origin), Some("public"));
}

#[test]
fn normalize_host_strips_scheme_and_slash() {
    assert_eq!(normalize_host("https://a.example.com/"), "a.example.com");
    assert_eq!(normalize_host("http://a.example.com"), "a.example.com");
    assert_eq!(normalize_host("  a.example.com///  "), "a.example.com");
}

#[test]
fn override_with_http_scheme_is_kept_so_local_simulator_is_reachable() {
    // 本机模拟 OpenAPI 只能是 http://127.0.0.1:<port>；scheme 被剥掉后再拼 https 就打不到
    let mut overrides = BTreeMap::new();
    overrides.insert("cms".to_string(), "http://127.0.0.1:19443".to_string());
    let ep = resolve(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &overrides);
    assert!(ep.is_ok(), "{ep:?}");
    if let Ok(ep) = ep {
        assert_eq!(ep.host, "127.0.0.1:19443");
        assert_eq!(ep.scheme, "http");
        assert!(ep.is_plaintext());
        assert_eq!(ep.url("/"), "http://127.0.0.1:19443/");
        assert_eq!(ep.url("pop/2019-01-01/events"), "http://127.0.0.1:19443/pop/2019-01-01/events");
    }
}

#[test]
fn scheme_defaults_to_https_and_only_changes_on_explicit_config() {
    // 默认行为不变：无 override、无开关 ⇒ 一律 https
    assert_eq!(default_scheme(), "https", "AGF_ALIYUN_ENDPOINT_SCHEME 未设置时必须默认 https");
    let ep = resolve(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &empty_overrides());
    assert_eq!(ep.as_ref().ok().map(|e| e.scheme), Some("https"));
    assert_eq!(ep.as_ref().ok().map(|e| e.url("/")), Some("https://metrics.cn-hangzhou.aliyuncs.com/".to_string()));
    assert!(ep.as_ref().is_ok_and(|e| !e.is_plaintext()));

    // 显式开关（或调用方显式传参）才切 http
    let http_ep =
        resolve_with_scheme(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &empty_overrides(), "http");
    assert!(http_ep.is_err(), "禁止向公网通过明文发送签名和临时凭据");

    // 覆盖值自带 https:// 时不得被降级为 http
    let mut https_override = BTreeMap::new();
    https_override.insert("cms".to_string(), "https://metrics.cn-hangzhou.aliyuncs.com".to_string());
    let forced =
        resolve_with_scheme(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &https_override, "http");
    assert_eq!(forced.ok().map(|e| e.url("/")), Some("https://metrics.cn-hangzhou.aliyuncs.com/".to_string()));
}

#[test]
fn region_validation() {
    assert!(validate_region("cn-hangzhou").is_ok());
    assert!(validate_region("ap-southeast-1").is_ok());
    assert!(validate_region("").is_err());
    assert!(validate_region(" CN-Hangzhou ").is_err());
    assert!(validate_region("cn hangzhou").is_err());
    assert!(validate_region("-cn").is_err());
    assert!(validate_region("cn-").is_err());
    assert!(validate_region("cn--hz").is_err());
    assert!(validate_region(&"a".repeat(80)).is_err());
}

#[test]
fn known_region_lookup_is_case_insensitive() {
    assert!(is_known_region("cn-hangzhou"));
    assert!(is_known_region("CN-Hangzhou"));
    assert!(!is_known_region("cn-nowhere-9"));
    assert!(KNOWN_REGIONS.len() >= 20);
}

#[test]
fn resolve_all_produces_six_entries_and_flags_public_exposure() {
    let integration = fixture_integration(CloudCredentialKind::AssumeRole, "1234567890");
    let table = resolve_all(&integration, &AliCloudService::all(), EndpointStyle::Private);
    assert!(table.is_ok());
    if let Ok(table) = table {
        assert_eq!(table.entries.len(), 6);
        assert!(table.all_private());
        assert_eq!(table.private_count(), 6);
        assert!(table.get(AliCloudService::AgentTeams).is_some());
        assert!(table.get(AliCloudService::Cms).is_some_and(|e| e.region == "cn-hangzhou"));
    }

    let public_table = resolve_all(&integration, &AliCloudService::all(), EndpointStyle::Public);
    assert!(public_table.is_ok_and(|t| !t.all_private()));
}

#[test]
fn resolve_all_rejects_bad_region() {
    let mut integration = fixture_integration(CloudCredentialKind::InstanceRole, "1");
    integration.region_id = "cn hangzhou".to_string();
    let table = resolve_all(&integration, &AliCloudService::all(), EndpointStyle::Public);
    assert!(matches!(table, Err(DomainError::Config(_))));
}

#[test]
fn service_keys_and_subdomains_are_unique() {
    let mut keys: Vec<&str> = AliCloudService::all().iter().map(|s| service_key(*s)).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 6);
    let mut subs: Vec<&str> = AliCloudService::all().iter().map(|s| service_subdomain(*s)).collect();
    subs.sort_unstable();
    subs.dedup();
    assert_eq!(subs.len(), 6);
    assert!(is_regional_endpoint(AliCloudService::Apig));
    assert!(is_regional_endpoint(AliCloudService::Cms));
}

#[test]
fn privatelink_advice_mentions_endpoint_and_whitelist() {
    let advice = privatelink_advice(AliCloudService::Mse, "cn-hangzhou");
    assert!(advice.contains("mse-vpc.cn-hangzhou.aliyuncs.com"));
    assert!(advice.contains("白名单"));
}

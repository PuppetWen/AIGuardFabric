//! 由 `http.rs` 拆分：`test_endpoint` 等 21 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn test_endpoint() -> ResolvedEndpoint {
    resolve(AliCloudService::Cms, "cn-hangzhou", EndpointStyle::Public, &BTreeMap::new()).unwrap_or_else(|_| {
        ResolvedEndpoint {
            service: AliCloudService::Cms,
            region: "cn-hangzhou".to_string(),
            host: "metrics.cn-hangzhou.aliyuncs.com".to_string(),
            scheme: "https",
            style: EndpointStyle::Public,
            origin: "public",
        }
    })
}

pub(crate) fn test_config() -> RpcClientConfig {
    RpcClientConfig {
        adapter: "alicloud-cms".to_string(),
        region: "cn-hangzhou".to_string(),
        account_id: "1234567890".to_string(),
        style: SignStyle::Rpc,
        timeout_secs: 10,
    }
}

pub(crate) fn client_with(mode: AdapterMode, transport: Arc<dyn Transport>) -> DomainResult<RpcClient> {
    RpcClient::live(
        mode,
        test_config(),
        Some(CloudCredential::long_term("LTAI5tTestAk00000000", "test-secret")),
        test_endpoint(),
        transport,
    )
}

/// **默认行为不变**：非 dev / 无显式开关时，即使配了 `ca_pem`+`insecure_tls` 也必须被忽略。
#[test]
pub(crate) fn tls_relaxation_is_ignored_outside_dev() {
    let plain = ReqwestTransport::new(5);
    assert_eq!(plain.as_ref().ok().map(|t| t.tls_policy().clone()), Some(TlsPolicy::VerifyChain));

    if tls_override_allowed() {
        // 本进程处于 dev/显式开关环境：上面"被忽略"的断言不适用（由集成测试覆盖放开分支）
        return;
    }
    let pem = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_vec();
    let ignored = ReqwestTransport::with_tls_options(5, Some(pem), true);
    assert!(ignored.is_ok(), "{ignored:?}");
    assert_eq!(
        ignored.ok().map(|t| t.tls_policy().clone()),
        Some(TlsPolicy::VerifyChain),
        "生产（非 dev）必须忽略 ca_pem / insecure_tls"
    );
}

/// 放开分支下非法 CA PEM 必须**报错**（不静默退回"看似可用"）。
#[test]
pub(crate) fn invalid_ca_pem_is_rejected_when_override_is_active() {
    if !tls_override_allowed() {
        // 非 dev：非法 PEM 根本不进入解析路径（已被忽略），见上一个用例
        return;
    }
    let err = ReqwestTransport::with_tls_options(5, Some(b"not a pem at all".to_vec()), false);
    assert!(matches!(err, Err(DomainError::Config(_))), "{err:?}");
    assert!(TlsPolicy::Insecure.is_relaxed() && TlsPolicy::CustomCa.is_relaxed());
    assert!(!TlsPolicy::VerifyChain.is_relaxed());
}

#[test]
pub(crate) fn live_refuses_mock_mode() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({})));
    let err = client_with(AdapterMode::Mocked, transport);
    assert!(matches!(err, Err(DomainError::Internal(_))), "Mock 模式必须拒绝构造真实客户端: {err:?}");
}

#[test]
pub(crate) fn live_refuses_missing_credentials() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({})));
    let err = RpcClient::live(AdapterMode::Live, test_config(), None, test_endpoint(), transport);
    assert!(matches!(err, Err(DomainError::DependencyUnavailable { .. })), "缺凭据必须明确不可用: {err:?}");
    let transport2 = Arc::new(RecordingTransport::with_body(serde_json::json!({})));
    let err2 = RpcClient::live(
        AdapterMode::Unconfigured,
        test_config(),
        Some(CloudCredential::long_term("ak", "sk")),
        test_endpoint(),
        transport2,
    );
    assert!(matches!(err2, Err(DomainError::DependencyUnavailable { .. })), "{err2:?}");
}

#[test]
pub(crate) fn build_rpc_request_signs_and_sorts_query() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({})));
    let Some(client) = client_with(AdapterMode::Live, transport).ok() else { return };
    let client = client.with_nonce("fixed-nonce");
    let request = client.build("PutCustomEvent", "2019-01-01", "GET", &[]);
    assert!(request.is_ok());
    if let Ok(request) = request {
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "https://metrics.cn-hangzhou.aliyuncs.com/");
        assert!(request.query.contains("Action=PutCustomEvent"), "{}", request.query);
        assert!(request.query.contains("Version=2019-01-01"));
        assert!(request.query.contains("AccessKeyId=LTAI5tTestAk00000000"));
        assert!(request.query.contains("SignatureNonce=fixed-nonce"));
        assert!(request.query.contains("SignatureMethod=HMAC-SHA1"));
        assert!(request.query.contains("Signature="));
        let ak_at = request.query.find("AccessKeyId=").unwrap_or(usize::MAX);
        let action_at = request.query.find("Action=").unwrap_or(0);
        assert!(ak_at < action_at, "键必须按字节序升序: {}", request.query);
        assert!(request.summary().contains("rpc-hmac-sha1"));
    }
}

#[test]
pub(crate) fn execute_records_request_and_parses_json() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({
        "RequestId": "req-1",
        "TotalCount": 3
    })));
    let Some(client) = client_with(AdapterMode::Live, transport.clone()).ok() else { return };
    let response = client.call("DescribeAlarmHistories", "2019-01-01", "GET", &[]);
    assert!(response.is_ok(), "{response:?}");
    assert_eq!(transport.call_count().ok(), Some(1), "必须且只发一次");
    if let Ok(response) = response {
        assert!(response.is_business_success());
        assert_eq!(json_i64(&response.body, "TotalCount"), Some(3));
        assert_eq!(json_str(&response.body, "RequestId").as_deref(), Some("req-1"));
    }
    // 同步通道遇真实发送口时必须被拒绝
    let real = ReqwestTransport::new(5);
    assert!(real.is_ok());
    if let Ok(real) = real {
        let bound = client_with(AdapterMode::Live, Arc::new(RecordingTransport::default()))
            .map(|bound| bound.with_async_transport(Arc::new(real)));
        assert!(bound.is_ok());
        if let Ok(bound) = bound {
            let request = bound.build("X", "1", "GET", &[]);
            assert!(request.is_ok());
            if let Ok(request) = request {
                assert!(matches!(bound.execute(&request), Err(DomainError::Internal(_))));
            }
        }
    }
}

#[test]
pub(crate) fn network_failure_maps_to_dependency_unavailable() {
    let transport = Arc::new(RecordingTransport::failing("连接被拒绝"));
    let Some(client) = client_with(AdapterMode::Live, transport).ok() else { return };
    let err = client.call("DescribeAlarmHistories", "2019-01-01", "GET", &[]);
    assert!(matches!(err, Err(DomainError::DependencyUnavailable { .. })), "{err:?}");
    if let Err(e) = err {
        assert!(e.is_degradable(), "网络失败应可降级（进离线缓存）");
    }
}

#[test]
pub(crate) fn error_code_mapping_matrix() {
    assert!(matches!(map_error_code("InvalidAccessKeyId", "ak 不存在", Some("r1")), DomainError::Forbidden(_)));
    assert!(matches!(map_error_code("SignatureDoesNotMatch", "签名不符", None), DomainError::Forbidden(_)));
    assert!(matches!(map_error_code("Throttling", "限流", None), DomainError::DependencyUnavailable { .. }));
    assert!(matches!(map_error_code("InvalidParameter", "参数错", None), DomainError::Validation(_)));
    assert!(matches!(map_error_code("QuotaExceeded", "超配额", None), DomainError::QuotaExceeded { .. }));
    assert!(map_error_code("SomethingNew", "未知", None).is_degradable());
    assert!(
        map_error_code("Forbidden", "无权限", Some("REQ-9")).to_string().contains("REQ-9"),
        "错误里必须带 RequestId 便于排障"
    );
}

#[test]
pub(crate) fn business_error_response_is_rejected() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({
        "Code": "SignatureDoesNotMatch",
        "Message": "签名错误",
        "RequestId": "req-2"
    })));
    let Some(client) = client_with(AdapterMode::Live, transport).ok() else { return };
    let err = client.call("PutCustomEvent", "2019-01-01", "GET", &[]);
    assert!(matches!(err, Err(DomainError::Forbidden(_))), "{err:?}");
}

#[test]
pub(crate) fn non_2xx_without_code_is_reported() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({ "oops": true })));
    assert!(transport.set_status(502).is_ok());
    let Some(client) = client_with(AdapterMode::Live, transport).ok() else { return };
    let err = client.call("PutCustomEvent", "2019-01-01", "GET", &[]);
    assert!(matches!(err, Err(DomainError::DependencyUnavailable { .. })), "{err:?}");
}

#[test]
pub(crate) fn json_array_supports_both_shapes() {
    let flat = serde_json::json!({ "AlarmList": [ {"a": 1}, {"a": 2} ] });
    assert_eq!(json_array(&flat, &["AlarmList"]).len(), 2);
    let nested = serde_json::json!({ "AlarmLists": { "AlarmList": [ {"a": 1} ] } });
    assert_eq!(json_array(&nested, &["AlarmList"]).len(), 1);
    let doubly = serde_json::json!({ "AlarmLists": { "AlarmLists": [ {"a": 1}, {"a": 2}, {"a": 3} ] } });
    assert_eq!(json_array(&doubly, &["AlarmList"]).len(), 3);
    assert!(json_array(&serde_json::json!({}), &["AlarmList"]).is_empty());
}

#[test]
pub(crate) fn json_array_supports_irregular_plural_alias() {
    // 阿里云真实形态：AlarmHistory → AlarmHistories（不是 AlarmHistorys）
    let nested = serde_json::json!({ "AlarmHistories": { "AlarmHistory": [ {"AlarmId": "a1"} ] } });
    let items = json_array(&nested, &["AlarmHistory", "AlarmHistories"]);
    assert_eq!(items.len(), 1, "不规则复数必须能解析: {nested}");
    let doubly = serde_json::json!({ "AlarmHistories": { "AlarmHistories": [ {"AlarmId": "a2"} ] } });
    assert_eq!(json_array(&doubly, &["AlarmHistory", "AlarmHistories"]).len(), 1);
    let flat = serde_json::json!({ "AlarmHistories": [ {"AlarmId": "a3"} ] });
    assert_eq!(json_array(&flat, &["AlarmHistory", "AlarmHistories"]).len(), 1);
    assert_eq!(plural_alias("AlarmHistory"), "AlarmHistories");
    assert_eq!(plural_alias("VpcEndpoint"), "VpcEndpoints");
    assert_eq!(plural_alias("Unknown"), "");
}

#[test]
pub(crate) fn json_i64_accepts_string_numbers() {
    let body = serde_json::json!({ "a": 3, "b": "42", "c": "x" });
    assert_eq!(json_i64(&body, "a"), Some(3));
    assert_eq!(json_i64(&body, "b"), Some(42));
    assert_eq!(json_i64(&body, "c"), None);
    assert_eq!(json_i64(&body, "missing"), None);
    assert_eq!(json_str(&body, "c").as_deref(), Some("x"));
}

#[test]
pub(crate) fn simple_xml_parsing() {
    let xml = "<DescribeResponse><RequestId>r-1</RequestId><TotalCount>3</TotalCount>\
                   <Name>分析集群</Name></DescribeResponse>";
    let json = parse_simple_xml(xml);
    assert_eq!(json.get("RequestId").and_then(serde_json::Value::as_str), Some("r-1"));
    assert_eq!(json_i64(&json, "TotalCount"), Some(3));
    assert_eq!(json.get("Name").and_then(serde_json::Value::as_str), Some("分析集群"));
    assert!(parse_simple_xml("").as_object().is_some_and(serde_json::Map::is_empty));
}

#[test]
pub(crate) fn v3_style_builds_authorization_header() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({})));
    let mut config = test_config();
    config.style = SignStyle::V3;
    let client = RpcClient::live(
        AdapterMode::Live,
        config,
        Some(CloudCredential::long_term("LTAI5tTestAk00000000", "test-secret")),
        test_endpoint(),
        transport,
    );
    assert!(client.is_ok());
    if let Ok(client) = client {
        let request = client.with_nonce("n1").build(
            "ListClusters",
            "2022-05-09",
            "POST",
            &[("RegionId".into(), "cn-hangzhou".into())],
        );
        assert!(request.is_ok());
        if let Ok(request) = request {
            assert_eq!(request.style, SignStyle::V3);
            assert!(request.headers.contains_key("Authorization"));
            assert!(request.headers.contains_key("x-acs-action"));
            assert!(request.headers.contains_key("x-acs-content-sha256"));
            assert_eq!(request.url, "https://metrics.cn-hangzhou.aliyuncs.com/");
            assert_eq!(request.query, "RegionId=cn-hangzhou");
            assert_eq!(request.headers.get("x-acs-action").map(String::as_str), Some("ListClusters"));
            assert_eq!(request.headers.get("x-acs-version").map(String::as_str), Some("2022-05-09"));
            assert_eq!(request.style.as_str(), "v3-acs3-hmac-sha256");
        }
    }
}

#[tokio::test]
pub(crate) async fn async_call_uses_sync_double_when_no_real_transport() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({ "ok": true })));
    let Some(client) = client_with(AdapterMode::Live, transport.clone()).ok() else { return };
    let response = client.call_async("PutCustomEvent", "2019-01-01", "GET", &[]).await;
    assert!(response.is_ok(), "{response:?}");
    assert_eq!(transport.call_count().ok(), Some(1));
    assert!(!client.has_async_transport());
}

#[test]
pub(crate) fn reqwest_transport_builds_and_parses_bodies() {
    let transport = ReqwestTransport::new(5);
    assert!(transport.is_ok());
    if let Ok(transport) = transport {
        assert_eq!(transport.timeout(), std::time::Duration::from_secs(5));
        let err = transport.send(&RpcRequest {
            method: "GET".to_string(),
            url: "https://example.invalid/".to_string(),
            style: SignStyle::Rpc,
            query: String::new(),
            headers: BTreeMap::new(),
            body: String::new(),
        });
        assert!(matches!(err, Err(DomainError::Internal(_))), "同步口不得用于真实网络");
    }
    let json = ReqwestTransport::parse_body(200, "{\"a\":1}");
    assert_eq!(json.body.get("a").and_then(serde_json::Value::as_i64), Some(1));
    let xml = ReqwestTransport::parse_body(200, "<R><TotalCount>2</TotalCount></R>");
    assert_eq!(json_i64(&xml.body, "TotalCount"), Some(2));
    assert!(ReqwestTransport::parse_body(204, "   ").is_business_success());
    assert!(ReqwestTransport::parse_body(200, "plain text").body.get("Raw").is_some());
}

#[test]
pub(crate) fn credential_is_masked_in_debug() {
    let transport = Arc::new(RecordingTransport::default());
    let Some(client) = client_with(AdapterMode::Live, transport).ok() else { return };
    let text = format!("{client:?}");
    assert!(!text.contains("test-secret"), "调试输出不得泄漏 secret: {text}");
}

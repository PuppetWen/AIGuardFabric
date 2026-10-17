//! 由 `vendors.rs` 拆分：**厂商目录的横切单测**（注册表、能力登记、报文校验、HMAC、等级映射）。
//!
//! 纯搬移 + 语义登记断言：这里只测"全目录级"的不变式，单厂商行为在各自模块的单测里。
use super::*;
use crate::vendor::VendorSpec;

#[test]
fn builtin_roster_is_complete_and_unique() {
    let adapters = builtin();
    assert_eq!(adapters.len(), BUILTIN_NAMES.len());
    let mut names: Vec<&str> = adapters.iter().map(|a| a.name()).collect();
    assert_eq!(names, BUILTIN_NAMES.to_vec(), "注册名顺序与常量必须一致");
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), BUILTIN_NAMES.len(), "注册名必须唯一");
}

#[test]
fn every_builtin_descriptor_is_complete() {
    for adapter in builtin() {
        let d = adapter.descriptor();
        assert!(!d.name.is_empty());
        assert!(!d.display_name.is_empty());
        assert!(!d.category.is_empty());
        assert!(!d.degradation.is_empty(), "{} 必须写明降级行为", d.name);
        assert!(!d.mock_location.is_empty(), "{} 必须写明 Mock 位置", d.name);
        assert!(d.mock_location.contains(&d.name), "{} 的 Mock 位置应指向自身模块", d.name);
        assert!(d.doc_anchor.starts_with("docs/adapter-spec.md#"), "{} 缺少文档锚点", d.name);
        // 真实实现必须**如实登记**：12 个适配器均已落地真实传输（email 走真实 SMTP 投递）
        assert!(d.real_implementation, "{} 已实现真实传输，必须如实登记", d.name);
        let meta = adapter.metadata();
        assert_eq!(meta.version, env!("CARGO_PKG_VERSION"));
        assert!(!meta.capabilities.is_empty(), "{} 能力清单不得为空", d.name);
        assert!(meta.requires_network, "{} 需要网络", d.name);
    }
}

#[test]
fn every_builtin_registers_real_transport_without_todo_anchors() {
    // 12 个适配器（含 email 的真实 SMTP 投递）均已实现真实传输：
    // 元信息必须如实登记，且 push/pull/sync 的错误文本不得是 TODO/未实现占位。
    for adapter in builtin() {
        let name = adapter.name().to_string();
        let meta = adapter.metadata();
        assert!(meta.real_transport, "{name} 应已登记真实传输");
        // 语义登记必须自洽：无"未登记"档位、无空原因、sync ⇒ pull + push
        capability_matrix::validate_semantics(&meta).unwrap_or_else(|e| panic!("{e}"));
        for semantic in crate::contract::Semantic::ALL {
            let support = meta.semantics.support(semantic);
            if let Some(reason) = support.reason() {
                assert!(!reason.trim().is_empty(), "{name}/{semantic} 的 Unsupported 原因不得为空");
                assert!(
                    !reason.contains("TODO") && !reason.contains("尚未实现"),
                    "{name}/{semantic} 必须写明「不适用」而不是「未实现」占位: {reason}"
                );
            }
        }
    }
    // 未登记语义的运行时错误必须来自能力登记（Validation + 原因），不是 NotImplemented
    for (name, error) in [
        ("email", crate::vendors::email::Email::semantic_error(crate::contract::Semantic::Pull)),
        ("feishu", crate::vendors::feishu::Feishu::semantic_error(crate::contract::Semantic::Pull)),
    ] {
        let text = error.to_string();
        assert!(matches!(error, DomainError::Validation(_)), "{name} 的 pull 应登记为 Unsupported: {text}");
        assert!(text.contains("Unsupported"), "{name} 的错误必须标注 Unsupported: {text}");
        assert!(!text.contains("TODO("), "{name} 不得再产出 TODO 锚点: {text}");
    }
    // 已实现的语义不得落到"未实现"错误上（漏覆盖编码才报缺陷）
    for (name, error) in [
        ("jira", crate::vendors::jira::Jira::semantic_error(crate::contract::Semantic::Push)),
        ("slack", crate::vendors::slack::Slack::semantic_error(crate::contract::Semantic::Push)),
    ] {
        let text = error.to_string();
        assert!(matches!(error, DomainError::Internal(_)), "{name} 的 Push 已实现，走到这里只能是缺覆盖: {text}");
        assert!(text.contains("实现缺陷"), "{text}");
    }
}

#[test]
fn custom_host_switch_bypasses_vendor_domain_check_only() {
    use crate::contract::AdapterMetadata;
    use crate::settings::AdapterSettings;
    let meta = AdapterMetadata::new("t", "T", "t", crate::contract::AdapterCategory::Notification)
        .with_secrets(&["webhook_url"], &[]);
    let mut settings = AdapterSettings::defaults(&meta);
    settings.settings.insert("allow_custom_host".into(), serde_json::json!(true));
    assert!(
        validate_vendor_webhook_with(
            &settings,
            "http://127.0.0.1:8080/open-apis/bot/v2/hook/token",
            &["feishu.cn"],
            "/open-apis/bot"
        )
        .is_ok(),
        "allow_custom_host=true 应放行自定义主机"
    );
    assert!(
        validate_vendor_webhook_with(&settings, "http://127.0.0.1:8080/wrong", &["feishu.cn"], "/open-apis/bot")
            .is_err(),
        "路径形态仍必须校验"
    );
    settings.settings.insert("allow_custom_host".into(), serde_json::json!(false));
    assert!(
        validate_vendor_webhook_with(
            &settings,
            "http://127.0.0.1:8080/open-apis/bot/v2/hook/token",
            &["feishu.cn"],
            "/open-apis/bot"
        )
        .is_err(),
        "未开开关时不得放行非厂商域名"
    );
}

#[test]
fn business_code_response_matrix() {
    assert!(ensure_business_ok("feishu", 200, r#"{"code":0,"msg":"success"}"#, &["code"], &["msg"]).is_ok());
    assert!(
        ensure_business_ok(
            "feishu",
            200,
            r#"{"StatusCode":0,"StatusMessage":"success"}"#,
            &["StatusCode"],
            &["StatusMessage"]
        )
        .is_ok()
    );
    let error = ensure_business_ok(
        "dingtalk",
        200,
        r#"{"errcode":310000,"errmsg":"sign not match"}"#,
        &["errcode"],
        &["errmsg"],
    )
    .expect_err("业务错误码必须报错");
    assert!(matches!(error, DomainError::Validation(_)));
    assert!(error.to_string().contains("310000"), "{error}");
    assert!(error.to_string().contains("sign not match"), "{error}");
    assert!(!error.is_degradable(), "业务错误码不得重试");
    assert!(ensure_business_ok("wecom", 200, "not-json", &["errcode"], &["errmsg"]).is_err());
    assert!(
        ensure_business_ok("wecom", 200, r#"{"msg":"ok"}"#, &["errcode"], &["errmsg"]).is_err(),
        "缺业务码字段不得视为成功"
    );
}

#[test]
fn hmac_signature_is_deterministic_and_key_dependent() {
    let a = hmac_sha256_b64("secret-a", "1700000000\nsecret-a");
    let b = hmac_sha256_b64("secret-a", "1700000000\nsecret-a");
    let c = hmac_sha256_b64("secret-b", "1700000000\nsecret-b");
    assert!(a.is_some());
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(hmac_sha256_b64("", "x").is_none(), "空密钥不得产生签名");
}

#[test]
fn vendor_webhook_validation_matrix() {
    assert!(
        validate_vendor_webhook("https://open.feishu.cn/open-apis/bot/v2/hook/abc", &["feishu.cn"], "/open-apis/bot")
            .is_ok()
    );
    assert!(
        validate_vendor_webhook(
            "https://evil.example.invalid/open-apis/bot/v2/hook/abc",
            &["feishu.cn"],
            "/open-apis/bot"
        )
        .is_err()
    );
    assert!(validate_vendor_webhook("https://open.feishu.cn/wrong/path", &["feishu.cn"], "/open-apis/bot").is_err());
    assert!(validate_vendor_webhook("not-a-url", &["feishu.cn"], "/open-apis/bot").is_err());
    // 子域名匹配同样接受
    assert!(validate_vendor_webhook("https://sub.feishu.cn/open-apis/bot/x", &["feishu.cn"], "/open-apis/bot").is_ok());
    // 后缀伪装不接受
    assert!(validate_vendor_webhook("https://notfeishu.cn/open-apis/bot/x", &["feishu.cn"], "/open-apis/bot").is_err());
}

#[test]
fn severity_helpers_cover_every_level() {
    for (severity, color, marker) in [
        (Severity::Critical, "red", "🔴"),
        (Severity::High, "orange", "🟠"),
        (Severity::Medium, "yellow", "🟡"),
        (Severity::Low, "blue", "🔵"),
        (Severity::Info, "blue", "⚪"),
    ] {
        assert_eq!(severity_color(severity), color);
        assert_eq!(severity_marker(severity), marker);
    }
}

#[test]
fn require_setting_and_secret_report_missing_keys() {
    let settings = crate::settings::AdapterSettings::defaults(&crate::contract::AdapterMetadata::new(
        "x",
        "X",
        "t",
        crate::contract::AdapterCategory::Itsm,
    ));
    let err = require_setting(&settings, "base_url");
    assert!(err.is_err());
    assert!(require_secret(&settings, "api_token").is_err());
    assert!(optional_secret(&settings, "api_token").is_none());
}

#[test]
fn push_helpers_reject_empty_target_and_unsupported_entity() {
    let payload = crate::contract::PushPayload {
        entity: "ticket.status".to_string(),
        entity_id: "  ".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    let error = require_remote_id("jira", &payload).expect_err("空 entity_id 必须拒绝");
    assert!(error.to_string().contains("remote_id"), "{error}");
    assert!(require_entity("jira", &payload, &["ticket.status"]).is_ok());
    assert!(require_entity("jira", &payload, &["message.update"]).is_err());
    assert!(require_safe_id("jira", "SEC-7", "issue key").is_ok());
    assert!(require_safe_id("jira", "../../etc/passwd", "issue key").is_err(), "路径注入必须拒绝");
    assert!(body_str(&serde_json::json!({"comment": "  "}), "comment").is_none());
    // 幂等键的确定性：显式键优先，缺省由实体 + id + 载荷派生
    let explicit = crate::contract::PushPayload { idempotency_key: Some("k1".into()), ..payload.clone() };
    assert_eq!(push_idempotency_key("jira", &explicit), "k1");
    let derived = crate::contract::PushPayload { entity_id: "SEC-7".into(), ..payload.clone() };
    assert_eq!(push_idempotency_key("jira", &derived), push_idempotency_key("jira", &derived));
    assert_ne!(push_idempotency_key("jira", &derived), push_idempotency_key("zentao", &derived));
}

#[test]
fn query_and_limit_helpers_are_deterministic_and_bounded() {
    use agf_core::adapter::PullRequest;
    let url = with_query(
        "https://jira.example.invalid/rest/api/2/search",
        &[("jql", "project = \"SEC\"".to_string()), ("maxResults", "50".to_string())],
    )
    .expect("合法 URL");
    assert!(url.starts_with("https://jira.example.invalid/rest/api/2/search?jql=project"), "{url}");
    assert!(url.contains("maxResults=50"));
    assert!(with_query("not a url", &[]).is_err());

    let request = PullRequest { resource: "BUGS".to_string(), limit: Some(9999), ..PullRequest::default() };
    assert_eq!(pull_resource("zentao", &request, &["bugs", "bug"], "bugs").ok(), Some("bugs"), "资源名归一为小写");
    assert!(pull_resource("zentao", &request, &["hosts"], "hosts").is_err(), "白名单外必须拒绝");
    assert_eq!(pull_limit(&request, 50, 200), 200, "上限必须钳制");
    let unlimited = PullRequest { resource: "bugs".to_string(), limit: Some(0), ..PullRequest::default() };
    assert_eq!(pull_limit(&unlimited, 50, 200), 1, "下限必须钳制（0 ⇒ 1）");
    let default = PullRequest { resource: String::new(), ..PullRequest::default() };
    assert_eq!(pull_resource("zentao", &default, &["bugs"], "bugs").ok(), Some("bugs"), "空资源名 ⇒ 默认");
    assert_eq!(pull_limit(&default, 50, 200), 50);
}

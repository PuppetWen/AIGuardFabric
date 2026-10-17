//! SAML and cross-device sign-in operations in the published API contract.
use super::EndpointSpec;
use utoipa::openapi::path::HttpMethod::{Get, Post, Put};

pub(super) fn endpoint_specs() -> Vec<EndpointSpec> {
    let mut specs = Vec::new();
    let mut push =
        |path, method, id, summary, tag| specs.push(EndpointSpec { path, method, id, summary, tag, implemented: true });
    push("/api/v1/settings/identity/saml", Get, "getSamlSettings", "读取当前租户 SAML 配置（不返回私钥）", "settings");
    push("/api/v1/settings/identity/saml", Put, "saveSamlSettings", "按版本保存 SAML 配置与 SP 签名证书", "settings");
    push("/api/v1/auth/saml/{tenant_slug}/metadata", Get, "samlSpMetadata", "公开 SP 元数据与证书", "auth");
    push("/api/v1/auth/saml/start", Post, "startSaml", "创建浏览器绑定的 SAML 登录事务", "auth");
    push("/api/v1/auth/saml/{tenant_slug}/acs", Post, "samlAcs", "验证 IdP 签名响应和一次性回调", "auth");
    push("/api/v1/auth/saml/status", Post, "samlStatus", "查询浏览器绑定的 SAML 登录状态", "auth");
    push("/api/v1/auth/saml/complete", Post, "completeSaml", "完成平台 MFA 并签发会话", "auth");
    push("/api/v1/auth/qr/start", Post, "startQr", "创建三分钟跨设备扫码请求", "auth");
    push("/api/v1/auth/qr/status", Post, "qrStatus", "查询浏览器绑定的扫码批准状态", "auth");
    push("/api/v1/auth/qr/complete", Post, "completeQr", "单次领取经手机 MFA 批准的新会话", "auth");
    push("/api/v1/auth/qr/{tenant_slug}/{state}/preview", Get, "previewQr", "手机预览扫码请求", "auth");
    push(
        "/api/v1/auth/qr/{tenant_slug}/{state}/approve",
        Post,
        "approveQr",
        "同租户手机用平台 MFA 批准扫码登录",
        "auth",
    );
    specs
}

//! 厂商适配器目录：**一厂商一模块**；语义实现按"语义面"另拆四个模块（见下）。
//!
//! | 分类 | 模块 | 注册名 | 通道 | `send` 真实传输 | `push`/`pull`/`sync` |
//! |---|---|---|---|---|---|
//! | 通知 | [`feishu`] | `feishu` | 飞书/Lark 机器人 Webhook | ✅ HTTP POST | ⛔ Unsupported（见能力矩阵的原因） |
//! | 通知 | [`dingtalk`] | `dingtalk` | 钉钉机器人 Webhook（含加签） | ✅ HTTP POST | ⛔ Unsupported |
//! | 通知 | [`wecom`] | `wecom` | 企业微信机器人 Webhook | ✅ HTTP POST | ⛔ Unsupported |
//! | 通知 | [`email`] | `email` | SMTP（RFC 5322 报文 + STARTTLS/SMTPS/AUTH） | ✅ SMTP 投递 | ⛔ Unsupported |
//! | 通知 | [`webhook`] | `webhook` | 通用 Webhook（幂等键 + 自定义头） | ✅ HTTP POST | ⛔ Unsupported |
//! | 通知 | [`slack`] | `slack` | Slack Incoming Webhook + Web API | ✅ HTTP POST | `push` ✅（`chat.update`/`chat.delete`）；`pull`/`sync` ⛔ |
//! | 工单 | [`jira`] | `jira` | Jira REST v2 issue | ✅ HTTP POST | ✅ `push`/`pull`/`sync` |
//! | 工单 | [`servicenow`] | `servicenow` | ServiceNow Table API incident | ✅ HTTP POST | ✅ `push`/`pull`/`sync` |
//! | 工单 | [`zentao`] | `zentao` | 禅道 REST v1 bug | ✅ HTTP POST | ✅ `push`/`pull`/`sync` |
//! | 安全平台 | [`syslog`] | `syslog-forwarder` | RFC 5424 转发（TCP/UDP） | ✅ UDP/TCP 发包 | ⛔ Unsupported |
//! | 安全平台 | [`edr`] | `edr-isolation` | EDR 主机隔离指令下发 | ✅ HTTP POST | ✅ `push`/`pull`/`sync` |
//! | 安全平台 | [`iam`] | `iam-scim` | SCIM 用户停用 | ✅ HTTP PATCH | ⛔ Unsupported（身份动作仅经审批案件） |
//!
//! 每个模块的 `VendorSpec` 实现中，**编码与响应解析都是纯函数**（不做网络、可离线断言）；
//! 真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一经 [`crate::http::execute`]（HTTP）
//! 或厂商覆写的 `invoke_live`（Syslog UDP/TCP、`email` 的真实 SMTP 会话）完成。
//!
//! ## 语义实现的文件布局（避免单文件膨胀，且按"语义面"聚合）
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`itsm_push`] | 工单类状态/评论回写编码（Jira 双请求序列、ServiceNow PATCH、禅道 PUT） |
//! | [`itsm_pull`] | 工单类增量拉取编码与解析（JQL `updated >=`、`sysparm_query`、客户端 `since`） |
//! | [`device_semantics`] | EDR 隔离状态回写 + 主机/事件增量拉取 |
//! | [`notify_semantics`] | Slack 消息更新/撤回（`chat.update`/`chat.delete`） |
//! | [`capability_matrix`] | 12 × 4 的能力矩阵（文档/控制台的真源，含测试证据核对） |
//!
//! ## 未配置时的降级行为（全目录）
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置（缺凭据/必需设置） | 不下发；`send()` 返回 `Config` 错误并列出缺项，**不建连不发包**；`push`/`pull`/`sync` 同 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 全部 12 个适配器返回确定性 Mock 回执，**零网络**；已登记语义返回确定性降级结果 |
//! | 配置齐全且已实现真实传输 | 真实 HTTP/UDP/TCP/SMTP 往返；上游失败按 `RetryConfig` 重试（仅 5xx/超时/SMTP 4xx 可重试，SMTP 认证失败不重试），连续失败由熔断器开路 |
//! | 该语义未登记（`Unsupported`） | `Validation` + **不适用原因**（不可重试）；**不是** `NotImplemented` 占位 |

pub mod dingtalk;
pub mod edr;
pub mod email;
pub mod feishu;
pub mod iam;
pub mod jira;
pub mod servicenow;
pub mod slack;
pub mod syslog;
pub mod webhook;
pub mod wecom;
pub mod zentao;

pub mod capability_matrix;
pub mod device_semantics;
pub mod itsm_pull;
pub mod itsm_push;
pub mod notify_semantics;

use agf_core::adapter::AdapterCapability;
use agf_core::adapter::PushPayload;
use agf_core::enums::Severity;
use agf_core::error::{DomainError, DomainResult};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::contract::VendorAdapter;

/// 全部内置适配器的注册名（固定顺序，控制台列表按此渲染）。
pub const BUILTIN_NAMES: [&str; 12] = [
    "feishu",
    "dingtalk",
    "wecom",
    "email",
    "webhook",
    "slack",
    "jira",
    "servicenow",
    "zentao",
    "syslog-forwarder",
    "edr-isolation",
    "iam-scim",
];

/// 构造全部内置适配器实例（未配置形态；供 [`crate::registry::AdapterRegistry`] 批量注册）。
#[must_use]
pub fn builtin() -> Vec<Box<dyn VendorAdapter>> {
    vec![
        Box::new(crate::vendor::VendorAdapterImpl::<feishu::Feishu>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<dingtalk::DingTalk>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<wecom::WeCom>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<email::Email>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<webhook::Webhook>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<slack::Slack>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<jira::Jira>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<servicenow::ServiceNow>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<zentao::Zentao>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<syslog::SyslogForwarder>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<edr::EdrIsolation>::new()),
        Box::new(crate::vendor::VendorAdapterImpl::<iam::ScimIdentity>::new()),
    ]
}

/// 通知渠道的公共能力集。
#[must_use]
pub fn notify_capabilities() -> Vec<AdapterCapability> {
    vec![AdapterCapability::PushEvents, AdapterCapability::SelfCheck]
}

/// 工单渠道的公共能力集（`push`/`pull` 已实现 ⇒ 追加 `PushConfig` + `PullInventory`）。
#[must_use]
pub fn itsm_capabilities() -> Vec<AdapterCapability> {
    vec![
        AdapterCapability::PushEvents,
        AdapterCapability::PushConfig,
        AdapterCapability::PullInventory,
        AdapterCapability::QueryLogs,
        AdapterCapability::SelfCheck,
    ]
}

// ---------------------------------------------------------------------------
// 语义不适用（Unsupported）的原因文本 —— 按**通道能力**分档，逐条给出客观依据
// ---------------------------------------------------------------------------

/// 群机器人 Webhook 的 `push` 不适用原因。
pub const NOTIFY_PUSH_UNSUPPORTED: &str = "群机器人 Webhook 只有「投递」权限，没有消息更新/撤回接口（飞书更新消息需 tenant_access_token、\
     钉钉撤回需企业内部应用 access_token + robotCode、企业微信撤回需应用 secret），本适配器未配置该类通道";

/// 通知渠道的 `pull` 不适用原因。
pub const NOTIFY_PULL_UNSUPPORTED: &str = "通知渠道是单向投递（Webhook 无读取接口），没有「拉取外部状态」的语义";

/// 通知渠道的 `sync` 不适用原因。
pub const NOTIFY_SYNC_UNSUPPORTED: &str = "对账需要读回外部状态，通知渠道无读取语义，因此双向对账不适用";

/// 通用 Webhook 的 `push` 不适用原因。
pub const WEBHOOK_PUSH_UNSUPPORTED: &str = "通用 Webhook 的接收方协议由使用方自定义，平台无法假设其存在「按对象 id 回写」的接口；\
     需要回写的目标请新增专用适配器（如 jira/servicenow/edr）";

/// SMTP 邮件的 `push` 不适用原因。
pub const EMAIL_PUSH_UNSUPPORTED: &str =
    "SMTP 是投递协议，没有「更新/撤回已投递邮件」的语义（重发 = 再调用一次 send，不属于状态回写）";

/// SMTP 邮件的 `pull`/`sync` 不适用原因。
pub const EMAIL_READ_UNSUPPORTED: &str = "SMTP 只有投递方向（收取需 IMAP/POP3，本适配器未配置该类通道），无读取语义";

/// Syslog 转发的 `push` 不适用原因。
pub const SYSLOG_PUSH_UNSUPPORTED: &str =
    "RFC 5424 转发是 fire-and-forget 单向日志投递，报文一旦发出不可更新/撤回，没有状态回写语义";

/// Syslog 转发的 `pull`/`sync` 不适用原因。
pub const SYSLOG_READ_UNSUPPORTED: &str = "Syslog 是单向日志转发（无读取/查询接口），无法拉取外部状态进行对账";

/// 通知类「消息更新」实现方的 `pull` 不适用原因（Slack Web API）。
pub const MESSAGE_API_PULL_UNSUPPORTED: &str =
    "Slack Web API 可更新消息但本适配器只做消息维度回写；拉取频道历史属于 conversation.* 域，不在对账语义内";

/// 通知类「消息更新」实现方的 `sync` 不适用原因。
pub const MESSAGE_API_SYNC_UNSUPPORTED: &str = "消息更新是单向回写，无对账所需的外部读取语义，双向对账不适用";

/// 校验回写实体名（不支持的实体名一律 `Validation`，避免把载荷发成错误的语义）。
///
/// # Errors
/// 实体名不在 `allowed` 内时返回 `DomainError::Validation`（列出支持项）。
pub fn require_entity<'a>(vendor: &str, payload: &PushPayload, allowed: &[&'a str]) -> DomainResult<&'a str> {
    let entity = payload.entity.trim();
    allowed.iter().find(|candidate| **candidate == entity).copied().ok_or_else(|| {
        DomainError::Validation(format!("{vendor} 不支持回写实体 {:?}（支持：{allowed:?}）", payload.entity))
    })
}

/// 校验回写的目标远端 id（回写必须指向**已存在**的对象）。
///
/// # Errors
/// `entity_id` 为空时返回 `DomainError::Validation`（提示用 `send` 回执的 `remote_id`）。
pub fn require_remote_id(vendor: &str, payload: &PushPayload) -> DomainResult<String> {
    let id = payload.entity_id.trim();
    if id.is_empty() {
        return Err(DomainError::Validation(format!(
            "{vendor}：回写缺少远端对象 id（payload.entity_id）——请用 send 回执里的 remote_id 作为 entity_id"
        )));
    }
    Ok(id.to_string())
}

/// 校验可安全拼进 URL 路径的远端 id（字母数字与 `-_.`），避免路径注入。
///
/// # Errors
/// id 含路径分隔符或其他非白名单字符时返回 `DomainError::Validation`。
pub fn require_safe_id(vendor: &str, id: &str, what: &str) -> DomainResult<String> {
    if id.is_empty()
        || matches!(id, "." | "..")
        || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(DomainError::Validation(format!("{vendor}：{what} 含非法字符（只允许字母数字与 -_.）: {id:?}")));
    }
    Ok(id.to_string())
}

/// 读取回写体里的字符串字段（空白视为未提供）。
#[must_use]
pub fn body_str(body: &serde_json::Value, key: &str) -> Option<String> {
    body.get(key).and_then(serde_json::Value::as_str).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string)
}

/// 回写幂等键（显式提供优先；缺省由 `实体 + 远端 id + 载荷体` 确定性派生）。
#[must_use]
pub fn push_idempotency_key(vendor: &str, payload: &PushPayload) -> String {
    payload.idempotency_key.clone().unwrap_or_else(|| {
        crate::transport::deterministic_token(
            "agf-push",
            &format!("{vendor}|{}|{}|{}", payload.entity, payload.entity_id, payload.body),
        )
    })
}

/// 归一化拉取资源名并与白名单比对（空 ⇒ 厂商默认资源）。
///
/// # Errors
/// 资源名不在白名单内时返回 `DomainError::Validation`（列出支持项，不重试）。
pub fn pull_resource<'a>(
    vendor: &str,
    req: &agf_core::adapter::PullRequest,
    allowed: &[&'a str],
    default: &'a str,
) -> DomainResult<&'a str> {
    let raw = req.resource.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Ok(default);
    }
    allowed
        .iter()
        .find(|candidate| **candidate == raw)
        .copied()
        .ok_or_else(|| DomainError::Validation(format!("{vendor} 不支持拉取资源 {raw:?}（支持：{allowed:?}）")))
}

/// 单页上限（缺省 `default`，并对上限做钳制，避免上游拒绝或一次拉爆内存）。
#[must_use]
pub fn pull_limit(req: &agf_core::adapter::PullRequest, default: u32, max: u32) -> u32 {
    req.limit.unwrap_or(default).clamp(1, max)
}

/// 给 URL 追加查询串（正确百分号编码；键顺序稳定，便于断言的确定性）。
///
/// # Errors
/// URL 非法时返回 `DomainError::Config`。
pub fn with_query(url: &str, pairs: &[(&str, String)]) -> DomainResult<String> {
    let mut parsed = url::Url::parse(url).map_err(|e| DomainError::Config(format!("endpoint 非法（{url}）: {e}")))?;
    {
        let mut query = parsed.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Ok(parsed.to_string())
}

/// 严重等级 → 飞书卡片/钉钉卡片颜色模板。
#[must_use]
pub const fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "red",
        Severity::High => "orange",
        Severity::Medium => "yellow",
        Severity::Low | Severity::Info => "blue",
    }
}

/// 严重等级 → 文本标记（纯文本渠道用）。
#[must_use]
pub const fn severity_marker(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

/// 计算 HMAC-SHA256 并以 base64 输出（飞书/钉钉加签共用）。
///
/// 密钥为空时返回 `None`（不产生签名，调用方据此决定是否加签字段）。
#[must_use]
pub fn hmac_sha256_b64(key: &str, data: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
    mac.update(data.as_bytes());
    Some(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

/// 校验 Webhook URL：scheme/host + 厂商域名后缀 + 路径标记。
///
/// # Errors
/// URL 非法、域名不属于该厂商、路径不符合 Webhook 形态时返回 `DomainError::Config`。
pub fn validate_vendor_webhook(url: &str, host_suffixes: &[&str], path_marker: &str) -> DomainResult<()> {
    crate::settings::validate_endpoint(url)?;
    let parsed = url::Url::parse(url).map_err(|e| DomainError::Config(format!("Webhook URL 非法: {e}")))?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if !host_suffixes.iter().any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}"))) {
        return Err(DomainError::Config(format!(
            "Webhook 域名不属于该厂商（host={host}，允许后缀 {host_suffixes:?}）；\
             私有化部署/反向代理网关请显式设置 allow_custom_host=true"
        )));
    }
    if !parsed.path().starts_with(path_marker) {
        return Err(DomainError::Config(format!(
            "Webhook 路径形态非法（path={}，应以 {path_marker} 开头）",
            parsed.path()
        )));
    }
    Ok(())
}

/// 带"允许自定义主机"开关的 Webhook 校验（私有化部署 / 反向代理网关场景）。
///
/// `allow_custom_host=true` 时**跳过厂商域名后缀校验**，但仍强制校验
/// endpoint 合法性（scheme 白名单 + 必须有 host）与路径形态——
/// 即"可以选择主机，但不能把请求发成非 Webhook 形态"。
///
/// # Errors
/// URL 非法或路径形态不符时返回 `DomainError::Config`。
pub fn validate_vendor_webhook_with(
    settings: &crate::settings::AdapterSettings,
    url: &str,
    host_suffixes: &[&str],
    path_marker: &str,
) -> DomainResult<()> {
    if !settings.get_bool("allow_custom_host", false) {
        return validate_vendor_webhook(url, host_suffixes, path_marker);
    }
    crate::settings::validate_endpoint(url)?;
    let parsed = url::Url::parse(url).map_err(|e| DomainError::Config(format!("Webhook URL 非法: {e}")))?;
    if !parsed.path().starts_with(path_marker) {
        return Err(DomainError::Config(format!(
            "Webhook 路径形态非法（path={}，应以 {path_marker} 开头）",
            parsed.path()
        )));
    }
    Ok(())
}

/// 校验"HTTP 200 + 业务码"型响应（飞书 `code` / 钉钉与企业微信 `errcode`）。
///
/// 这类厂商把业务结果放在响应体而非状态码里：HTTP 200 也可能是签名失败。
/// 因此**必须解析业务码**，不能只看状态码（"不假装成功"）。
///
/// # Errors
/// 业务码非 0、响应体非 JSON 或缺少业务码字段时返回 `DomainError::Validation`（不重试）。
pub fn ensure_business_ok(
    vendor: &str,
    status: u16,
    body: &str,
    code_keys: &[&str],
    message_keys: &[&str],
) -> DomainResult<()> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Err(DomainError::Validation(format!(
            "{vendor} 上游返回 HTTP {status} 但响应体不是合法 JSON: {}",
            crate::http::snippet(body)
        )));
    };
    let code = code_keys.iter().find_map(|key| value.get(*key).and_then(serde_json::Value::as_i64));
    match code {
        Some(0) => Ok(()),
        Some(other) => {
            let message =
                message_keys.iter().find_map(|key| value.get(*key).and_then(serde_json::Value::as_str)).unwrap_or("");
            Err(DomainError::Validation(format!("{vendor} 上游返回业务错误码 {other}: {message}")))
        }
        None => Err(DomainError::Validation(format!(
            "{vendor} 上游响应缺少业务码字段 {:?}: {}",
            code_keys,
            crate::http::snippet(body)
        ))),
    }
}

/// 读取厂商必需字符串设置（缺失/空白即配置错误）。
///
/// # Errors
/// 设置缺失或为空白时返回 `DomainError::Config`。
pub fn require_setting(settings: &crate::settings::AdapterSettings, key: &str) -> DomainResult<String> {
    match settings.get_str(key).map(str::trim) {
        Some(v) if !v.is_empty() => Ok(v.to_string()),
        _ => Err(DomainError::Config(format!("适配器 {} 缺少必需设置 {key}", settings.adapter))),
    }
}

/// 读取厂商必需凭据（缺失即配置错误；返回值仅用于构造请求）。
///
/// # Errors
/// 凭据缺失时返回 `DomainError::Config`（错误信息只含键名）。
pub fn require_secret(settings: &crate::settings::AdapterSettings, key: &str) -> DomainResult<String> {
    settings
        .secret_raw(key)
        .filter(|v| !v.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| DomainError::Config(format!("适配器 {} 缺少凭据 {key}", settings.adapter)))
}

/// 读取可选的厂商凭据。
#[must_use]
pub fn optional_secret(settings: &crate::settings::AdapterSettings, key: &str) -> Option<String> {
    settings.secret_raw(key).filter(|v| !v.trim().is_empty()).map(ToString::to_string)
}

#[cfg(test)]
mod tests;

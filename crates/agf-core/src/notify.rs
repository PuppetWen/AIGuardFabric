//! 通知渠道与投递模型（§4.6 升级路由：钉钉/飞书/企业微信/邮件/短信/Webhook/PagerDuty）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 通知渠道类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelKind {
    /// 钉钉机器人。
    #[serde(rename = "dingtalk", alias = "ding-talk")]
    DingTalk,
    /// 飞书机器人。
    Feishu,
    /// 企业微信机器人。
    #[serde(rename = "wecom", alias = "we-com")]
    WeCom,
    /// 邮件（SMTP）。
    Email,
    /// 短信。
    Sms,
    /// 通用 Webhook。
    Webhook,
    /// PagerDuty。
    #[serde(rename = "pagerduty", alias = "pager-duty")]
    PagerDuty,
    /// Slack。
    Slack,
    /// 站内消息（控制台）。
    InApp,
}

impl ChannelKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DingTalk => "dingtalk",
            Self::Feishu => "feishu",
            Self::WeCom => "wecom",
            Self::Email => "email",
            Self::Sms => "sms",
            Self::Webhook => "webhook",
            Self::PagerDuty => "pagerduty",
            Self::Slack => "slack",
            Self::InApp => "in-app",
        }
    }

    /// 全部渠道。
    #[must_use]
    pub const fn all() -> [Self; 9] {
        [
            Self::DingTalk,
            Self::Feishu,
            Self::WeCom,
            Self::Email,
            Self::Sms,
            Self::Webhook,
            Self::PagerDuty,
            Self::Slack,
            Self::InApp,
        ]
    }

    /// 是否使用 Webhook URL 形式（决定配置字段）。
    #[must_use]
    pub const fn uses_webhook_url(&self) -> bool {
        matches!(self, Self::DingTalk | Self::Feishu | Self::WeCom | Self::Webhook | Self::Slack)
    }
}

/// 通知渠道配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 是否启用。
    pub enabled: bool,
    /// Webhook URL 引用（**密文存 `credentials`**，此处只存引用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<Id>,
    /// 非敏感的收件目标（邮箱地址、手机号掩码、频道名）。
    #[serde(default)]
    pub targets: Vec<String>,
    /// 适用的最低等级。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<crate::enums::Severity>,
    /// 附加静态请求头。
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// 消息模板（Markdown/文本，支持 `{{title}}`、`{{severity}}` 等占位符）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// 静默期（秒）：同渠道同键在静默期内不重复发送。
    #[serde(default = "default_silence")]
    pub silence_secs: i64,
    /// 发送重试次数。
    #[serde(default = "default_retries")]
    pub max_retries: u32,
    /// 最近一次发送时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sent_at: Option<Timestamp>,
    /// 最近一次错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
}

const fn default_silence() -> i64 {
    300
}

const fn default_retries() -> u32 {
    3
}

impl TenantScoped for NotificationChannel {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl NotificationChannel {
    /// 是否应发送该等级的通知。
    #[must_use]
    pub fn accepts_severity(&self, severity: crate::enums::Severity) -> bool {
        self.enabled && self.min_severity.is_none_or(|min| severity.weight() >= min.weight())
    }

    /// 静默期是否已过。
    #[must_use]
    pub fn silence_expired(&self, now: Timestamp) -> bool {
        self.last_sent_at.is_none_or(|t| now.since_secs(&t) >= self.silence_secs)
    }
}

/// 通知投递记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 渠道 id。
    pub channel_id: Id,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 关联对象类型（`alert` / `case` / `report`）。
    pub subject_kind: String,
    /// 关联对象 id。
    pub subject_id: Id,
    /// 去重键。
    pub dedup_key: String,
    /// 标题。
    pub title: String,
    /// 正文（已渲染）。
    pub body: String,
    /// 投递状态。
    pub state: DeliveryState,
    /// 尝试次数。
    pub attempts: u32,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 投递完成时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<Timestamp>,
}

impl TenantScoped for NotificationRecord {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

/// 投递状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryState {
    /// 待发送。
    Pending,
    /// 已发送。
    Sent,
    /// 已投递成功。
    Delivered,
    /// 失败。
    Failed,
    /// 已抑制（静默期/聚合）。
    Suppressed,
}

impl DeliveryState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Suppressed => "suppressed",
        }
    }

    /// 是否为终态。
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Delivered | Self::Failed | Self::Suppressed)
    }
}

/// 通知模板渲染上下文。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyContext {
    /// 标题。
    pub title: String,
    /// 等级。
    pub severity: String,
    /// 域。
    pub domain: String,
    /// 资产。
    pub asset: String,
    /// 摘要。
    pub summary: String,
    /// 控制台深链。
    pub console_url: String,
    /// 发生时间。
    pub at: String,
    /// 附加键值。
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

impl NotifyContext {
    /// 用上下文替换模板中的 `{{key}}` 占位符。
    ///
    /// 未知占位符保留原样（便于发现模板写错），不做转义（渠道侧各自处理）。
    #[must_use]
    pub fn render(&self, template: &str) -> String {
        let mut out = template.to_string();
        let pairs: Vec<(&str, &str)> = vec![
            ("title", self.title.as_str()),
            ("severity", self.severity.as_str()),
            ("domain", self.domain.as_str()),
            ("asset", self.asset.as_str()),
            ("summary", self.summary.as_str()),
            ("console_url", self.console_url.as_str()),
            ("at", self.at.as_str()),
        ];
        for (k, v) in pairs {
            out = out.replace(&format!("{{{{{k}}}}}"), v);
        }
        for (k, v) in &self.extra {
            out = out.replace(&format!("{{{{{k}}}}}"), v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::Severity;

    fn channel(kind: ChannelKind, min: Option<Severity>) -> NotificationChannel {
        NotificationChannel {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "c".into(),
            kind,
            enabled: true,
            secret_ref: None,
            targets: vec![],
            min_severity: min,
            headers: BTreeMap::new(),
            template: None,
            silence_secs: 300,
            max_retries: 3,
            last_sent_at: None,
            last_error: None,
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn channel_kind_matrix() {
        assert_eq!(ChannelKind::all().len(), 9);
        assert!(ChannelKind::DingTalk.uses_webhook_url());
        assert!(ChannelKind::Webhook.uses_webhook_url());
        assert!(!ChannelKind::Email.uses_webhook_url());
        assert!(!ChannelKind::InApp.uses_webhook_url());
        assert_eq!(ChannelKind::InApp.as_str(), "in-app");
    }

    #[test]
    fn severity_gating() {
        let c = channel(ChannelKind::DingTalk, Some(Severity::High));
        assert!(c.accepts_severity(Severity::High));
        assert!(c.accepts_severity(Severity::Critical));
        assert!(!c.accepts_severity(Severity::Medium));
        let open = channel(ChannelKind::DingTalk, None);
        assert!(open.accepts_severity(Severity::Info));
        let mut disabled = channel(ChannelKind::DingTalk, None);
        disabled.enabled = false;
        assert!(!disabled.accepts_severity(Severity::Critical));
    }

    #[test]
    fn silence_window() {
        let now = Timestamp::now();
        let mut c = channel(ChannelKind::DingTalk, None);
        assert!(c.silence_expired(now), "从未发送过即可发送");
        c.last_sent_at = Some(now.offset_secs(-100));
        assert!(!c.silence_expired(now));
        c.last_sent_at = Some(now.offset_secs(-400));
        assert!(c.silence_expired(now));
    }

    #[test]
    fn template_rendering() {
        let ctx = NotifyContext {
            title: "提示词注入".into(),
            severity: "high".into(),
            domain: "prompt-attack".into(),
            asset: "claude-code@host1".into(),
            summary: "命中 PA-INJ-001".into(),
            console_url: "http://127.0.0.1:8081/alerts/1".into(),
            at: "2026-03-01T10:00:00Z".into(),
            extra: BTreeMap::from([("rule".to_string(), "PA-INJ-001".to_string())]),
        };
        let rendered =
            ctx.render("【{{severity}}】{{title}} @ {{asset}} 规则={{rule}} 链接={{console_url}} 未知名={{unknown}}");
        assert!(rendered.contains("【high】提示词注入"));
        assert!(rendered.contains("规则=PA-INJ-001"));
        assert!(rendered.contains("{{unknown}}"), "未知占位符保留原样");
        assert!(!rendered.contains("{{title}}"));
    }

    #[test]
    fn delivery_state_terminal() {
        assert!(DeliveryState::Delivered.is_terminal());
        assert!(DeliveryState::Failed.is_terminal());
        assert!(DeliveryState::Suppressed.is_terminal());
        assert!(!DeliveryState::Pending.is_terminal());
        assert_eq!(DeliveryState::Suppressed.as_str(), "suppressed");
    }
}

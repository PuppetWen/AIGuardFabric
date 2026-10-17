//! 由 `contract.rs` 拆分：`AdapterCategory`/`AdapterMessage`/`AdapterMetadata`/`MessageKind` 的实现（纯搬移，逻辑不变）。
use super::*;

impl AdapterCategory {
    /// 落库/展示用文本（对齐 `docs/adapter-spec.md` §1.2 的 category 词表）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Notification => "message",
            Self::Itsm => "itsm",
            Self::SecurityPlatform => "siem",
        }
    }

    /// 中文显示名。
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Notification => "通知渠道",
            Self::Itsm => "工单/ITSM",
            Self::SecurityPlatform => "安全设备/平台",
        }
    }
}

impl MessageKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Notification => "notification",
            Self::Event => "event",
        }
    }
}

impl AdapterMessage {
    /// 由内容派生确定性幂等键。
    ///
    /// **不使用时间戳**：同一事件重复投递必须得到同一键，否则远端去重失效。
    #[must_use]
    pub fn derive_key(kind: MessageKind, event_type: &str, title: &str, body: &serde_json::Value) -> String {
        let canonical = format!("{}|{event_type}|{title}|{body}", kind.as_str());
        crate::transport::deterministic_token("agf-msg", &canonical)
    }

    /// 构造通知类载荷。
    #[must_use]
    pub fn notification(title: impl Into<String>, summary: impl Into<String>) -> Self {
        let title = title.into();
        let body = serde_json::Value::Null;
        let key = Self::derive_key(MessageKind::Notification, "notify.alert", &title, &body);
        Self {
            kind: MessageKind::Notification,
            event_type: "notify.alert".to_string(),
            title,
            summary: summary.into(),
            severity: Severity::Medium,
            asset: None,
            body,
            idempotency_key: key,
            occurred_at: Timestamp::now(),
            labels: BTreeMap::new(),
        }
    }

    /// 构造事件类载荷。
    #[must_use]
    pub fn event(
        event_type: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        summary: impl Into<String>,
        body: serde_json::Value,
    ) -> Self {
        let event_type = event_type.into();
        let title = title.into();
        let key = Self::derive_key(MessageKind::Event, &event_type, &title, &body);
        Self {
            kind: MessageKind::Event,
            event_type,
            title,
            summary: summary.into(),
            severity,
            asset: None,
            body,
            idempotency_key: key,
            occurred_at: Timestamp::now(),
            labels: BTreeMap::new(),
        }
    }

    /// 设置等级（链式）。
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// 设置关联资产（链式）。
    #[must_use]
    pub fn with_asset(mut self, asset: impl Into<String>) -> Self {
        self.asset = Some(asset.into());
        self
    }

    /// 追加标签（链式）。
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// 覆盖幂等键（链式；显式键优先，用于上层跨通道去重）。
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = key.into();
        self
    }

    /// 人读文本渲染（各厂商最终都以它作为正文基础，保证文案一致）。
    ///
    /// 输出确定性：同一载荷在任何适配器上渲染结果完全一致（便于快照断言）。
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::with_capacity(self.summary.len() + self.title.len() + 64);
        out.push('【');
        out.push_str(self.severity.as_str());
        out.push('】');
        out.push_str(&self.title);
        out.push('\n');
        if !self.summary.is_empty() {
            out.push_str(&self.summary);
            out.push('\n');
        }
        out.push_str("event=");
        out.push_str(&self.event_type);
        if let Some(asset) = &self.asset {
            out.push_str(" asset=");
            out.push_str(asset);
        }
        out.push_str(" at=");
        out.push_str(&self.occurred_at.to_rfc3339());
        if !self.labels.is_empty() {
            out.push('\n');
            let joined: Vec<String> = self.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            out.push_str(&joined.join(" "));
        }
        out
    }

    /// 是否命中事件类型前缀（`*` 表示全订阅）。
    #[must_use]
    pub fn matches_prefix(&self, prefixes: &[String]) -> bool {
        prefixes.iter().any(|p| p == "*" || self.event_type.starts_with(p.as_str()))
    }

    /// 是否达到最低等级要求。
    #[must_use]
    pub fn meets_severity(&self, min: Option<Severity>) -> bool {
        min.is_none_or(|m| self.severity.weight() >= m.weight())
    }
}

impl AdapterMetadata {
    /// 构造元信息（其余字段用链式方法补齐，`version` 取本 crate 版本）。
    #[must_use]
    pub fn new(name: &str, display_name: &str, vendor: &str, category: AdapterCategory) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            vendor: vendor.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            category,
            capabilities: Vec::new(),
            requires_network: true,
            required_secrets: Vec::new(),
            optional_secrets: Vec::new(),
            endpoint_key: None,
            degradation: String::new(),
            mock_location: format!("crates/agf-adapters/src/{name}/mock.rs#Mock{}Adapter", camel(name)),
            doc_anchor: format!("docs/adapter-spec.md#{name}"),
            real_transport: false,
            // 默认**不声称** push/pull/sync 能力：适配器必须显式 `with_semantics` 声明，
            // 漏声明会被"内置适配器不得未登记"的单测拦住（fail-safe：宁可不声称）。
            semantics: crate::contract::SemanticProfile::undeclared(),
        }
    }

    /// 设置能力清单。
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<AdapterCapability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// 设置凭据键。
    #[must_use]
    pub fn with_secrets(mut self, required: &[&str], optional: &[&str]) -> Self {
        self.required_secrets = required.iter().map(|s| (*s).to_string()).collect();
        self.optional_secrets = optional.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// 设置 endpoint 设置键。
    #[must_use]
    pub fn with_endpoint_key(mut self, key: &str) -> Self {
        self.endpoint_key = Some(key.to_string());
        self
    }

    /// 设置是否需要网络。
    #[must_use]
    pub fn with_network(mut self, requires_network: bool) -> Self {
        self.requires_network = requires_network;
        self
    }

    /// 设置降级行为说明。
    #[must_use]
    pub fn with_degradation(mut self, degradation: &str) -> Self {
        self.degradation = degradation.to_string();
        self
    }

    /// 设置 Mock 实现位置。
    #[must_use]
    pub fn with_mock_location(mut self, location: &str) -> Self {
        self.mock_location = location.to_string();
        self
    }

    /// 标记是否已有真实传输实现。
    #[must_use]
    pub fn with_real_transport(mut self, real: bool) -> Self {
        self.real_transport = real;
        self
    }

    /// 声明 `push` / `pull` / `sync` 的能力档位（**如实登记**：不适用必须给原因）。
    #[must_use]
    pub fn with_semantics(mut self, semantics: crate::contract::SemanticProfile) -> Self {
        self.semantics = semantics;
        self
    }

    /// 转为 `agf-core` 的描述符（契约要求的两个非空字段在此保证）。
    #[must_use]
    pub fn to_descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            name: self.name.clone(),
            display_name: self.display_name.clone(),
            category: self.category.as_str().to_string(),
            required_secrets: self.required_secrets.clone(),
            optional_secrets: self.optional_secrets.clone(),
            capabilities: self.capabilities.clone(),
            degradation: if self.degradation.is_empty() {
                "未配置时不下发任何通知/工单/指令（降级而非失败），平台主流程不受影响".to_string()
            } else {
                self.degradation.clone()
            },
            mock_location: self.mock_location.clone(),
            real_implementation: self.real_transport,
            doc_anchor: self.doc_anchor.clone(),
        }
    }

    /// 判断必需凭据的缺项（纯逻辑，不触网、不读环境）。
    #[must_use]
    pub fn missing_secrets<'a>(&'a self, present: &[String]) -> Vec<&'a str> {
        self.required_secrets.iter().filter(|k| !present.iter().any(|p| p == *k)).map(String::as_str).collect()
    }
}

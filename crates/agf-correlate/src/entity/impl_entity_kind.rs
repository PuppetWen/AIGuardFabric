//! 由 `entity.rs` 拆分：`impl_EntityKind`/`impl_EntityRef` 等 8 项（纯搬移，逻辑不变）。
use super::*;

impl EntityKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Host => "host",
            Self::User => "user",
            Self::Agent => "agent",
            Self::McpServer => "mcp-server",
            Self::Domain => "domain",
            Self::CloudIdentity => "cloud-identity",
        }
    }

    /// 全部类型。
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [Self::Ip, Self::Host, Self::User, Self::Agent, Self::McpServer, Self::Domain, Self::CloudIdentity]
    }
}

impl EntityRef {
    /// 构造。
    #[must_use]
    pub fn new(
        kind: Option<EntityKind>,
        canonical: impl Into<String>,
        strength: EntityRefStrength,
        source: impl Into<String>,
    ) -> Self {
        Self { kind, canonical: canonical.into(), strength, source: source.into() }
    }

    /// 生成对齐键：`类型|归一标识`（不含租户，租户在 [`entity_alignment_key`] 里拼）。
    #[must_use]
    pub fn local_key(&self) -> String {
        let kind = self.kind.map_or("generic", |k| k.as_str());
        format!("{kind}|{}", self.canonical)
    }

    /// 生成实体 id（确定性，同类型同标识跨会话稳定）。
    ///
    /// 用途：攻击链路图节点 id、跨事件稳定性对照。
    #[must_use]
    pub fn entity_id(&self, tenant: TenantId) -> Id {
        agf_core::ids::deterministic_id(NS_ENTITY, &entity_alignment_key(tenant, self.kind, &self.canonical))
    }
}

/// 跨源实体对齐键：`租户 + 类型 + 归一化标识`。
#[must_use]
pub fn entity_alignment_key(tenant: TenantId, kind: Option<EntityKind>, canonical: &str) -> String {
    let kind = kind.map_or("generic", |k| k.as_str());
    format!("{tenant}|{kind}|{canonical}")
}

impl EventEntities {
    /// 是否空（未抽取到任何指称）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// 该事件涉及的全部对齐键（去重、稳定顺序）。
    #[must_use]
    pub fn alignment_keys(&self, tenant: TenantId) -> Vec<String> {
        let mut keys: Vec<String> = self
            .refs
            .iter()
            .map(|r| entity_alignment_key(tenant, r.kind, &r.canonical))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        keys.sort();
        keys
    }

    /// 某类型下的全部归一化标识。
    #[must_use]
    pub fn identifiers(&self, kind: EntityKind) -> Vec<String> {
        self.by_kind.get(kind.as_str()).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// 最强证据的指称。
    #[must_use]
    pub fn strongest(&self) -> Option<&EntityRef> {
        self.refs.first()
    }
}

impl Default for EntityAligner {
    fn default() -> Self {
        Self { scan_message: true, promote_ip_to_host: true, max_message_refs: 32 }
    }
}

impl EntityAligner {
    /// 默认配置。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 关闭正文扫描（只信结构字段，噪声最低）。
    #[must_use]
    pub const fn structural_only() -> Self {
        Self { scan_message: false, promote_ip_to_host: true, max_message_refs: 0 }
    }

    /// 从一个事件抽取跨源实体指称。
    #[must_use]
    pub fn extract(&self, event: &Event) -> EventEntities {
        let mut refs: Vec<EntityRef> = Vec::new();
        let src = if event.source_name.is_empty() { "event" } else { event.source_name.as_str() };

        // ---- 主机：强标识优先 ----
        if let Some(id) = clean_opt(event.host.id.as_deref()) {
            refs.push(EntityRef::new(Some(EntityKind::Host), id, EntityRefStrength::Strong, format!("{src}.host.id")));
        }
        if let Some(inst) = clean_opt(event.host.cloud_instance_id.as_deref()) {
            refs.push(EntityRef::new(
                Some(EntityKind::Host),
                inst,
                EntityRefStrength::Strong,
                format!("{src}.host.cloud_instance_id"),
            ));
        }
        if let Some(name) = clean_opt(event.host.name.as_deref()) {
            refs.push(EntityRef::new(
                Some(EntityKind::Host),
                normalize_hostname(&name),
                EntityRefStrength::Medium,
                format!("{src}.host.name"),
            ));
        }
        for ip in &event.host.ips {
            if let Some(n) = normalize_ip(ip) {
                refs.push(EntityRef::new(
                    Some(EntityKind::Ip),
                    n,
                    EntityRefStrength::Medium,
                    format!("{src}.host.ips"),
                ));
            }
        }
        if let Some(pod) = clean_opt(event.host.k8s_pod.as_deref()) {
            refs.push(EntityRef::new(
                Some(EntityKind::Host),
                pod,
                EntityRefStrength::Weak,
                format!("{src}.host.k8s_pod"),
            ));
        }

        // ---- 网络 ----
        for (field, value) in [
            ("network.source_ip", event.network.source_ip.as_deref()),
            ("network.destination_ip", event.network.destination_ip.as_deref()),
        ] {
            if let Some(n) = value.and_then(normalize_ip) {
                refs.push(EntityRef::new(Some(EntityKind::Ip), n, EntityRefStrength::Medium, format!("{src}.{field}")));
            }
        }
        if let Some(domain) = event.network.domain.as_deref().and_then(normalize_domain) {
            refs.push(EntityRef::new(
                Some(EntityKind::Domain),
                domain,
                EntityRefStrength::Medium,
                format!("{src}.network.domain"),
            ));
        }

        // ---- 用户 ----
        if let Some(id) = clean_opt(event.user.id.as_deref()) {
            refs.push(EntityRef::new(Some(EntityKind::User), id, EntityRefStrength::Strong, format!("{src}.user.id")));
        }
        if let Some(email) = event.user.email.as_deref().and_then(normalize_email) {
            refs.push(EntityRef::new(
                Some(EntityKind::User),
                email,
                EntityRefStrength::Strong,
                format!("{src}.user.email"),
            ));
        }
        if let Some(name) = clean_opt(event.user.name.as_deref()) {
            refs.push(EntityRef::new(
                Some(EntityKind::User),
                name,
                EntityRefStrength::Medium,
                format!("{src}.user.name"),
            ));
        }

        // ---- AI 资产 ----
        if let Some(agent) = event.ai.agent_id {
            refs.push(EntityRef::new(
                Some(EntityKind::Agent),
                agent.to_string(),
                EntityRefStrength::Strong,
                format!("{src}.ai.agent_id"),
            ));
        }
        if let Some(flavor) = clean_opt(event.ai.agent_flavor.as_deref()) {
            refs.push(EntityRef::new(
                Some(EntityKind::Agent),
                flavor,
                EntityRefStrength::Weak,
                format!("{src}.ai.agent_flavor"),
            ));
        }
        if let Some(mcp) = event.ai.mcp_server_id {
            refs.push(EntityRef::new(
                Some(EntityKind::McpServer),
                mcp.to_string(),
                EntityRefStrength::Strong,
                format!("{src}.ai.mcp_server_id"),
            ));
        }
        if let Some(provider) = clean_opt(event.ai.provider.as_deref()) {
            refs.push(EntityRef::new(
                Some(EntityKind::CloudIdentity),
                provider,
                EntityRefStrength::Weak,
                format!("{src}.ai.provider"),
            ));
        }

        // ---- 正文兜底（低置信，只补空缺） ----
        if self.scan_message && self.max_message_refs > 0 && !event.message.is_empty() {
            refs.extend(scan_text(&event.message, self.max_message_refs, &format!("{src}.message")));
        }

        self.finish(refs)
    }

    /// 去重、按强度降序、填 `by_kind`。
    pub(crate) fn finish(&self, mut refs: Vec<EntityRef>) -> EventEntities {
        refs.sort_by(|a, b| b.strength.cmp(&a.strength).then_with(|| a.local_key().cmp(&b.local_key())));
        let mut seen: BTreeSet<String> = BTreeSet::new();
        refs.retain(|r| !r.canonical.is_empty() && seen.insert(r.local_key()));
        if self.promote_ip_to_host {
            promote_ips_to_hosts(&mut refs);
        }
        let mut by_kind: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for r in &refs {
            let key = r.kind.map_or("generic".to_string(), |k| k.as_str().to_string());
            by_kind.entry(key).or_default().insert(r.canonical.clone());
        }
        EventEntities { refs, by_kind }
    }
}

/// 把 IP 指称同步登记为主机指称（IP 是最常见的主机指称）。
pub(crate) fn promote_ips_to_hosts(refs: &mut Vec<EntityRef>) {
    let ips: Vec<EntityRef> = refs
        .iter()
        .filter(|r| r.kind == Some(EntityKind::Ip))
        .map(|r| EntityRef::new(Some(EntityKind::Host), r.canonical.clone(), r.strength, r.source.clone()))
        .collect();
    for ip in ips {
        if !refs.iter().any(|r| r.kind == Some(EntityKind::Host) && r.canonical == ip.canonical) {
            refs.push(ip);
        }
    }
    refs.sort_by(|a, b| b.strength.cmp(&a.strength).then_with(|| a.local_key().cmp(&b.local_key())));
}

/// 从自由文本里抠出 IP / 域名 / 邮箱（低置信兜底）。
pub(crate) fn scan_text(text: &str, limit: usize, source: &str) -> Vec<EntityRef> {
    let mut out = Vec::new();
    for token in text
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '"' | '\'' | '<' | '>'))
    {
        if out.len() >= limit {
            break;
        }
        let token = token.trim_matches(|c: char| matches!(c, '.' | ':' | '/' | '\\' | '|'));
        if token.is_empty() {
            continue;
        }
        if let Some(email) = normalize_email(token) {
            out.push(EntityRef::new(Some(EntityKind::User), email, EntityRefStrength::Weak, source.to_string()));
            continue;
        }
        if let Some(ip) = normalize_ip(token) {
            out.push(EntityRef::new(Some(EntityKind::Ip), ip, EntityRefStrength::Weak, source.to_string()));
            continue;
        }
        if let Some(domain) = normalize_domain(token) {
            out.push(EntityRef::new(Some(EntityKind::Domain), domain, EntityRefStrength::Weak, source.to_string()));
        }
    }
    out
}

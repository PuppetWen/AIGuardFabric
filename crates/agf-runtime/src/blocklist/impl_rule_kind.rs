//! 由 `blocklist.rs` 拆分：`impl_RuleKind`/`impl_RuleAction` 等 8 项（纯搬移，逻辑不变）。
use super::*;

impl RuleKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Domain => "domain",
            Self::Path => "path",
            Self::Tool => "tool",
            Self::Hash => "hash",
        }
    }

    /// 中文显示名（控制台）。
    #[must_use]
    pub const fn display_zh(&self) -> &'static str {
        match self {
            Self::Command => "命令",
            Self::Domain => "域名",
            Self::Path => "路径",
            Self::Tool => "工具",
            Self::Hash => "哈希",
        }
    }

    /// 全部类别。
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [Self::Command, Self::Domain, Self::Path, Self::Tool, Self::Hash]
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知类别返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "command" | "cmd" => Ok(Self::Command),
            "domain" | "host" => Ok(Self::Domain),
            "path" | "file" => Ok(Self::Path),
            "tool" => Ok(Self::Tool),
            "hash" | "digest" => Ok(Self::Hash),
            other => Err(format!("未知黑名单类别: {other}")),
        }
    }
}

impl RuleAction {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Audit => "audit",
        }
    }

    /// 是否拦截。
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Self::Deny)
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知动作返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "deny" | "block" => Ok(Self::Deny),
            "allow" | "permit" => Ok(Self::Allow),
            "audit" | "log" => Ok(Self::Audit),
            other => Err(format!("未知黑名单动作: {other}")),
        }
    }
}

impl RuleRule {
    /// 构造拒绝规则。
    #[must_use]
    pub fn deny(
        id: impl Into<String>,
        kind: RuleKind,
        pattern: impl Into<String>,
        reason: impl Into<String>,
        domain: RiskDomain,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            pattern: pattern.into(),
            action: RuleAction::Deny,
            reason: reason.into(),
            domain,
            severity,
        }
    }

    /// 构造白名单规则。
    #[must_use]
    pub fn allow(
        id: impl Into<String>,
        kind: RuleKind,
        pattern: impl Into<String>,
        reason: impl Into<String>,
        domain: RiskDomain,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            pattern: pattern.into(),
            action: RuleAction::Allow,
            reason: reason.into(),
            domain,
            severity: Severity::Info,
        }
    }

    /// 模式是否为正则。
    #[must_use]
    pub fn is_regex(&self) -> bool {
        self.pattern.starts_with("re:")
    }
}

impl RuleHit {
    /// 是否应拦截。
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        self.action.is_blocking()
    }
}

impl BlocklistStats {
    /// 规则总数（`rule_count` 的别名，便于前端两种命名）。
    #[must_use]
    pub const fn total_rules(&self) -> usize {
        self.rule_count
    }

    /// 是否已加载任何规则（自检项）。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rule_count == 0
    }
}

impl CompiledRule {
    pub(crate) fn compile(rule: RuleRule) -> DomainResult<Self> {
        let regex = if let Some(src) = rule.pattern.strip_prefix("re:") {
            let regex = Regex::new(src)
                .map_err(|e| DomainError::Parse(format!("黑名单规则 {} 的正则非法 `{src}`: {e}", rule.id)))?;
            Some(regex)
        } else {
            None
        };
        Ok(Self { rule, regex })
    }

    /// 对给定文本求值。
    pub(crate) fn matches(&self, text: &str) -> DomainResult<bool> {
        match self.rule.kind {
            RuleKind::Domain => {
                if let Some(re) = &self.regex {
                    return Ok(re.is_match(text));
                }
                Ok(domain_matches(&self.rule.pattern, text))
            }
            RuleKind::Path => {
                if let Some(re) = &self.regex {
                    return Ok(re.is_match(text));
                }
                Ok(path_matches_sensitive(&self.rule.pattern, text))
            }
            RuleKind::Command | RuleKind::Tool | RuleKind::Hash => {
                // 复用 agf-core 的实现：子串不区分大小写 + `re:` 正则。
                command_matches_deny(&self.rule.pattern, text)
                    .map_err(|e| DomainError::Parse(format!("黑名单规则 {} 匹配失败: {e}", self.rule.id)))
            }
        }
    }
}

/// 敏感路径匹配（分隔符归一 + 大小写不敏感 + **按路径段对齐**）。
///
/// 为什么不能只用 [`path_matches_prefix`]：内置路径规则既有绝对路径
/// （`/etc/shadow`、`%USERPROFILE%\.aws\credentials`），也有**文件名/目录名**
/// （`id_rsa`、`.ssh`、`.npmrc`、`kubeconfig`、`Login Data`）。前者是前缀语义，
/// 后者只能靠"路径段"识别。
///
/// 为什么不能用纯子串：`.ssh` 的纯子串匹配会把 `.ssh_backup` 也判成命中，
/// 造成误报。因此这里要求匹配**落在路径段边界上**（`/pattern` 或 `/pattern/`）。
#[must_use]
pub fn path_matches_sensitive(pattern: &str, path: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").to_ascii_lowercase();
    let p = norm(pattern);
    let p = p.trim_matches('/');
    if p.is_empty() {
        return false;
    }
    let v = norm(path);
    if v == p || v == format!("/{p}") {
        return true;
    }
    let seg = format!("/{p}");
    // 前缀（模式本身不带前导 `/`，如 `%APPDATA%\gcloud`）
    if let Some(rest) = v.strip_prefix(p) {
        if rest.starts_with('/') {
            return true;
        }
    }
    // 前缀 / 后缀 / 中间段（模式为 `/etc/shadow`、`id_rsa`、`.ssh` 等）
    if let Some(rest) = v.strip_prefix(&seg) {
        if rest.is_empty() || rest.starts_with('/') {
            return true;
        }
    }
    v.ends_with(&seg) || v.contains(&format!("{seg}/"))
}

impl Default for Blocklist {
    /// 默认即[内置黑名单](Blocklist::default_rules)（**保证最低防线**）。
    fn default() -> Self {
        Self::with_defaults()
    }
}

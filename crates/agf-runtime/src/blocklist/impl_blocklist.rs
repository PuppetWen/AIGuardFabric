//! 由 `blocklist.rs` 拆分：`Blocklist` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Blocklist {
    /// 空黑名单（仅测试与"完全自定义"场景；[`crate::guard::SelfCheck`] 会判 FAIL）。
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new(), stats: BlocklistStats::default(), allowlist: Vec::new() }
    }

    /// 内置默认黑名单。
    ///
    /// # Panics
    /// 内置规则均为常量且已通过单测覆盖，正则非法属于编译期缺陷；此处不返回 `Result`
    /// 以避免调用方为"不可能失败"的分支写样板。构造过程本身不 panic：
    /// 非法正则的规则会被**跳过**（并在 [`Blocklist::validate`] 中暴露）。
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut list = Self::empty();
        for rule in default_rules() {
            // 内置规则理应全部可编译；不可编译者跳过而非 panic，保证 `with_defaults` 永不 panic。
            if let Ok(compiled) = CompiledRule::compile(rule) {
                list.rules.push(compiled);
            }
        }
        list.stats.rule_count = list.rules.len();
        list.stats.by_kind = count_by_kind(&list.rules);
        list.stats.last_change = format!("内置默认黑名单（{} 条规则）", list.rules.len());
        list
    }

    /// 由显式规则集构造（会做编译校验）。
    ///
    /// # Errors
    /// 任一规则的正则非法即返回 [`DomainError::Parse`]（**整体拒绝**，不做部分加载）。
    pub fn from_rules(rules: Vec<RuleRule>) -> DomainResult<Self> {
        let mut list = Self::empty();
        for rule in rules {
            list.push_compiled(CompiledRule::compile(rule)?);
        }
        list.refresh_stats("显式规则集加载");
        Ok(list)
    }

    /// 追加一条规则。
    ///
    /// # Errors
    /// 正则非法返回 [`DomainError::Parse`]。
    pub fn add_rule(&mut self, rule: RuleRule) -> DomainResult<()> {
        let compiled = CompiledRule::compile(rule)?;
        self.push_compiled(compiled);
        self.refresh_stats("追加规则");
        Ok(())
    }

    /// 热重载：用新规则集**整体替换**现有规则，不中断服务。
    ///
    /// 失败语义：**先编译全部新规则，全部成功才替换**。因此编译失败时旧规则集原样生效
    /// （黑名单不会因为一次错误的下发而变空 → 不会静默放行）。
    ///
    /// # Errors
    /// 新规则集中任一条正则非法。
    pub fn reload(&mut self, rules: Vec<RuleRule>) -> DomainResult<()> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            compiled.push(CompiledRule::compile(rule)?);
        }
        self.rules = compiled;
        self.allowlist.clear();
        self.refresh_stats("热重载");
        self.stats.reload_count += 1;
        self.stats.last_reload_at = Some(Timestamp::now());
        Ok(())
    }

    /// 热重载为内置默认规则集。
    pub fn reload_defaults(&mut self) {
        let rules = default_rules();
        self.rules = rules.into_iter().filter_map(|r| CompiledRule::compile(r).ok()).collect();
        self.allowlist.clear();
        self.refresh_stats("重载内置默认规则");
        self.stats.reload_count += 1;
        self.stats.last_reload_at = Some(Timestamp::now());
    }

    /// 变更前的校验：返回配置问题的告警列表（不阻断加载，供控制台提示）。
    ///
    /// 覆盖三类问题：
    /// - 规则正则可编译性（内置规则不应出现）；
    /// - 规则 id 重复；
    /// - 白名单覆盖了内置拒绝规则（"过宽白名单会整体关闭内置防线"）。
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for c in self.rules.iter().chain(self.allowlist.iter()) {
            *seen.entry(c.rule.id.as_str()).or_insert(0) += 1;
            if c.rule.is_regex() && c.regex.is_none() {
                warnings.push(format!("规则 {} 的正则无法编译", c.rule.id));
            }
        }
        for (id, count) in seen {
            if count > 1 {
                warnings.push(format!("规则 id 重复 {count} 次：{id}"));
            }
        }
        for allow in &self.allowlist {
            for deny in &self.rules {
                if deny.rule.action.is_blocking() && allow.rule.kind == deny.rule.kind {
                    warnings.push(format!(
                        "白名单 {}（{}）可能覆盖内置拒绝规则 {}（同类别），请确认范围",
                        allow.rule.id, allow.rule.pattern, deny.rule.id
                    ));
                }
            }
        }
        warnings
    }

    /// 注册白名单规则（覆盖同载荷的拒绝规则）。
    ///
    /// # Errors
    /// 正则非法。
    pub fn add_allowlist_rule(&mut self, rule: RuleRule) -> DomainResult<()> {
        let compiled = CompiledRule::compile(rule)?;
        self.allowlist.push(compiled);
        Ok(())
    }

    /// 规则数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// 是否没有任何规则。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 白名单数量。
    #[must_use]
    pub fn allowlist_len(&self) -> usize {
        self.allowlist.len()
    }

    /// 当前规则快照（控制台导出/编辑）。
    #[must_use]
    pub fn rules(&self) -> Vec<RuleRule> {
        self.rules.iter().map(|c| c.rule.clone()).collect()
    }

    /// 统计快照。
    #[must_use]
    pub const fn stats(&self) -> &BlocklistStats {
        &self.stats
    }

    /// 从 [`PolicyContext`] 提取待匹配的命令文本。
    ///
    /// 提取顺序（先显式、后推断）：
    /// 1. `ctx.command` 非空 ⇒ 直接使用（策略调用方已明确给出命令）；
    /// 2. 否则在 `ctx.payload` 中按 MCP 常见字段查找：`command` / `cmd` / `script` / `code` /
    ///    以及 `arguments.<同上>`（JSON-RPC `tools/call` 的参数对象）；
    /// 3. 仍无 ⇒ 返回 `None`（**不做**全载荷字符串化，避免把无关文本误判为命令）。
    #[must_use]
    pub fn extract_command(ctx: &PolicyContext) -> Option<String> {
        if let Some(cmd) = ctx.command.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            return Some(cmd.to_string());
        }
        const KEYS: [&str; 4] = ["command", "cmd", "script", "code"];
        let sources = [Some(&ctx.payload), ctx.payload.get("arguments")];
        for source in sources.into_iter().flatten() {
            for key in KEYS {
                let found =
                    source.get(key).and_then(serde_json::Value::as_str).map(str::trim).filter(|s| !s.is_empty());
                if let Some(text) = found {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    /// 对上下文求值：返回首个命中的规则。
    ///
    /// 语义见模块文档「命中优先级与允许覆盖拒绝」。
    ///
    /// # Errors
    /// 规则匹配过程中出现内部错误（正则运行时异常，正常不可达）。
    pub fn evaluate(&mut self, ctx: &PolicyContext) -> DomainResult<Option<RuleHit>> {
        self.stats.evaluations += 1;
        let command = Self::extract_command(ctx);
        // 先绑定到具名变量：`searchable_hash_text` 的所有权必须活到 candidates 使用结束。
        let hash_text = searchable_hash_text(ctx);
        let candidates: [(RuleKind, Option<&str>); 5] = [
            (RuleKind::Tool, ctx.tool_name.as_deref()),
            (RuleKind::Domain, ctx.domain.as_deref()),
            (RuleKind::Path, ctx.path.as_deref()),
            (RuleKind::Hash, hash_text.as_deref()),
            (RuleKind::Command, command.as_deref()),
        ];

        // 1) 白名单优先（允许覆盖拒绝）
        for (kind, text) in candidates {
            let Some(text) = text.filter(|t| !t.trim().is_empty()) else { continue };
            for compiled in self.allowlist.iter().filter(|c| c.rule.kind == kind) {
                if compiled.matches(text)? {
                    let hit = make_hit(compiled, text);
                    self.record_hit(&hit.rule_id);
                    return Ok(Some(hit));
                }
            }
        }
        // 2) 拒绝/审计规则：按 candidates 顺序取首条命中
        for (kind, text) in candidates {
            let Some(text) = text.filter(|t| !t.trim().is_empty()) else { continue };
            for compiled in self.rules.iter().filter(|c| c.rule.kind == kind) {
                if compiled.matches(text)? {
                    let hit = make_hit(compiled, text);
                    self.record_hit(&hit.rule_id);
                    return Ok(Some(hit));
                }
            }
        }
        Ok(None)
    }

    /// 只对一段命令文本求值（进程 Hook / eBPF 场景没有完整 [`PolicyContext`]）。
    ///
    /// # Errors
    /// 规则匹配内部错误。
    pub fn evaluate_command(&mut self, command: &str) -> DomainResult<Option<RuleHit>> {
        self.stats.evaluations += 1;
        for compiled in self.allowlist.iter().filter(|c| c.rule.kind == RuleKind::Command) {
            if compiled.matches(command)? {
                let hit = make_hit(compiled, command);
                self.record_hit(&hit.rule_id);
                return Ok(Some(hit));
            }
        }
        for compiled in self.rules.iter().filter(|c| c.rule.kind == RuleKind::Command) {
            if compiled.matches(command)? {
                let hit = make_hit(compiled, command);
                self.record_hit(&hit.rule_id);
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    /// 只对域名求值。
    ///
    /// # Errors
    /// 规则匹配内部错误。
    pub fn evaluate_domain(&mut self, domain: &str) -> DomainResult<Option<RuleHit>> {
        self.evaluate_single(RuleKind::Domain, domain)
    }

    /// 只对路径求值。
    ///
    /// # Errors
    /// 规则匹配内部错误。
    pub fn evaluate_path(&mut self, path: &str) -> DomainResult<Option<RuleHit>> {
        self.evaluate_single(RuleKind::Path, path)
    }

    /// 只对工具名求值。
    ///
    /// # Errors
    /// 规则匹配内部错误。
    pub fn evaluate_tool(&mut self, tool: &str) -> DomainResult<Option<RuleHit>> {
        self.evaluate_single(RuleKind::Tool, tool)
    }

    /// 只对哈希求值。
    ///
    /// # Errors
    /// 规则匹配内部错误。
    pub fn evaluate_hash(&mut self, hash: &str) -> DomainResult<Option<RuleHit>> {
        self.evaluate_single(RuleKind::Hash, hash)
    }

    pub(crate) fn evaluate_single(&mut self, kind: RuleKind, text: &str) -> DomainResult<Option<RuleHit>> {
        self.stats.evaluations += 1;
        for compiled in self.allowlist.iter().filter(|c| c.rule.kind == kind) {
            if compiled.matches(text)? {
                let hit = make_hit(compiled, text);
                self.record_hit(&hit.rule_id);
                return Ok(Some(hit));
            }
        }
        for compiled in self.rules.iter().filter(|c| c.rule.kind == kind) {
            if compiled.matches(text)? {
                let hit = make_hit(compiled, text);
                self.record_hit(&hit.rule_id);
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    /// 命中结果的 JSON 形式（注入 Rego / CEL 的 `hit` 变量；无命中为 `null`）。
    #[must_use]
    pub fn hit_json(hit: &Option<RuleHit>) -> serde_json::Value {
        match hit {
            Some(h) => serde_json::json!({
                "rule_id": h.rule_id,
                "kind": h.kind.as_str(),
                "pattern": h.pattern,
                "action": h.action.as_str(),
                "reason": h.reason,
                "domain": h.domain.as_str(),
                "severity": h.severity.as_str(),
                "matched_text": h.matched_text,
            }),
            None => serde_json::Value::Null,
        }
    }

    pub(crate) fn push_compiled(&mut self, compiled: CompiledRule) {
        if compiled.rule.action == RuleAction::Allow {
            self.allowlist.push(compiled);
        } else {
            self.rules.push(compiled);
        }
    }

    pub(crate) fn refresh_stats(&mut self, change: &str) {
        self.stats.rule_count = self.rules.len();
        self.stats.by_kind = count_by_kind(&self.rules);
        self.stats.last_change = change.to_string();
    }

    pub(crate) fn record_hit(&mut self, rule_id: &str) {
        *self.stats.hits.entry(rule_id.to_string()).or_insert(0) += 1;
    }
}

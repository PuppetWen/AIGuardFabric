//! `ParserRegistry` 的匹配与解析主逻辑：模板装载、优先级匹配（explicit/protocol/打分/AI 推断）与统计累计。

use super::*;

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ParserRegistry {
    /// 空注册表（无内置模板；测试与最小部署用）。
    #[must_use]
    pub fn new() -> Self {
        Self { entries: Vec::new(), invalid: Vec::new(), stats: RegistryStats::default(), ai_fallback: false }
    }

    /// 带内置模板的注册表（生产默认）。
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        let mut priority = 100_u32;
        for def in template::builtin_templates() {
            // 内置模板已由测试保证可编译；此处仍走统一注册路径，失败会进 invalid 而非 panic
            if registry.register(def, priority).is_ok() {
                registry.stats.builtin += 1;
            }
            priority += 10;
        }
        registry
    }

    /// 是否启用 AI 推断兜底。
    pub fn set_ai_fallback(&mut self, enabled: bool) {
        self.ai_fallback = enabled;
    }

    /// 注册一个模板（`priority` 数值小者优先）。
    ///
    /// # Errors
    /// 模板校验失败（`key` 为空/模式非法/正则不可编译）。
    pub fn register(&mut self, def: ParserDefinition, priority: u32) -> DomainResult<Id> {
        let origin = if def.builtin { "<builtin>".to_string() } else { "<yaml>".to_string() };
        if let Err(errs) = def.validate() {
            let reason = errs.join("; ");
            self.invalid.push(InvalidTemplate { origin, key: def.key.clone(), reason: reason.clone() });
            self.stats.invalid += 1;
            return Err(DomainError::Validation(format!("模板 {} 校验失败: {reason}", def.key)));
        }
        if let Err(reason) = engine::validate_pattern(&def) {
            self.invalid.push(InvalidTemplate { origin, key: def.key.clone(), reason: reason.clone() });
            self.stats.invalid += 1;
            return Err(DomainError::Validation(format!("模板 {} 模式不可用: {reason}", def.key)));
        }
        let id = parser_id_for(&def.key);
        let now = Timestamp::now();
        // 同 key 覆盖（热更新语义）
        if let Some(existing) = self.entries.iter_mut().find(|p| p.definition.key == def.key) {
            existing.definition = def;
            existing.priority = priority;
            existing.content_hash = content_hash(&existing.definition.pattern);
            existing.updated_at = now;
            return Ok(existing.id);
        }
        self.entries.push(Parser {
            id,
            tenant_id: agf_core::ids::TenantId::default_tenant(),
            content_hash: content_hash(&def.pattern),
            definition: def,
            enabled: true,
            priority,
            success_count: 0,
            failure_count: 0,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        });
        Ok(id)
    }

    /// 注册 AI 推断结果（需人工确认后调用；`priority` 默认排在内置模板之后）。
    ///
    /// # Errors
    /// 与 [`Self::register`] 相同。
    pub fn register_ai_inferred(&mut self, suggestion: &AiParserSuggestion, priority: u32) -> DomainResult<Id> {
        let mut def = suggestion.definition.clone();
        def.ai_inferred = true;
        def.builtin = false;
        let id = self.register(def, priority)?;
        self.stats.ai_inferred += 1;
        Ok(id)
    }

    /// 递归加载目录下的 `*.yaml` / `*.yml` 模板文件。
    ///
    /// 支持两种文件形态：
    /// - 单模板：文件顶层即一个 [`ParserDefinition`]；
    /// - 多模板：`{ "parsers": [ {...}, {...} ] }` 包装。
    ///
    /// # Errors
    /// 目录不存在或不可读。**单个文件解析失败不会中断整体加载**（计入 `invalid`）。
    pub fn load_dir(&mut self, dir: &Path) -> DomainResult<usize> {
        if !dir.is_dir() {
            return Err(DomainError::NotFound { entity: "parser-dir", id: dir.display().to_string() });
        }
        let mut files = Vec::new();
        collect_yaml_files(dir, &mut files)?;
        // 不再二次排序：`collect_yaml_files` 已保证确定性顺序
        // （当前目录文件优先、按文件名排序；随后子目录递归），
        // 该顺序即 priority 的先后，顶层文件因此天然高于子目录。
        let mut loaded = 0_usize;
        let mut priority = 1_000_u32;
        for file in files {
            let text = match std::fs::read_to_string(&file) {
                Ok(t) => t,
                Err(e) => {
                    self.invalid.push(InvalidTemplate {
                        origin: file.display().to_string(),
                        key: String::new(),
                        reason: format!("读取失败: {e}"),
                    });
                    self.stats.invalid += 1;
                    continue;
                }
            };
            let defs = match parse_template_file(&text) {
                Ok(defs) => defs,
                Err(reason) => {
                    self.invalid.push(InvalidTemplate {
                        origin: file.display().to_string(),
                        key: String::new(),
                        reason: reason.clone(),
                    });
                    self.stats.invalid += 1;
                    warn!(file = %file.display(), reason, "解析器模板文件加载失败");
                    continue;
                }
            };
            for def in defs {
                let key = def.key.clone();
                match self.register(def, priority) {
                    Ok(_) => {
                        loaded += 1;
                        debug!(key, file = %file.display(), "解析器模板已加载");
                    }
                    Err(e) => {
                        warn!(key, error = %e, "解析器模板被拒绝");
                    }
                }
                priority += 1;
            }
        }
        self.stats.loaded += loaded;
        Ok(loaded)
    }

    /// 全部模板（含内置）。
    #[must_use]
    pub fn all(&self) -> &[Parser] {
        &self.entries
    }

    /// 加载失败的模板。
    #[must_use]
    pub fn invalid_templates(&self) -> &[InvalidTemplate] {
        &self.invalid
    }

    /// 统计快照。
    #[must_use]
    pub fn stats(&self) -> RegistryStats {
        self.stats.clone()
    }

    /// 按 key 查找（启用与否都返回，便于 UI 展示）。
    #[must_use]
    pub fn find_key(&self, key: &str) -> Option<&Parser> {
        self.entries.iter().find(|p| p.definition.key == key)
    }

    /// 按 id 查找。
    #[must_use]
    pub fn find_id(&self, id: Id) -> Option<&Parser> {
        self.entries.iter().find(|p| p.id == id)
    }

    /// 按 (vendor, product, protocol) 过滤（UI 下拉与排障用）。
    #[must_use]
    pub fn filter(&self, vendor: &str, product: &str, protocol: Option<IngestProtocol>) -> Vec<&Parser> {
        self.entries
            .iter()
            .filter(|p| vendor.is_empty() || p.definition.vendor.contains(vendor))
            .filter(|p| product.is_empty() || p.definition.product.contains(product))
            .filter(|p| protocol.is_none_or(|proto| p.definition.protocols.contains(&proto)))
            .collect()
    }

    /// 匹配并解析一条原始日志（= [`Self::match_raw_with_mode`] 的结果部分）。
    #[must_use]
    pub fn match_raw(
        &mut self,
        raw: &str,
        protocol: IngestProtocol,
        vendor: Option<&str>,
        parser_key: Option<&str>,
    ) -> ParseOutcome {
        self.match_raw_with_mode(raw, protocol, vendor, parser_key).0
    }

    /// 匹配并解析一条原始日志，并给出**命中趟次**（严格 / 放宽 / 样本打分 / AI / 显式）。
    ///
    /// 顺序见模块文档；关键不变量：
    ///
    /// * 严格趟（协议白名单生效）**行为与修复前逐字一致**——放宽趟只在严格趟零命中后才跑；
    /// * 放宽趟**只忽略协议白名单**：vendor 提示过滤、`required_fields` 校验、优先级顺序、
    ///   `protocols` 为空的模板（严格趟已试）全部保持原样，因此不会"因为放宽就接受缺字段的载荷"；
    /// * 命中趟次**如实返回**（`None` = 未命中），绝不把放宽命中伪装成严格命中；
    /// * 命中时趟次还会**逐条写进结果**（[`ParseOutcome::matched_by`]，统一由 [`Self::record`]
    ///   回填）：调用方拿到的是"命中了谁 + 凭什么命中"，而不是只有 `parser_key`。
    #[must_use]
    pub fn match_raw_with_mode(
        &mut self,
        raw: &str,
        protocol: IngestProtocol,
        vendor: Option<&str>,
        parser_key: Option<&str>,
    ) -> (ParseOutcome, Option<MatchMode>) {
        // 插件引擎的调用上下文（协议 / 源 / 时间）：**在这里**设置而不是在 engine 层，
        // 因为只有匹配路径知道协议与厂商标识提示（`source` 取 `LogSource.vendor`）。
        // 守卫在函数返回时自动还原（多条提前 return 的分支不会漏清理）。
        let _plugin_context = engine::plugin::set_plugin_context(engine::plugin::PluginContext {
            protocol: protocol.as_str().to_string(),
            source: vendor.unwrap_or_default().to_string(),
            received_at: Timestamp::now().to_rfc3339(),
        });

        // 1) 显式指定
        if let Some(key) = parser_key {
            if let Some(parser) = self.entries.iter().find(|p| p.enabled && p.definition.key == key) {
                let mut outcome = engine::parse_with(&parser.definition, raw);
                self.record(&mut outcome, MatchMode::Explicit);
                if outcome.matched {
                    return (outcome, Some(MatchMode::Explicit));
                }
                debug!(key, "显式指定的解析器未命中，回退到优先级匹配");
            }
        }

        let order = self.match_order();
        let vendor_hint = vendor.map(str::to_lowercase);

        // 2) 优先级顺序（**严格趟**：协议白名单生效）
        for idx in order.iter().copied() {
            let Some(parser) = self.entries.get(idx) else { continue };
            if !parser.enabled {
                continue;
            }
            let def = &parser.definition;
            if !protocol_allowed(def, protocol) {
                continue;
            }
            if !vendor_accepts(def, vendor_hint.as_deref()) {
                continue;
            }
            let outcome = engine::parse_with(def, raw);
            if outcome.matched {
                let mut outcome = outcome;
                self.record(&mut outcome, MatchMode::Protocol);
                return (outcome, Some(MatchMode::Protocol));
            }
        }

        // 3) **放宽趟**（仅严格趟零命中）：忽略协议白名单补试一次。
        //    只试"声明了协议但不含当前协议"的模板——`protocols` 为空者已在严格趟试过，
        //    重复解析只会白烧 CPU；`required_fields` 由 `parse_with` 继续把关。
        for idx in order.iter().copied() {
            let Some(parser) = self.entries.get(idx) else { continue };
            if !parser.enabled {
                continue;
            }
            let def = &parser.definition;
            if protocol_allowed(def, protocol) {
                continue;
            }
            if !vendor_accepts(def, vendor_hint.as_deref()) {
                continue;
            }
            if !format_plausible(def, raw) {
                debug!(key = %def.key, "放宽趟跳过：载荷形态与模板引擎不相容（JSON 载荷不交给 CSV 模板）");
                continue;
            }
            let outcome = engine::parse_with(def, raw);
            if outcome.matched {
                debug!(
                    key = %def.key,
                    protocol = protocol.as_str(),
                    declared = ?def.protocols,
                    "协议白名单放宽命中（严格趟零命中；请考虑给该模板补声明此协议）"
                );
                let mut outcome = outcome;
                self.record(&mut outcome, MatchMode::ProtocolRelaxed);
                return (outcome, Some(MatchMode::ProtocolRelaxed));
            }
        }

        // 4) 样本打分
        //
        //    打分修好（与 `parse_with` 同口径）之后，本趟才真正开始生效，因此也必须
        //    与放宽趟共用同一张**格式自证**闸门：`Csv` 引擎会把一条 JSON 日志按逗号切开、
        //    按列名凑出 `required_fields`（如 `serial`），造出"高分假命中"并顶掉 AI 兜底
        //    （与放宽趟里实测到的 `paloalto-panos-csv` 吃掉 JSON 载荷是同一个坑）。
        let mut best: Option<(f32, usize)> = None;
        for (idx, parser) in self.entries.iter().enumerate() {
            if !parser.enabled {
                continue;
            }
            let def = &parser.definition;
            if !format_plausible(def, raw) {
                continue;
            }
            let score = engine::sample_match_score(def, raw);
            if score >= MATCH_THRESHOLD && best.is_none_or(|(best_score, _)| score > best_score) {
                best = Some((score, idx));
            }
        }
        if let Some((score, idx)) = best {
            if let Some(parser) = self.entries.get(idx) {
                let outcome = engine::parse_with(&parser.definition, raw);
                if outcome.matched {
                    debug!(key = %parser.definition.key, score, "样本打分命中");
                    let mut outcome = outcome;
                    self.record(&mut outcome, MatchMode::SampleScore);
                    return (outcome, Some(MatchMode::SampleScore));
                }
            }
        }

        // 5) AI 推断兜底（可选）
        if self.ai_fallback {
            if let Some(suggestion) = crate::ai_parser::infer_suggestion(&[raw.to_string()], vendor, Some(protocol)) {
                let mut def = suggestion.definition;
                def.ai_inferred = true;
                def.builtin = false;
                let mut outcome = engine::parse_with(&def, raw);
                if outcome.matched {
                    outcome.parser_key = Some(def.key.clone());
                    self.stats.ai_inferred += 1;
                    self.record(&mut outcome, MatchMode::AiInferred);
                    return (outcome, Some(MatchMode::AiInferred));
                }
            }
        }

        self.stats.unmatched += 1;
        (ParseOutcome::miss("无模板命中（可上送 AI 推断生成解析器）"), None)
    }

    /// 模板尝试顺序（`(priority 升序, 内置优先, key)`）——严格趟与放宽趟**共用**，
    /// 保证两趟顺序一致、结果确定（可复现、可解释）。
    fn match_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        order.sort_by(|a, b| {
            let pa = self.entries.get(*a);
            let pb = self.entries.get(*b);
            match (pa, pb) {
                (Some(x), Some(y)) => x
                    .priority
                    .cmp(&y.priority)
                    .then_with(|| y.definition.builtin.cmp(&x.definition.builtin))
                    .then_with(|| x.definition.key.cmp(&y.definition.key)),
                _ => std::cmp::Ordering::Equal,
            }
        });
        order
    }

    /// 记录一次匹配结果到统计，并**在命中时把趟次逐条写进结果**
    /// （[`ParseOutcome::matched_by`]）。
    ///
    /// 所有命中路径都经过本函数，因此"命中但不知道凭什么命中"不可能发生：
    /// `matched_by` 是**逐条**可观测的（进 `IngestOutcome.matched_by`、进响应体、进事件记录），
    /// [`RegistryStats::matched_by_mode`] 是它的聚合。
    fn record(&mut self, outcome: &mut ParseOutcome, mode: MatchMode) {
        if outcome.matched {
            outcome.matched_by = Some(mode.as_str().to_string());
        }
        self.stats.match_micros_total = self.stats.match_micros_total.saturating_add(outcome.elapsed_micros);
        let Some(key) = outcome.parser_key.clone() else {
            return;
        };
        if outcome.matched {
            *self.stats.matched_counts.entry(key.clone()).or_insert(0) += 1;
            *self.stats.matched_by_mode.entry(mode.as_str().to_string()).or_insert(0) += 1;
            if mode.is_relaxed() {
                self.stats.matched_relaxed = self.stats.matched_relaxed.saturating_add(1);
                *self.stats.relaxed_hits.entry(key.clone()).or_insert(0) += 1;
            }
        }
        if let Some(parser) = self.entries.iter_mut().find(|p| p.definition.key == key) {
            if outcome.matched {
                parser.success_count += 1;
                parser.last_used_at = Some(Timestamp::now());
            } else {
                parser.failure_count += 1;
            }
        }
    }

    /// 需要人工关注的模板（成功率低且样本足够）。
    #[must_use]
    pub fn needs_attention(&self, min_rate: f32, min_samples: u64) -> Vec<&Parser> {
        self.entries.iter().filter(|p| p.needs_attention(min_rate, min_samples)).collect()
    }
}

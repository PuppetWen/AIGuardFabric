//! 由 `loader.rs` 拆分：`LoadReport`/`RulePack`/`RulePackLoader`/`RulesDir` 的实现（纯搬移，逻辑不变）。
use super::*;

impl RulesDir {
    /// 构造。
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// 目录是否存在。
    #[must_use]
    pub fn exists(&self) -> bool {
        self.root.is_dir()
    }

    /// 各安全域子目录路径（不要求存在）。
    #[must_use]
    pub fn domain_dirs(&self) -> Vec<(RiskDomain, PathBuf)> {
        RiskDomain::all().into_iter().map(|d| (d, self.root.join(d.as_str()))).collect()
    }
}

impl LoadReport {
    /// 是否健康（无非法规则、无重复、无缺样本）。
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.invalid.is_empty() && self.duplicates.is_empty() && self.missing_samples.is_empty() && self.loaded > 0
    }

    /// 某安全域的规则数。
    #[must_use]
    pub fn count_domain(&self, domain: RiskDomain) -> usize {
        self.by_domain.get(domain.as_str()).copied().unwrap_or(0)
    }

    /// 转换为 `agf-core` 的汇总结构（供控制台与 CI 断言）。
    #[must_use]
    pub fn to_summary(&self) -> RulePackSummary {
        RulePackSummary {
            by_domain: self.by_domain.clone(),
            by_severity: self.by_severity.clone(),
            total: self.loaded,
            invalid: self.invalid.clone(),
            sources: vec![],
            generated_at: self.generated_at,
        }
    }
}

impl RulePack {
    /// 规则数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 按安全域筛选规则的索引。
    #[must_use]
    pub fn indices_of_domain(&self, domain: RiskDomain) -> Vec<usize> {
        self.rules.iter().enumerate().filter(|(_, r)| r.domain == domain).map(|(i, _)| i).collect()
    }

    /// 取编译后的匹配器。
    #[must_use]
    pub fn compiled(&self, index: usize) -> Option<&CompiledDetection> {
        self.compiled.get(index)
    }

    /// 规则与其匹配器的迭代。
    pub fn iter_compiled(&self) -> impl Iterator<Item = (&RuleDefinition, &CompiledDetection)> {
        self.rules.iter().zip(self.compiled.iter())
    }

    /// 计算某资产适用的规则（灰度判定）。
    #[must_use]
    pub fn applicable_to_asset(&self, asset_id: &agf_core::ids::Id) -> Vec<usize> {
        self.rules.iter().enumerate().filter(|(_, r)| r.applies_to_asset(asset_id)).map(|(i, _)| i).collect()
    }
}

impl RulePackLoader {
    /// 宽松模式（生产运行：坏规则跳过并记录）。
    #[must_use]
    pub fn lenient() -> Self {
        Self { strict: false }
    }

    /// 严格模式（CI/校验用：任何问题都返回错误）。
    #[must_use]
    pub fn strict() -> Self {
        Self { strict: true }
    }

    /// 从目录加载。
    ///
    /// # Errors
    /// 目录不存在；严格模式下存在非法/重复/缺样本规则。
    pub fn load_dir(&self, dir: &RulesDir) -> DomainResult<RulePack> {
        if !dir.exists() {
            return Err(DomainError::NotFound { entity: "rules_dir", id: dir.root.display().to_string() });
        }
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in
            walkdir::WalkDir::new(&dir.root).follow_links(false).sort_by_file_name().into_iter().filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if ext == "yaml" || ext == "yml" {
                files.push(entry.path().to_path_buf());
            }
        }
        info!(dir = %dir.root.display(), files = files.len(), "开始加载规则包");
        self.load_files(&files)
    }

    /// 从一批文件加载。
    ///
    /// # Errors
    /// 严格模式下存在问题时返回错误。
    pub fn load_files(&self, files: &[PathBuf]) -> DomainResult<RulePack> {
        let mut report = LoadReport { files_scanned: files.len(), ..Default::default() };
        let mut rules: Vec<RuleDefinition> = Vec::new();
        let mut seen_keys: BTreeMap<String, PathBuf> = BTreeMap::new();
        let mut hashes: Vec<String> = Vec::new();

        for path in files {
            let raw = match std::fs::read_to_string(path) {
                Ok(v) => v,
                Err(e) => {
                    report.invalid.insert(path.display().to_string(), vec![format!("文件不可读: {e}")]);
                    continue;
                }
            };
            let def: RuleDefinition = match serde_yaml::from_str(&raw) {
                Ok(v) => v,
                Err(e) => {
                    report.invalid.insert(path.display().to_string(), vec![format!("YAML 解析失败: {e}")]);
                    continue;
                }
            };

            if let Some(prev) = seen_keys.get(&def.key) {
                let msg = format!("规则键 {} 重复（已存在于 {}）", def.key, prev.display());
                report.duplicates.push(msg.clone());
                report.invalid.entry(path.display().to_string()).or_default().push(msg);
                continue;
            }

            if let Err(errs) = def.validate() {
                report.invalid.insert(path.display().to_string(), errs);
                continue;
            }
            if !def.samples.is_complete() {
                report.missing_samples.push(def.key.clone());
            }
            if let Err(e) = CompiledDetection::compile(&def.detection) {
                report.invalid.entry(path.display().to_string()).or_default().push(format!("检测条件编译失败: {e}"));
                continue;
            }
            if CompiledDetection::compile(&def.detection).map(|c| c.is_degraded()).unwrap_or(false) {
                report.degraded_semantic.push(def.key.clone());
            }

            *report.by_domain.entry(def.domain.as_str().to_string()).or_insert(0) += 1;
            *report.by_severity.entry(def.severity.as_str().to_string()).or_insert(0) += 1;
            hashes.push(def.content_hash());
            seen_keys.insert(def.key.clone(), path.clone());
            rules.push(def);
        }

        if self.strict && !report.invalid.is_empty() {
            let detail: Vec<String> =
                report.invalid.iter().flat_map(|(f, errs)| errs.iter().map(move |e| format!("{f}: {e}"))).collect();
            return Err(DomainError::Validation(format!(
                "严格模式：{} 条规则存在问题 → {}",
                detail.len(),
                detail.join("; ")
            )));
        }
        if self.strict && !report.missing_samples.is_empty() {
            return Err(DomainError::Validation(format!(
                "严格模式：以下规则缺少正负样本 → {}",
                report.missing_samples.join(", ")
            )));
        }

        // 编译（上面的编译只做校验，这里留存结果）
        let mut compiled = Vec::with_capacity(rules.len());
        for r in &rules {
            match CompiledDetection::compile(&r.detection) {
                Ok(c) => compiled.push(c),
                Err(e) => {
                    warn!(key = %r.key, error = %e, "规则编译失败（不应发生，已在前面校验）");
                    compiled.push(CompiledDetection::compile(&agf_core::rule::Detection::Keyword {
                        any: vec!["__never__".into()],
                    })?);
                }
            }
        }

        // Sort definitions and their compiled matchers together; sorting definitions alone
        // associates the wrong detector with each rule whenever file order differs from key order.
        let mut pairs: Vec<(RuleDefinition, CompiledDetection)> = rules.into_iter().zip(compiled).collect();
        pairs.sort_by(|a, b| (a.0.domain.as_str(), a.0.key.as_str()).cmp(&(b.0.domain.as_str(), b.0.key.as_str())));
        let (rules, compiled): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();

        hashes.sort();
        report.pack_fingerprint = content_hash(&hashes.join("\n"));
        report.loaded = rules.len();
        report.generated_at = Some(Timestamp::now());

        if !report.invalid.is_empty() {
            warn!(invalid = report.invalid.len(), "存在非法规则（已跳过，未纳入生效集合）");
        }
        info!(
            loaded = report.loaded,
            domains = report.by_domain.len(),
            fingerprint = %report.pack_fingerprint,
            "规则包加载完成"
        );
        Ok(RulePack { rules, compiled, report })
    }

    /// 由内存中的规则列表构造规则包（测试与内置规则用）。
    ///
    /// # Errors
    /// 规则非法时返回错误。
    pub fn load_inline(&self, rules: Vec<RuleDefinition>) -> DomainResult<RulePack> {
        let mut report = LoadReport::default();
        let mut kept: Vec<RuleDefinition> = Vec::new();
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut hashes = Vec::new();
        for def in rules {
            if let Some(n) = seen.get(&def.key) {
                report.duplicates.push(format!("规则键 {} 重复（第 {} 条）", def.key, n + 1));
                continue;
            }
            // 先登记"缺样本"（它同时是硬错误），再走其它校验，
            // 这样 `missing_samples` 在两种模式下都能被 CI 用于精确定位。
            if !def.samples.is_complete() {
                let msg = format!("规则 {} 缺少正负样本（须至少 1 正 1 负）", def.key);
                report.missing_samples.push(def.key.clone());
                report.invalid.entry(def.key.clone()).or_default().push(msg);
                continue;
            }
            if let Err(errs) = def.validate() {
                report.invalid.insert(def.key.clone(), errs);
                continue;
            }
            if CompiledDetection::compile(&def.detection).map(|c| c.is_degraded()).unwrap_or(false) {
                report.degraded_semantic.push(def.key.clone());
            }
            *report.by_domain.entry(def.domain.as_str().to_string()).or_insert(0) += 1;
            *report.by_severity.entry(def.severity.as_str().to_string()).or_insert(0) += 1;
            hashes.push(def.content_hash());
            seen.insert(def.key.clone(), kept.len());
            kept.push(def);
        }
        if self.strict
            && (!report.invalid.is_empty() || !report.missing_samples.is_empty() || !report.duplicates.is_empty())
        {
            return Err(DomainError::Validation(format!(
                "严格模式下规则集合不合法：非法 {} 条、缺样本 {} 条、重复键 {} 条",
                report.invalid.len(),
                report.missing_samples.len(),
                report.duplicates.len()
            )));
        }
        let mut compiled = Vec::with_capacity(kept.len());
        for r in &kept {
            compiled.push(CompiledDetection::compile(&r.detection)?);
        }
        hashes.sort();
        report.pack_fingerprint = content_hash(&hashes.join("\n"));
        report.loaded = kept.len();
        report.generated_at = Some(Timestamp::now());
        Ok(RulePack { rules: kept, compiled, report })
    }

    /// 校验单个规则文件（`agfctl rules verify` 用）。
    ///
    /// # Errors
    /// 文件不可读或 YAML 非法。
    pub fn verify_file(&self, path: &Path) -> DomainResult<Vec<String>> {
        let raw = std::fs::read_to_string(path)?;
        let def: RuleDefinition = serde_yaml::from_str(&raw)?;
        // 显式类型标注 + 全限定调用：避免与其它 `validate()`（trait 方法）产生歧义
        let mut problems: Vec<String> = match RuleDefinition::validate(&def) {
            Ok(()) => Vec::new(),
            Err(errs) => errs,
        };
        if let Err(e) = CompiledDetection::compile(&def.detection) {
            problems.push(format!("检测条件编译失败: {e}"));
        }
        debug!(path = %path.display(), problems = problems.len(), "规则文件校验");
        Ok(problems)
    }
}

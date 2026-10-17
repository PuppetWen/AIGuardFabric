//! 由 `redteam.rs` 拆分：`CaseLibrary`/`CaseLibraryStats`/`RedteamSimulator` 的实现（纯搬移，逻辑不变）。
use super::*;

impl CaseLibraryStats {
    /// 是否达到 §4.2 要求的 200+ 用例规模。
    #[must_use]
    pub fn meets_target(&self, target: usize) -> bool {
        self.total >= target
    }

    /// 公开 PoC 占比。
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn public_poc_ratio(&self) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        self.public_poc as f32 / self.total as f32
    }

    /// 某类别的用例数。
    #[must_use]
    pub fn count_category(&self, c: AttackCategory) -> usize {
        self.by_category.get(c.as_str()).copied().unwrap_or(0)
    }

    /// 是否健康（无非法用例且非空）。
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.total > 0 && self.invalid.is_empty()
    }
}

impl CaseLibrary {
    /// 从目录加载（递归读取 `*.yaml|yml`）。
    ///
    /// # Errors
    /// 目录不存在。
    pub fn load_dir(root: impl AsRef<Path>) -> DomainResult<Self> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(DomainError::NotFound { entity: "redteam_dir", id: root.display().to_string() });
        }
        let files: Vec<PathBuf> = walkdir::WalkDir::new(root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .filter(|p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                ext == "yaml" || ext == "yml"
            })
            .collect();
        info!(dir = %root.display(), files = files.len(), "加载红队用例库");
        Self::load_files(&files)
    }

    /// 从文件列表加载。
    ///
    /// # Errors
    /// 无（坏用例进入 `invalid`，不整体失败）。
    pub fn load_files(files: &[PathBuf]) -> DomainResult<Self> {
        let mut cases = Vec::new();
        let mut stats = CaseLibraryStats::default();
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut signals: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for path in files {
            let raw = match std::fs::read_to_string(path) {
                Ok(v) => v,
                Err(e) => {
                    stats.invalid.insert(path.display().to_string(), vec![format!("不可读: {e}")]);
                    continue;
                }
            };
            let case: RedteamCase = match serde_yaml::from_str(&raw) {
                Ok(v) => v,
                Err(e) => {
                    stats.invalid.insert(path.display().to_string(), vec![format!("YAML 解析失败: {e}")]);
                    continue;
                }
            };
            if let Some(prev) = seen.get(&case.key) {
                stats
                    .invalid
                    .entry(path.display().to_string())
                    .or_default()
                    .push(format!("用例键 {} 与 {prev} 重复", case.key));
                continue;
            }
            if let Err(errs) = case.validate() {
                stats.invalid.insert(path.display().to_string(), errs);
                continue;
            }
            seen.insert(case.key.clone(), path.display().to_string());
            *stats.by_category.entry(case.category.as_str().to_string()).or_insert(0) += 1;
            *stats.by_severity.entry(case.severity.as_str().to_string()).or_insert(0) += 1;
            *stats.by_mode.entry(case.mode.as_str().to_string()).or_insert(0) += 1;
            if case.public_poc {
                stats.public_poc += 1;
            }
            for s in &case.success_signals {
                signals.insert(s.clone());
            }
            cases.push(case);
        }
        stats.total = cases.len();
        stats.signals = signals.into_iter().collect();
        cases.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(Self { cases, stats })
    }

    /// 由内存用例构造（测试用）。
    #[must_use]
    pub fn from_cases(cases: Vec<RedteamCase>) -> Self {
        let mut stats = CaseLibraryStats { total: cases.len(), ..Default::default() };
        let mut signals = std::collections::BTreeSet::new();
        for c in &cases {
            *stats.by_category.entry(c.category.as_str().to_string()).or_insert(0) += 1;
            *stats.by_severity.entry(c.severity.as_str().to_string()).or_insert(0) += 1;
            *stats.by_mode.entry(c.mode.as_str().to_string()).or_insert(0) += 1;
            if c.public_poc {
                stats.public_poc += 1;
            }
            for s in &c.success_signals {
                signals.insert(s.clone());
            }
        }
        stats.signals = signals.into_iter().collect();
        let mut cases = cases;
        cases.sort_by(|a, b| a.key.cmp(&b.key));
        Self { cases, stats }
    }

    /// 用例列表。
    #[must_use]
    pub fn cases(&self) -> &[RedteamCase] {
        &self.cases
    }

    /// 统计。
    #[must_use]
    pub const fn stats(&self) -> &CaseLibraryStats {
        &self.stats
    }

    /// 按类别筛选。
    #[must_use]
    pub fn by_category(&self, category: AttackCategory) -> Vec<&RedteamCase> {
        self.cases.iter().filter(|c| c.category == category).collect()
    }

    /// 按标签筛选。
    #[must_use]
    pub fn by_tags(&self, tags: &[String]) -> Vec<&RedteamCase> {
        if tags.is_empty() {
            return self.cases.iter().collect();
        }
        self.cases.iter().filter(|c| c.tags.iter().any(|t| tags.iter().any(|x| x.eq_ignore_ascii_case(t)))).collect()
    }

    /// 按用例键选取。
    #[must_use]
    pub fn by_keys(&self, keys: &[String]) -> Vec<&RedteamCase> {
        if keys.is_empty() {
            return self.cases.iter().collect();
        }
        self.cases.iter().filter(|c| keys.iter().any(|k| k == &c.key)).collect()
    }

    /// 综合筛选（键 + 类别 + 标签 + 能力）。
    #[must_use]
    pub fn select(
        &self,
        keys: &[String],
        categories: &[AttackCategory],
        tags: &[String],
        capabilities: &[&str],
    ) -> Vec<&RedteamCase> {
        self.cases
            .iter()
            .filter(|c| keys.is_empty() || keys.iter().any(|k| k == &c.key))
            .filter(|c| categories.is_empty() || categories.contains(&c.category))
            .filter(|c| tags.is_empty() || c.tags.iter().any(|t| tags.iter().any(|x| x.eq_ignore_ascii_case(t))))
            .filter(|c| capabilities.is_empty() || c.applies_to_capabilities(capabilities))
            .collect()
    }

    /// 用例的确定性 id（便于与 finding/报告关联）。
    #[must_use]
    pub fn case_id(case: &RedteamCase) -> Id {
        deterministic_id(NS_REDTEAM_CASE, &case.key)
    }

    /// 是否覆盖全部攻击类别（覆盖率自检）。
    #[must_use]
    pub fn missing_categories(&self) -> Vec<AttackCategory> {
        AttackCategory::all().into_iter().filter(|c| self.stats.count_category(*c) == 0).collect()
    }
}

impl Default for RedteamSimulator {
    fn default() -> Self {
        Self::new("local-simulated-agent", 35)
    }
}

impl RedteamSimulator {
    /// 构造：`guard_strength` 表示目标防护强度（0=无防护，100=拦截全部）。
    #[must_use]
    pub fn new(name: impl Into<String>, guard_strength: u8) -> Self {
        Self {
            name: name.into(),
            asset_id: Id::new(),
            capabilities: vec![
                "prompt".into(),
                "model-output".into(),
                "tool-arguments".into(),
                "tool-result".into(),
                "mcp-request".into(),
                "mcp-response".into(),
                "document".into(),
                "config".into(),
                "tool-definition".into(),
            ],
            tools: vec![
                "read_file".into(),
                "write_file".into(),
                "execute_shell".into(),
                "http_request".into(),
                "search_kb".into(),
                "ingest_document".into(),
                "send_email".into(),
            ],
            guard_strength: guard_strength.min(100),
        }
    }

    /// 指定能力集合。
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// 指定可用工具集合。
    #[must_use]
    pub fn with_tools(mut self, tools: Vec<String>) -> Self {
        self.tools = tools;
        self
    }

    /// 防护强度。
    #[must_use]
    pub const fn guard_strength(&self) -> u8 {
        self.guard_strength
    }
}

#[async_trait]
impl TargetUnderTest for RedteamSimulator {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> Vec<String> {
        self.capabilities.clone()
    }

    fn asset_id(&self) -> Id {
        self.asset_id
    }

    fn is_simulated(&self) -> bool {
        true
    }

    async fn observe_case(&self, case: &RedteamCase) -> DomainResult<TargetObservation> {
        if !case.required_tools.iter().all(|tool| self.tools.contains(tool)) {
            return Ok(TargetObservation::inconclusive("Simulator lacks a required tool."));
        }
        if !case.applies_to_capabilities(&self.capabilities.iter().map(String::as_str).collect::<Vec<_>>()) {
            return Ok(TargetObservation::inconclusive("Case does not apply to the simulator capabilities."));
        }
        Ok(TargetObservation::evaluated(self.run_case(case).await?, vec![]))
    }

    async fn run_case(&self, case: &RedteamCase) -> DomainResult<Vec<String>> {
        // 缺少必要工具 → 攻击面不存在
        if !case.required_tools.is_empty() && !case.required_tools.iter().all(|t| self.tools.iter().any(|x| x == t)) {
            debug!(case = %case.key, "目标缺少必要工具，攻击面不存在");
            return Ok(Vec::new());
        }
        // 能力不匹配 → 不适用
        if !case.applies_to_capabilities(&self.capabilities.iter().map(String::as_str).collect::<Vec<_>>()) {
            return Ok(Vec::new());
        }
        // 确定性判定：hash(用例键 + 目标名) mod 100 < (100 - 防护强度) → 得逞
        let h = agf_core::secret::content_hash(&format!("{}|{}", case.key, self.name));
        let bucket = u8::from_str_radix(&h[..2], 16).unwrap_or(0) % 100;
        let threshold = 100_u8.saturating_sub(self.guard_strength);
        if bucket < threshold {
            // 得逞：至少返回一个信号；多信号用例按比例返回
            let mut signals: Vec<String> = case.success_signals.clone();
            if signals.len() > 1 {
                let keep = usize::from(bucket % u8::try_from(signals.len()).unwrap_or(1)) + 1;
                signals.truncate(keep);
            }
            Ok(signals)
        } else {
            Ok(Vec::new())
        }
    }
}

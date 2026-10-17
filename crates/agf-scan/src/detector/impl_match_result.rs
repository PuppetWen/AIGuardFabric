//! 由 `detector.rs` 拆分：`impl_MatchResult`/`safe_excerpt` 等 8 项（纯搬移，逻辑不变）。
use super::*;

impl MatchResult {
    /// 未命中。
    #[must_use]
    pub fn miss(note: impl Into<String>) -> Self {
        Self { hit: false, spans: Vec::new(), note: note.into(), degraded: false }
    }

    /// 命中。
    #[must_use]
    pub fn hit(note: impl Into<String>, spans: Vec<MatchSpan>) -> Self {
        Self { hit: true, spans, note: note.into(), degraded: false }
    }

    /// 标记为降级判定。
    #[must_use]
    pub fn degraded(mut self) -> Self {
        self.degraded = true;
        self
    }

    /// 命中片段数量。
    #[must_use]
    pub fn span_count(&self) -> usize {
        self.spans.len()
    }
}

/// 截断并脱敏命中片段。
#[must_use]
pub fn safe_excerpt(text: &str, start: usize, end: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let s = start.min(chars.len());
    let e = end.min(chars.len());
    let slice: String = chars[s..e.max(s)].iter().collect();
    let truncated: String = slice.chars().take(MAX_EXCERPT_CHARS).collect();
    let was_truncated = slice.chars().count() > MAX_EXCERPT_CHARS;
    // 凭据类命中直接打码，避免证据里二次泄露；打码后仍标注截断
    let body = if looks_like_secret(&truncated) { mask_default(&truncated) } else { truncated };
    if was_truncated { format!("{body}…") } else { body }
}

/// 粗略判断字符串是否像密钥（用于证据脱敏）。
#[must_use]
pub fn looks_like_secret(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 12 {
        return false;
    }
    let has_long_token =
        v.split_whitespace().any(|t| t.len() >= 20 && t.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)));
    let has_prefix =
        ["sk-", "sk_", "LTAI", "AKIA", "ASIA", "ghp_", "xox", "eyJ", "-----BEGIN"].iter().any(|p| v.contains(p));
    has_long_token || has_prefix
}

impl CompiledDetection {
    /// 编译一条检测条件。
    ///
    /// # Errors
    /// 正则非法、正则组数不合法等**编译期错误**会被返回（加载规则时即暴露）。
    pub fn compile(detection: &Detection) -> DomainResult<Self> {
        let mut degraded = false;
        let node = compile_node(detection, &mut degraded)?;
        Ok(Self { node, degraded_semantic: degraded })
    }

    /// 是否包含降级的语义检测。
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.degraded_semantic
    }

    /// 对文本执行匹配。
    #[must_use]
    pub fn matches(&self, text: &str) -> MatchResult {
        match_node(&self.node, text)
    }

    /// 匹配并把结果标记为降级（若本检测含语义降级）。
    #[must_use]
    pub fn matches_with_flags(&self, text: &str) -> MatchResult {
        let mut r = self.matches(text);
        if self.degraded_semantic {
            r = r.degraded();
        }
        r
    }
}

pub(crate) fn compile_node(detection: &Detection, degraded: &mut bool) -> DomainResult<CompiledNode> {
    Ok(match detection {
        Detection::Regex { pattern, case_insensitive, min_matches } => {
            let src = if *case_insensitive && !pattern.starts_with("(?i)") {
                format!("(?i){pattern}")
            } else {
                pattern.clone()
            };
            let re = Regex::new(&src).map_err(|e| DomainError::Parse(format!("正则非法 {src}: {e}")))?;
            if *min_matches == 0 {
                return Err(DomainError::Validation("正则规则的 min_matches 必须 ≥ 1".to_string()));
            }
            CompiledNode::Regex { re, min_matches: *min_matches }
        }
        Detection::Keyword { any } => {
            if any.is_empty() {
                return Err(DomainError::Validation("Keyword 规则的 any 不能为空".to_string()));
            }
            CompiledNode::Keyword { any: any.iter().map(|k| k.to_lowercase()).collect() }
        }
        Detection::KeywordAll { all } => {
            if all.is_empty() {
                return Err(DomainError::Validation("KeywordAll 规则的 all 不能为空".to_string()));
            }
            CompiledNode::KeywordAll { all: all.iter().map(|k| k.to_lowercase()).collect() }
        }
        Detection::Entropy { min_length, min_entropy } => {
            CompiledNode::Entropy { min_length: *min_length, min_entropy: *min_entropy }
        }
        Detection::EncodingBypass { trigger, decoded_contains } => CompiledNode::EncodingBypass {
            trigger: trigger.iter().map(|t| t.to_lowercase()).collect(),
            decoded_contains: decoded_contains.iter().map(|t| t.to_lowercase()).collect(),
        },
        Detection::Ast { dangerous_symbols, context_symbols } => CompiledNode::Ast {
            dangerous: dangerous_symbols.iter().map(|s| s.to_lowercase()).collect(),
            context: context_symbols.iter().map(|s| s.to_lowercase()).collect(),
        },
        Detection::Yara { rule_name, source } => {
            // yara-x 的编译在运行时进行；这里做一次语法自检以尽早暴露问题。
            if source.trim().is_empty() {
                return Err(DomainError::Validation("Yara 规则 source 不能为空".to_string()));
            }
            CompiledNode::Yara { rule_name: rule_name.clone(), source: source.clone() }
        }
        Detection::Semantic { intent, fallback_keywords, threshold } => {
            // 语义检测在离线环境一律走关键词近似，因此始终标记降级
            if fallback_keywords.is_empty() {
                warn!(intent = %intent, "语义检测缺少 fallback_keywords，离线环境下将无法判定");
            }
            *degraded = true;
            CompiledNode::Semantic {
                intent: intent.clone(),
                fallback_keywords: fallback_keywords.iter().map(|k| k.to_lowercase()).collect(),
                threshold: *threshold,
            }
        }
        Detection::All { of } => {
            let nodes = of.iter().map(|d| compile_node(d, degraded)).collect::<DomainResult<Vec<_>>>()?;
            CompiledNode::All(nodes)
        }
        Detection::Any { of } => {
            let nodes = of.iter().map(|d| compile_node(d, degraded)).collect::<DomainResult<Vec<_>>>()?;
            CompiledNode::Any(nodes)
        }
        Detection::Not { of } => CompiledNode::Not(Box::new(compile_node(of, degraded)?)),
        Detection::Threshold { of, min_hits } => {
            if *min_hits == 0 || *min_hits > of.len() {
                return Err(DomainError::Validation(format!(
                    "Threshold 的 min_hits 必须位于 1..={}，实际 {}",
                    of.len(),
                    min_hits
                )));
            }
            let nodes = of.iter().map(|d| compile_node(d, degraded)).collect::<DomainResult<Vec<_>>>()?;
            CompiledNode::Threshold { of: nodes, min_hits: *min_hits }
        }
    })
}

pub(crate) fn match_node(node: &CompiledNode, text: &str) -> MatchResult {
    match node {
        CompiledNode::Regex { re, min_matches } => {
            let spans: Vec<MatchSpan> = re
                .find_iter(text)
                .take(64)
                .map(|m| MatchSpan { start: m.start(), end: m.end(), excerpt: safe_excerpt(text, m.start(), m.end()) })
                .collect();
            if spans.len() >= *min_matches {
                MatchResult::hit(format!("正则命中 {} 次（阈值 {}）", spans.len(), min_matches), spans)
            } else {
                MatchResult::miss(format!("正则命中 {} 次，未达阈值 {}", spans.len(), min_matches))
            }
        }
        CompiledNode::Keyword { any } => {
            let lower = text.to_lowercase();
            let spans: Vec<MatchSpan> = any
                .iter()
                .filter_map(|k| lower.find(k).map(|i| MatchSpan { start: i, end: i + k.len(), excerpt: k.clone() }))
                .take(64)
                .collect();
            if spans.is_empty() {
                MatchResult::miss("未命中任何关键字")
            } else {
                MatchResult::hit(format!("命中关键字 {} 个", spans.len()), spans)
            }
        }
        CompiledNode::KeywordAll { all } => {
            let lower = text.to_lowercase();
            let missing: Vec<&str> = all.iter().filter(|k| !lower.contains(k.as_str())).map(String::as_str).collect();
            if missing.is_empty() {
                let spans: Vec<MatchSpan> = all
                    .iter()
                    .filter_map(|k| lower.find(k).map(|i| MatchSpan { start: i, end: i + k.len(), excerpt: k.clone() }))
                    .collect();
                MatchResult::hit(format!("全部 {} 个关键字均命中", all.len()), spans)
            } else {
                MatchResult::miss(format!("缺少关键字: {}", missing.join(",")))
            }
        }
        CompiledNode::Entropy { min_length, min_entropy } => {
            let candidate = highest_entropy_token(text, *min_length);
            match candidate {
                Some((token, entropy, start)) if entropy >= *min_entropy => MatchResult::hit(
                    format!("检出高熵串（{entropy:.2} bits/char ≥ {min_entropy}）"),
                    vec![MatchSpan { start, end: start + token.len(), excerpt: mask_default(&token) }],
                ),
                Some((_, entropy, _)) => {
                    MatchResult::miss(format!("最高熵 {entropy:.2} bits/char，未达阈值 {min_entropy}"))
                }
                None => MatchResult::miss(format!("没有长度 ≥ {min_length} 的候选串")),
            }
        }
        CompiledNode::EncodingBypass { trigger, decoded_contains } => {
            let lower = text.to_lowercase();
            let triggered = trigger.iter().any(|t| lower.contains(t));
            if !triggered {
                return MatchResult::miss("未出现编码指令触发词");
            }
            // 尝试识别文本中的 base64/十六进制编码块并解码检查
            for token in extract_encoded_tokens(text) {
                if let Some(decoded) = try_decode(&token.0, token.1) {
                    let dl = decoded.to_lowercase();
                    if let Some(hit_kw) = decoded_contains.iter().find(|k| dl.contains(k.as_str())) {
                        return MatchResult::hit(
                            format!("编码绕过：{} 形式载荷解码后包含 `{hit_kw}`", token.1),
                            vec![MatchSpan {
                                start: token.2,
                                end: token.2 + token.0.len(),
                                excerpt: mask_default(&token.0),
                            }],
                        );
                    }
                }
            }
            MatchResult::miss("出现编码指令但未解码出敏感内容")
        }
        CompiledNode::Ast { dangerous, context } => {
            let lower = text.to_lowercase();
            let hits: Vec<&String> = dangerous.iter().filter(|s| lower.contains(s.as_str())).collect();
            if hits.is_empty() {
                return MatchResult::miss("未出现危险符号");
            }
            if !context.is_empty() && !context.iter().any(|c| lower.contains(c.as_str())) {
                return MatchResult::miss("出现危险符号但缺少上下文符号");
            }
            let spans: Vec<MatchSpan> = hits
                .iter()
                .filter_map(|s| {
                    lower.find(s.as_str()).map(|i| MatchSpan { start: i, end: i + s.len(), excerpt: (*s).clone() })
                })
                .collect();
            MatchResult::hit(format!("命中 {} 个危险符号（命令/调用结构）", spans.len()), spans)
        }
        CompiledNode::Yara { rule_name, source } => {
            // 用 yara-x 编译并扫描；编译失败降级为"规则语法错误"的不命中并记录。
            match yara_x::compile(source.as_str()) {
                Ok(rules) => {
                    let mut scanner = yara_x::Scanner::new(&rules);
                    match scanner.scan(text.as_bytes()) {
                        Ok(results) => {
                            let matched: Vec<String> =
                                results.matching_rules().map(|r| r.identifier().to_string()).collect();
                            if matched.is_empty() {
                                MatchResult::miss(format!("YARA {rule_name} 未命中"))
                            } else {
                                MatchResult::hit(
                                    format!("YARA 命中规则: {}", matched.join(",")),
                                    vec![MatchSpan {
                                        start: 0,
                                        end: text.len().min(MAX_EXCERPT_CHARS),
                                        excerpt: safe_excerpt(text, 0, MAX_EXCERPT_CHARS),
                                    }],
                                )
                            }
                        }
                        Err(e) => MatchResult::miss(format!("YARA 扫描失败: {e}")),
                    }
                }
                Err(e) => MatchResult::miss(format!("YARA 规则编译失败: {e}")),
            }
        }
        CompiledNode::Semantic { intent, fallback_keywords, threshold } => {
            // 离线降级：用关键词近似语义意图。
            //
            // 评分口径（重要）：以"命中的不同关键词个数"为主体，而不是"命中比例"。
            // 原因：真实用例的 fallback_keywords 往往有 5~10 个同义表达，
            // 用户只会用到其中一个；按比例算会把"明确命中 1 个关键词"判为不命中（漏报）。
            // 因此：命中 1 个 → 0.5（对 0.7 阈值需 2 个），命中 ≥2 个 → 0.7 起。
            let lower = text.to_lowercase();
            let hits: Vec<&String> = fallback_keywords.iter().filter(|k| lower.contains(k.as_str())).collect();
            if fallback_keywords.is_empty() {
                return MatchResult::miss(format!("语义检测「{intent}」缺少离线关键词，无法判定")).degraded();
            }
            #[allow(clippy::cast_precision_loss)]
            let score = if hits.is_empty() { 0.0_f32 } else { (0.75 + 0.15 * (hits.len() - 1) as f32).min(1.0) };
            let effective = threshold.clamp(0.1, 0.95);
            if score >= effective {
                let spans: Vec<MatchSpan> = hits
                    .iter()
                    .filter_map(|k| {
                        lower.find(k.as_str()).map(|i| MatchSpan { start: i, end: i + k.len(), excerpt: (*k).clone() })
                    })
                    .collect();
                MatchResult::hit(
                    format!("语义近似命中（离线降级，得分 {score:.2} ≥ {effective:.2}，关键词 {} 个）", hits.len()),
                    spans,
                )
                .degraded()
            } else {
                MatchResult::miss(format!("语义近似得分 {score:.2} 低于阈值 {effective:.2}")).degraded()
            }
        }
        CompiledNode::All(nodes) => {
            let mut all_spans = Vec::new();
            let mut sub_notes: Vec<String> = Vec::with_capacity(nodes.len());
            for n in nodes {
                let r = match_node(n, text);
                if !r.hit {
                    return MatchResult::miss(format!("All 条件未全部满足: {}", r.note));
                }
                all_spans.extend(r.spans);
                sub_notes.push(r.note);
            }
            MatchResult::hit(format!("All 满足（{} 个子条件）: {}", nodes.len(), sub_notes.join(" | ")), all_spans)
        }
        CompiledNode::Any(nodes) => {
            let mut spans = Vec::new();
            let mut hits = 0_usize;
            for n in nodes {
                let r = match_node(n, text);
                if r.hit {
                    spans.extend(r.spans);
                    hits += 1;
                }
            }
            if hits == 0 {
                MatchResult::miss("Any 条件均未命中")
            } else {
                MatchResult::hit(format!("Any 命中 {hits} 个子条件"), spans)
            }
        }
        CompiledNode::Not(inner) => {
            let r = match_node(inner, text);
            if r.hit {
                MatchResult::miss(format!("Not 条件被命中（排除项）: {}", r.note))
            } else {
                MatchResult::hit("Not 条件满足（排除项未命中）", Vec::new())
            }
        }
        CompiledNode::Threshold { of, min_hits } => {
            let mut spans = Vec::new();
            let mut hits = 0;
            for n in of {
                let r = match_node(n, text);
                if r.hit {
                    hits += 1;
                    spans.extend(r.spans);
                }
            }
            if hits >= *min_hits {
                MatchResult::hit(format!("阈值满足（{hits}/{min_hits}）"), spans)
            } else {
                MatchResult::miss(format!("命中 {hits} 个子条件，未达阈值 {min_hits}"))
            }
        }
    }
}

/// 计算字符串的香农熵（bits/char）。
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn shannon_entropy(value: &str) -> f32 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = value.chars().count() as f32;
    let mut entropy = 0.0_f32;
    for count in counts.values() {
        let p = *count as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// 找出文本中熵最高的 token（满足最小长度）。
#[must_use]
pub fn highest_entropy_token(text: &str, min_length: usize) -> Option<(String, f32, usize)> {
    let mut best: Option<(String, f32, usize)> = None;
    let mut offset = 0_usize;
    for token in text.split_whitespace() {
        // 记录 token 在原文中的位置
        let start = text[offset..].find(token).map(|i| i + offset).unwrap_or(offset);
        offset = start + token.len();
        let trimmed: String = token.chars().filter(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(*c)).collect();
        if trimmed.chars().count() < min_length {
            continue;
        }
        let e = shannon_entropy(&trimmed);
        if best.as_ref().is_none_or(|(_, be, _)| e > *be) {
            best = Some((trimmed, e, start));
        }
    }
    best
}

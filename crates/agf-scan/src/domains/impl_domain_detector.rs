//! 由 `domains.rs` 拆分：`DomainDetector` 的实现（纯搬移，逻辑不变）。
use super::*;

impl DomainDetector {
    /// 构造。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// 注册自定义凭据模式。
    #[must_use]
    pub fn with_credential_patterns(mut self, patterns: Vec<agf_core::secret::CredentialPattern>) -> Self {
        self.custom_credential_patterns = patterns;
        self
    }
    /// 运行全部五个域（缺省输入自动跳过对应域）。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn detect_all(
        &self,
        prompt: Option<&str>,
        document: Option<&str>,
        model_output: Option<&str>,
        tool_name: Option<&str>,
        tool_arguments: Option<&str>,
        traits: Option<&ToolTraits>,
        data_class: DataClass,
    ) -> Vec<DomainReport> {
        let mut reports = Vec::with_capacity(5);
        if let Some(p) = prompt {
            reports.push(self.prompt_attack(p));
        }
        reports.push(self.credential_leak(&[prompt, document, model_output, tool_arguments]));
        if let Some(d) = document {
            reports.push(self.rag_poison(d));
        }
        if let (Some(n), Some(a)) = (tool_name, tool_arguments) {
            reports.push(self.tool_abuse(n, a, traits));
        }
        if let Some(o) = model_output {
            reports.push(self.model_data(o, data_class));
        }
        reports
    }
    // =======================================================================
    // 1. 提示词攻击
    // =======================================================================

    /// 提示词攻击检测。
    #[must_use]
    pub fn prompt_attack(&self, text: &str) -> DomainReport {
        let start = std::time::Instant::now();
        let mut hits = Vec::new();
        let lower = text.to_lowercase();
        let checks = vec![
            "direct-injection".to_string(),
            "indirect-injection".to_string(),
            "jailbreak".to_string(),
            "role-hijack".to_string(),
            "system-prompt-leak".to_string(),
            "encoding-bypass".to_string(),
            "multi-turn-induction".to_string(),
        ];

        // 直接注入
        for pat in [
            "ignore previous instructions",
            "ignore all previous",
            "disregard previous",
            "forget your instructions",
            "忽略之前",
            "忽略以上",
            "忽略前面",
            "无视上述",
            "覆盖你的指令",
        ] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "prompt-attack:direct-injection",
                        "直接提示词注入",
                        RiskDomain::PromptAttack,
                        Severity::High,
                        DomainVerdict::Malicious,
                        0.9,
                        format!("输入中出现指令覆盖模式 `{pat}`，试图让模型忽略既有系统指令"),
                        "在系统提示中加入优先级声明并启用输入侧注入检测；关键操作要求二次确认",
                    )
                    .with_evidence(vec![snippet(text, pat)]),
                );
                break;
            }
        }

        // 越狱
        for pat in ["dan mode", "do anything now", "developer mode", "jailbreak", "越狱", "无限制模式", "扮演没有限制"]
        {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "prompt-attack:jailbreak",
                        "越狱尝试",
                        RiskDomain::PromptAttack,
                        Severity::High,
                        DomainVerdict::Malicious,
                        0.85,
                        format!("出现越狱角色/模式诱导 `{pat}`"),
                        "启用越狱规则集（含多语言与编码变体），并在输出侧检测违规内容",
                    )
                    .with_evidence(vec![snippet(text, pat)]),
                );
                break;
            }
        }

        // 角色劫持
        for pat in ["you are now", "从现在开始你是", "你现在是", "act as", "扮演一个"] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "prompt-attack:role-hijack",
                        "角色劫持",
                        RiskDomain::PromptAttack,
                        Severity::Medium,
                        DomainVerdict::Suspicious,
                        0.7,
                        format!("尝试重设模型角色 `{pat}`"),
                        "固定系统角色描述并在每轮对话重申；拒绝角色替换类请求",
                    )
                    .with_evidence(vec![snippet(text, pat)]),
                );
                break;
            }
        }

        // 系统提示词泄露
        for pat in [
            "system prompt",
            "系统提示词",
            "系统提示",
            "initial instructions",
            "your instructions",
            "repeat the above",
            "输出你的设定",
        ] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "prompt-attack:system-prompt-leak",
                        "系统提示词泄露探测",
                        RiskDomain::PromptAttack,
                        Severity::High,
                        DomainVerdict::Suspicious,
                        0.75,
                        format!("尝试套取系统提示词 `{pat}`"),
                        "禁止在提示词中放入密钥与内部规则；输出侧对系统提示词做指纹检测",
                    )
                    .with_evidence(vec![snippet(text, pat)]),
                );
                break;
            }
        }

        // 编码绕过
        if let Some(detail) = detect_encoding_bypass(text) {
            hits.push(
                DomainHit::new(
                    "prompt-attack:encoding-bypass",
                    "编码绕过载荷",
                    RiskDomain::PromptAttack,
                    Severity::High,
                    DomainVerdict::Malicious,
                    0.8,
                    detail.clone(),
                    "在入口统一做编码归一化（base64/hex/unicode/零宽字符）后再检测",
                )
                .with_evidence(vec![detail]),
            );
        }

        // 多轮诱导
        for pat in ["上一条消息", "previous message", "继续上面的", "as we discussed", "第 1 步"] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "prompt-attack:multi-turn-induction",
                        "多轮渐进诱导",
                        RiskDomain::PromptAttack,
                        Severity::Low,
                        DomainVerdict::Suspicious,
                        0.5,
                        format!("出现多轮诱导话术 `{pat}`，需结合会话历史判定"),
                        "启用会话级累计风险评分，跨轮次聚合而非单条判定",
                    )
                    .with_evidence(vec![snippet(text, pat)]),
                );
                break;
            }
        }

        // 间接注入（伪造会话角色标记）
        for pat in ["</system>", "<|im_start|>", "###system", "[system]", "assistant:", "<instructions>"] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "prompt-attack:indirect-injection",
                        "间接提示词注入（角色标记伪造）",
                        RiskDomain::PromptAttack,
                        Severity::Critical,
                        DomainVerdict::Malicious,
                        0.88,
                        format!("文本中出现伪造的会话角色标记 `{pat}`，常来自被投毒的文档或工具返回"),
                        "对工具返回与检索内容做净化（剥离角色标记），并标注内容来源",
                    )
                    .with_evidence(vec![snippet(text, pat)]),
                );
                break;
            }
        }

        let mut report = DomainReport::from_hits(RiskDomain::PromptAttack, hits, checks);
        report.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        report
    }
    // =======================================================================
    // 2. 凭证泄露
    // =======================================================================

    /// 凭证泄露检测（复用 `agf-core` 的凭据识别 + 自定义模式）。
    #[must_use]
    pub fn credential_leak(&self, texts: &[Option<&str>]) -> DomainReport {
        let start = std::time::Instant::now();
        let checks = vec![
            "api-key".to_string(),
            "cloud-aksk".to_string(),
            "jwt-and-token".to_string(),
            "private-key".to_string(),
            "connection-string".to_string(),
            "kv-assignment".to_string(),
        ];
        let mut hits = Vec::new();
        let mut seen_patterns: BTreeSet<String> = BTreeSet::new();

        for (idx, text) in texts.iter().enumerate() {
            let Some(t) = text else { continue };
            let matches: Vec<CredentialMatch> = scan_credentials(t, &self.custom_credential_patterns);
            for m in matches {
                if !seen_patterns.insert(m.pattern.clone()) {
                    continue;
                }
                hits.push(
                    DomainHit::new(
                        format!("credential-leak:{}", m.pattern),
                        format!("疑似凭据泄露（{}）", m.pattern),
                        RiskDomain::CredentialLeak,
                        m.kind.impact(),
                        if m.confidence >= 0.9 { DomainVerdict::Malicious } else { DomainVerdict::Suspicious },
                        m.confidence,
                        format!(
                            "在输入源 #{} 中发现疑似 {:?} 类型凭据（长度 {}），掩码 {}",
                            idx + 1,
                            m.kind,
                            m.length,
                            m.masked
                        ),
                        "立即轮换该凭据；在入口对提示词/日志/工具参数做凭据脱敏；禁止把密钥写入提示词",
                    )
                    .with_evidence(vec![
                        format!("掩码: {}", m.masked),
                        format!("位置: 源 #{} 偏移 {}", idx + 1, m.start),
                    ]),
                );
            }
        }
        let mut report = DomainReport::from_hits(RiskDomain::CredentialLeak, hits, checks);
        report.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        report
    }
    // =======================================================================
    // 3. RAG 投毒
    // =======================================================================

    /// RAG 投毒检测（知识库文档 / 检索片段）。
    #[must_use]
    pub fn rag_poison(&self, document: &str) -> DomainReport {
        let start = std::time::Instant::now();
        let checks = vec![
            "instruction-in-document".to_string(),
            "hidden-instruction".to_string(),
            "context-conflict".to_string(),
            "retrieval-scope".to_string(),
        ];
        let mut hits = Vec::new();
        let lower = document.to_lowercase();

        // 文档中的指令性内容
        for pat in [
            "ignore the above",
            "ignore previous",
            "忽略以上",
            "忽略正文",
            "as an ai, you must",
            "your new instruction",
            "新的指令",
            "请务必执行以下操作",
        ] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "rag-poison:instruction-in-document",
                        "知识库文档内嵌指令（投毒）",
                        RiskDomain::RagPoison,
                        Severity::Critical,
                        DomainVerdict::Malicious,
                        0.9,
                        format!("文档正文中出现面向模型的指令 `{pat}`，属于典型 RAG 投毒手法"),
                        "知识库入库前做指令性内容扫描；检索结果标注来源并要求模型忽略其中的指令",
                    )
                    .with_evidence(vec![snippet(document, pat)]),
                );
                break;
            }
        }

        // 隐藏指令（不可见字符）
        let invisible = count_invisible(document);
        if invisible > 0 {
            hits.push(
                DomainHit::new(
                    "rag-poison:hidden-instruction",
                    "文档隐藏指令（不可见字符）",
                    RiskDomain::RagPoison,
                    Severity::High,
                    DomainVerdict::Malicious,
                    0.85,
                    format!("文档含 {invisible} 个不可见字符，常用于隐藏指令绕过人工审阅"),
                    "入库前剥离不可见字符；对文档做纯文本归一化后再存向量库",
                )
                .with_evidence(vec![format!("不可见字符: {invisible}")]),
            );
        }

        // 隐藏指令（HTML 注释 / 隐藏样式）
        for pat in ["<!--", "display:none", "font-size:0", "color:#fff", "visibility:hidden", "opacity:0"] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "rag-poison:hidden-instruction",
                        "文档隐藏指令（不可见样式/注释）",
                        RiskDomain::RagPoison,
                        Severity::High,
                        DomainVerdict::Malicious,
                        0.8,
                        format!("文档包含隐藏标记 `{pat}`，可能在渲染后不可见但被模型读取"),
                        "入库前剥离 HTML 注释与隐藏样式；仅对纯文本做分块与向量化",
                    )
                    .with_evidence(vec![snippet(document, pat)]),
                );
                break;
            }
        }

        // 上下文冲突（分块召回污染）
        if let Some(detail) = detect_context_conflict(document) {
            hits.push(DomainHit::new(
                "rag-poison:context-conflict",
                "上下文冲突（分块召回污染）",
                RiskDomain::RagPoison,
                Severity::Medium,
                DomainVerdict::Suspicious,
                0.65,
                detail,
                "对同一主题的多个召回片段做一致性校验；冲突时降低置信度并提示人工确认",
            ));
        }

        // 越权内容特征（密级标记）
        for pat in ["internal only", "机密", "confidential", "禁止外传", "内部资料"] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "rag-poison:retrieval-scope",
                        "知识库收录内部/机密文档",
                        RiskDomain::RagPoison,
                        Severity::Medium,
                        DomainVerdict::Suspicious,
                        0.6,
                        format!("文档含密级标记 `{pat}`，需确认是否应进入可被外部模型检索的知识库"),
                        "按数据分级划分知识库；机密文档只允许本地模型检索",
                    )
                    .with_evidence(vec![snippet(document, pat)]),
                );
                break;
            }
        }

        let mut report = DomainReport::from_hits(RiskDomain::RagPoison, hits, checks);
        report.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        report
    }
}

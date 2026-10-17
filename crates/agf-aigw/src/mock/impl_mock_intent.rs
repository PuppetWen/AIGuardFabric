//! 由 `mock.rs` 拆分：`impl_MockIntent`/`impl_RecordedFixture` 等 8 项（纯搬移，逻辑不变）。
use super::*;

impl MockIntent {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AlertTriage => "alert-triage",
            Self::AttackChainSummary => "attack-chain-summary",
            Self::Report => "report",
            Self::Echo => "echo",
        }
    }

    /// 通过关键词识别意图（**纯函数，可单测**）。
    ///
    /// 优先级：研判 > 报告 > 攻击链路 > 兜底。
    /// 顺序刻意如此：真实场景里"研判告警并生成报告"的提示词会同时命中两组词，
    /// 此时更具体的"研判"应当胜出，避免把结构化判定降级成报告模板。
    #[must_use]
    pub fn detect(prompt: &str) -> Self {
        let lower = prompt.to_lowercase();
        const TRIAGE: [&str; 10] = [
            "研判",
            "分析告警",
            "告警分析",
            "判定",
            "是否恶意",
            "triage",
            "verdict",
            "恶意还是",
            "风险判定",
            "二次研判",
        ];
        const REPORT: [&str; 8] = ["报告", "复盘", "report", "总结报告", "生成报告", "周报", "月报", "汇报"];
        const CHAIN: [&str; 8] =
            ["攻击链路", "攻击链", "链路总结", "attack chain", "横向移动", "kill chain", "攻击路径", "入侵路径"];

        if TRIAGE.iter().any(|k| lower.contains(k)) {
            return Self::AlertTriage;
        }
        if REPORT.iter().any(|k| lower.contains(k)) {
            return Self::Report;
        }
        if CHAIN.iter().any(|k| lower.contains(k)) {
            return Self::AttackChainSummary;
        }
        Self::Echo
    }
}

impl RecordedFixture {
    /// 构造。
    #[must_use]
    pub fn new(fingerprint: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            content: content.into(),
            model: MOCK_MODEL.to_string(),
            usage: None,
            finish_reason: Some(FinishReason::Stop),
        }
    }

    /// 从 JSON 数组载入 fixtures；单条损坏时跳过（**不 panic**）。
    #[must_use]
    pub fn parse_all(raw: &str) -> Vec<Self> {
        match serde_json::from_str::<Vec<Self>>(raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "fixtures 解析失败，按空集处理");
                Vec::new()
            }
        }
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProvider {
    /// 新建（无 fixtures）。
    #[must_use]
    pub fn new() -> Self {
        Self { model: MOCK_MODEL.to_string(), fixtures: Arc::new(BTreeMap::new()), synthetic_latency_ms: 1 }
    }

    /// 指定模型名。
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// 注入 fixtures。
    #[must_use]
    pub fn with_fixtures(mut self, fixtures: Vec<RecordedFixture>) -> Self {
        self.fixtures = Arc::new(fixtures.into_iter().map(|f| (f.fingerprint.clone(), f)).collect());
        self
    }

    /// 从 fixtures 目录加载（目录不存在时返回空集，**不报错**）。
    ///
    /// 目录约定：`tests/fixtures/mock_responses/*.json`，每个文件要么是
    /// [`RecordedFixture`] 数组，要么是单个对象。
    #[must_use]
    pub fn load_fixtures_from_dir(dir: &std::path::Path) -> Vec<RecordedFixture> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<RecordedFixture> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Ok(list) = serde_json::from_str::<Vec<RecordedFixture>>(&raw) {
                out.extend(list);
            } else if let Ok(one) = serde_json::from_str::<RecordedFixture>(&raw) {
                out.push(one);
            } else {
                tracing::warn!(path = %path.display(), "fixture 文件格式不合法，已跳过");
            }
        }
        out
    }

    /// 加载默认 fixtures 目录（相对当前工作目录；不存在则为空）。
    #[must_use]
    pub fn load_default_fixtures() -> Vec<RecordedFixture> {
        Self::load_fixtures_from_dir(std::path::Path::new(FIXTURE_DIR))
    }

    /// fixture 数量。
    #[must_use]
    pub fn fixture_count(&self) -> usize {
        self.fixtures.len()
    }

    /// 合成回复（**确定性**，不依赖随机数）。
    #[must_use]
    pub fn synthesize(&self, req: &ChatRequest) -> ChatResponse {
        let fingerprint = req.fingerprint();
        if let Some(fixture) = self.fixtures.get(&fingerprint) {
            let (content, truncated) = limit_output(&fixture.content, req.max_tokens);
            let mut usage = fixture.usage.unwrap_or_else(|| self.estimate_usage(req, &content));
            if truncated {
                usage.completion_tokens = crate::wire::estimate_text_tokens(&content).ceil() as u64;
            }
            return ChatResponse {
                id: format!("mock-{}", &fingerprint[..16.min(fingerprint.len())]),
                model: if fixture.model.is_empty() { self.model.clone() } else { fixture.model.clone() },
                message: ChatMessage::assistant(content),
                finish_reason: if truncated {
                    FinishReason::Length
                } else {
                    fixture.finish_reason.unwrap_or(FinishReason::Stop)
                },
                usage,
                raw: Some(json!({"mock": true, "source": "fixture", "fingerprint": fingerprint})),
            };
        }

        let prompt = req
            .messages
            .iter()
            .filter(|m| m.role != crate::wire::Role::System)
            .map(|m| m.content.as_plain_text())
            .collect::<Vec<_>>()
            .join("\n");
        let intent = MockIntent::detect(&prompt);
        let (content, truncated) = limit_output(&self.render_intent(intent, req, &prompt), req.max_tokens);
        let usage = self.estimate_usage(req, &content);
        ChatResponse {
            id: format!("mock-{}", &fingerprint[..16.min(fingerprint.len())]),
            model: self.model.clone(),
            message: ChatMessage::assistant(content),
            finish_reason: if truncated { FinishReason::Length } else { FinishReason::Stop },
            usage,
            raw: Some(json!({
                "mock": true,
                "source": "synthesized",
                "intent": intent.as_str(),
                "fingerprint": fingerprint,
            })),
        }
    }

    /// 渲染指定意图的确定性回复。
    #[must_use]
    pub fn render_intent(&self, intent: MockIntent, req: &ChatRequest, prompt: &str) -> String {
        match intent {
            MockIntent::AlertTriage => render_alert_triage(req, prompt),
            MockIntent::AttackChainSummary => render_attack_chain(req),
            MockIntent::Report => render_report(req),
            MockIntent::Echo => render_echo(req, prompt),
        }
    }

    /// 估算用量（Mock 不产生真实计费，但仍要给出一致的计量数字）。
    #[must_use]
    pub fn estimate_usage(&self, req: &ChatRequest, completion: &str) -> Usage {
        Usage::new(req.estimate_prompt_tokens(), crate::wire::estimate_text_tokens(completion).ceil() as u64, 0)
    }

    /// 合成流式分片（按固定长度切分，末尾追加 usage 分片）。
    #[must_use]
    pub fn synthesize_stream(&self, req: &ChatRequest) -> Vec<StreamChunk> {
        let response = self.synthesize(req);
        let text = response.text_content();
        let chars: Vec<char> = text.chars().collect();
        let mut chunks: Vec<StreamChunk> = Vec::new();
        let mut role_chunk = StreamChunk {
            delta: ChatDelta { role: Some(crate::wire::Role::Assistant), ..ChatDelta::default() },
            finish_reason: None,
            usage: None,
            anthropic_event: None,
        };
        role_chunk.delta.content = String::new();
        chunks.push(role_chunk);
        for window in chars.chunks(24) {
            chunks.push(StreamChunk::text(window.iter().collect::<String>()));
        }
        chunks.push(StreamChunk::finished(response.finish_reason, Some(response.usage)));
        chunks
    }
}

fn limit_output(text: &str, max_tokens: Option<u32>) -> (String, bool) {
    let Some(limit) = max_tokens else { return (text.to_string(), false) };
    let mut output = String::new();
    let (mut latin, mut cjk, mut other) = (0_u64, 0_u64, 0_u64);
    for ch in text.chars() {
        if ch.is_ascii() {
            latin += 1;
        } else if crate::wire::is_cjk(ch) {
            cjk += 1;
        } else {
            other += 1;
        }
        let estimated = latin as f64 / 4.0 + cjk as f64 / 1.5 + other as f64 / 2.0;
        if estimated.ceil() > f64::from(limit) {
            return (output, true);
        }
        output.push(ch);
    }
    (output, false)
}

/// 告警研判：输出结构化 JSON 判定。
///
/// 判定逻辑（**确定性启发式**，用于离线演示，不代表真实模型能力）：
/// - 命中高危信号词（暴力破解/webshell/横向/外传/提权/挖矿/凭据泄露…）→ `malicious`；
/// - 命中中危信号词（异常登录/扫描/可疑/失败居多…）→ `suspicious`；
/// - 否则 → `benign`；
/// - 置信度按命中数量线性提升，上限 0.95。
pub(crate) fn render_alert_triage(req: &ChatRequest, prompt: &str) -> String {
    const HIGH: [&str; 12] = [
        "暴力破解",
        "webshell",
        "横向移动",
        "数据外传",
        "提权",
        "挖矿",
        "凭据泄露",
        "勒索",
        "反弹 shell",
        "brute force",
        "exfiltration",
        "ransomware",
    ];
    const MEDIUM: [&str; 10] =
        ["异常登录", "扫描", "可疑", "失败", "弱口令", "越权", "path traversal", "scan", "suspicious", "anomaly"];

    let lower = prompt.to_lowercase();
    let high_hits: Vec<&str> = HIGH.iter().copied().filter(|k| lower.contains(*k)).collect();
    let medium_hits: Vec<&str> = MEDIUM.iter().copied().filter(|k| lower.contains(*k)).collect();

    let (verdict, base) = if !high_hits.is_empty() {
        ("malicious", 0.72_f64)
    } else if !medium_hits.is_empty() {
        ("suspicious", 0.45_f64)
    } else {
        ("benign", 0.20_f64)
    };
    let confidence = (base + 0.05 * (high_hits.len() + medium_hits.len()) as f64).min(0.95);
    let mut cited: Vec<String> = high_hits.iter().map(|k| format!("signal:{k}")).collect();
    cited.extend(medium_hits.iter().map(|k| format!("signal:{k}")));
    if cited.is_empty() {
        cited.push("signal:none".to_string());
    }

    let rationale = match verdict {
        "malicious" => format!(
            "输入中出现 {} 个高危特征（{}），符合已知攻击链的行为特征，判定为恶意。",
            high_hits.len(),
            high_hits.join("、")
        ),
        "suspicious" => format!(
            "仅命中 {} 个中危特征（{}），证据不足以直接定性，建议保留样本并补充上下文。",
            medium_hits.len(),
            medium_hits.join("、")
        ),
        _ => "未发现已知攻击特征，且无高危信号，按良性处理。".to_string(),
    };

    let payload = json!({
        "verdict": verdict,
        "confidence": (confidence * 100.0).round() / 100.0,
        "rationale": rationale,
        "cited_evidence": cited,
        "model": MOCK_MODEL,
        "mock": true,
        "request_fingerprint_prefix": &req.fingerprint()[..16.min(req.fingerprint().len())],
    });
    // Mock 输出 JSON 文本（调用方按 response_format 自行解析）
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}

/// 攻击链路总结：输出分阶段清单。
pub(crate) fn render_attack_chain(req: &ChatRequest) -> String {
    let mut out = String::new();
    out.push_str("## 攻击链路总结（Mock 离线合成）\n\n");
    out.push_str("| 阶段 | 观察到的动作 | 证据引用 |\n|---|---|---|\n");
    out.push_str("| 1 初始访问 | 对外暴露的登录口被高频尝试 | evidence:auth-failure-burst |\n");
    out.push_str("| 2 执行 | 出现可疑子进程与下载行为 | evidence:process-tree |\n");
    out.push_str("| 3 持久化 | 计划任务/服务被写入 | evidence:persistence-item |\n");
    out.push_str("| 4 横向移动 | 内网 SMB/SSH 扇出连接 | evidence:lateral-fanout |\n");
    out.push_str("| 5 数据外传 | 大流量外联至陌生域名 | evidence:egress-volume |\n\n");
    out.push_str("> 本结论由 `MockProvider` 合成，用于离线演示；接入真实模型后由模型给出。\n");
    out.push_str(&format!("> 关联请求指纹: `{}`\n", &req.fingerprint()[..16.min(req.fingerprint().len())]));
    out
}

/// 报告生成：输出 Markdown 四节。
pub(crate) fn render_report(req: &ChatRequest) -> String {
    let mut out = String::new();
    out.push_str("## 摘要\n\n");
    out.push_str("本报告由 AIGuardFabric 大模型统一网关（Mock 模型）离线生成，覆盖本次分析周期内的安全态势。\n\n");
    out.push_str("## 关键发现\n\n");
    out.push_str("1. 存在 1 条高危攻击链（初始访问 → 执行 → 持久化 → 横向移动 → 数据外传）；\n");
    out.push_str("2. 检出 2 个硬编码模型 API Key（`sk-` / `LTAI` 模式），建议立即轮换；\n");
    out.push_str("3. 3 个 MCP Server 存在过度授权（放开全部主体且具备 shell 执行能力）。\n\n");
    out.push_str("## 影响\n\n");
    out.push_str("- 受影响资产：模型端点 2 个、Agent 3 个、MCP Server 3 个；\n");
    out.push_str(
        "- 数据风险：存在向外部大模型传输 `confidential` 级数据的路径，已由路由层「数据不出域」约束拦截。\n\n",
    );
    out.push_str("## 处置建议\n\n");
    out.push_str("1. 轮换泄露凭据并回收历史会话令牌；\n");
    out.push_str("2. 为受限数据强制绑定本地部署端点（`local_deployment = true`）；\n");
    out.push_str("3. 收敛 MCP 工具授权范围，补充出网域名白名单；\n");
    out.push_str("4. 将本次检出的规则加入回归用例，纳入每日巡检。\n\n");
    out.push_str(&format!("> 关联请求指纹: `{}`\n", &req.fingerprint()[..16.min(req.fingerprint().len())]));
    out
}

/// 兜底摘要：确定性回显。
pub(crate) fn render_echo(req: &ChatRequest, prompt: &str) -> String {
    let preview: String = prompt.chars().take(120).collect();
    let tools: Vec<&str> = req.tools.iter().map(|t: &ToolDefinition| t.name.as_str()).collect();
    let system_len = req.system_prompt().map_or(0, |s| s.chars().count());
    format!(
        "【Mock 模型】已收到请求（未配置真实模型凭据，按 §11 降级不报错）。\n\
         - 模型: {}\n\
         - 消息数: {}\n\
         - 系统提示词长度: {system_len} 字符\n\
         - 可用工具: {}\n\
         - 输入摘要: {preview}\n\
         - 请求指纹: {}\n\
         提示：配置任一厂商 API Key，或设置 `AGF_MOCK_MODE=0` 后接入真实端点，即可获得模型真实推理结果。",
        req.model,
        req.messages.len(),
        if tools.is_empty() { "无".to_string() } else { tools.join(", ") },
        &req.fingerprint()[..16.min(req.fingerprint().len())],
    )
}

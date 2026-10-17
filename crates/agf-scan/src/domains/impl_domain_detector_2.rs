//! 由 `domains.rs` 拆分：`DomainDetector` 的实现（纯搬移，逻辑不变）。
use super::*;

impl DomainDetector {
    // =======================================================================
    // 4. 工具与权限滥用
    // =======================================================================

    /// 工具滥用检测（工具名 + 参数 + 能力画像）。
    #[must_use]
    pub fn tool_abuse(&self, tool_name: &str, arguments: &str, traits: Option<&ToolTraits>) -> DomainReport {
        let start = std::time::Instant::now();
        let checks = vec![
            "destructive-command".to_string(),
            "command-injection".to_string(),
            "path-traversal".to_string(),
            "sensitive-file".to_string(),
            "ssrf".to_string(),
            "capability-combination".to_string(),
            "overbroad-scope".to_string(),
        ];
        let mut hits = Vec::new();
        // 参数统一小写；路径分隔符归一化为 `/`，一次覆盖 *nix 与 Windows 写法
        let lower = arguments.to_lowercase();
        let normalized = lower.replace('\\', "/");

        // 破坏性命令
        for pat in [
            "rm -rf /",
            "rm -rf ~",
            "mkfs",
            "dd if=",
            ":(){:|:&};:",
            "shutdown -h",
            "format c:",
            "del /f /s /q c:",
            "/dev/sda",
        ] {
            if lower.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "tool-abuse:destructive-command",
                        "破坏性命令调用",
                        RiskDomain::ToolAbuse,
                        Severity::Critical,
                        DomainVerdict::Malicious,
                        0.95,
                        format!("工具 `{tool_name}` 的参数包含破坏性命令片段 `{pat}`"),
                        "启用命令级黑名单拦截；对写/删类工具要求人工审批",
                    )
                    .with_evidence(vec![snippet(arguments, pat)]),
                );
                break;
            }
        }

        // 命令注入（管道下载执行）
        for pat in ["curl", "wget"] {
            let piped = lower.contains("| sh")
                || lower.contains("| bash")
                || lower.contains("|sh")
                || lower.contains("|bash")
                || lower.contains("-o- |")
                || lower.contains("invoke-expression");
            if lower.contains(pat) && piped {
                hits.push(
                    DomainHit::new(
                        "tool-abuse:command-injection",
                        "管道下载执行（curl|sh）",
                        RiskDomain::ToolAbuse,
                        Severity::Critical,
                        DomainVerdict::Malicious,
                        0.95,
                        format!("工具 `{tool_name}` 参数呈现 `{pat} … | sh` 形式的任意代码执行"),
                        "阻断管道执行模式；工具应使用参数化接口而非拼接 shell 字符串",
                    )
                    .with_evidence(vec![snippet(arguments, pat)]),
                );
                break;
            }
        }

        // 路径穿越
        if normalized.contains("../") || normalized.contains("%2e%2e") {
            hits.push(
                DomainHit::new(
                    "tool-abuse:path-traversal",
                    "路径穿越",
                    RiskDomain::ToolAbuse,
                    Severity::High,
                    DomainVerdict::Malicious,
                    0.85,
                    format!("工具 `{tool_name}` 参数包含 `..` 序列，可能读取授权目录之外的文件"),
                    "对路径参数做规范化并强制前缀白名单校验（注意符号链接与 Windows 短名）",
                )
                .with_evidence(vec![snippet(arguments, "..")]),
            );
        }

        // 敏感文件访问（归一化到 `/` 后匹配）
        for pat in [
            "/etc/shadow",
            "/etc/passwd",
            "system32/config",
            "sam/sam",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".aws/credentials",
            ".docker/config.json",
            ".kube/config",
            "kubeconfig",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".git-credentials",
        ] {
            if normalized.contains(pat) {
                hits.push(
                    DomainHit::new(
                        "tool-abuse:sensitive-file",
                        "访问敏感文件",
                        RiskDomain::ToolAbuse,
                        Severity::High,
                        DomainVerdict::Malicious,
                        0.88,
                        format!("工具 `{tool_name}` 试图访问敏感路径 `{pat}`"),
                        "文件路径白名单：默认拒绝，仅放行明确授权目录",
                    )
                    .with_evidence(vec![snippet(arguments, pat)]),
                );
                break;
            }
        }

        // SSRF（内网地址 + 出网能力）
        if let Some(target) = detect_internal_target(arguments) {
            if traits.is_none_or(|t| t.network_egress) {
                hits.push(
                    DomainHit::new(
                        "tool-abuse:ssrf",
                        "SSRF 访问内网目标",
                        RiskDomain::ToolAbuse,
                        Severity::High,
                        DomainVerdict::Malicious,
                        0.8,
                        format!("工具 `{tool_name}` 参数指向内网/环回地址 `{target}`，可用于探测内网服务"),
                        "对出网工具做域名与 IP 白名单；解析后的实际连接地址必须二次校验（防 DNS Rebinding）",
                    )
                    .with_evidence(vec![format!("目标: {target}")]),
                );
            }
        }

        // 能力组合风险
        if let Some(t) = traits {
            if t.is_exfil_capable() {
                hits.push(DomainHit::new(
                    "tool-abuse:capability-combination",
                    "具备数据外传能力组合（读文件 + 出网）",
                    RiskDomain::ToolAbuse,
                    Severity::High,
                    DomainVerdict::Suspicious,
                    0.75,
                    format!("工具 `{tool_name}` 同时具备文件读取与出网能力，可用于把本地数据外传"),
                    "拆分能力：读文件与出网由不同工具承担；出网工具限制目标域名，读文件工具限制路径",
                ));
            }
            if t.is_rce_capable() {
                hits.push(DomainHit::new(
                    "tool-abuse:capability-combination",
                    "具备代码执行能力组合",
                    RiskDomain::ToolAbuse,
                    Severity::Critical,
                    DomainVerdict::Suspicious,
                    0.8,
                    format!("工具 `{tool_name}` 具备 shell 执行或（写文件 + 出网）组合，等价于远程代码执行面"),
                    "此类工具必须纳入强制审批与完整审计；禁止对不受信输入开放",
                ));
            }
            if t.credential_access {
                hits.push(DomainHit::new(
                    "tool-abuse:overbroad-scope",
                    "工具可访问凭据",
                    RiskDomain::ToolAbuse,
                    Severity::Medium,
                    DomainVerdict::Suspicious,
                    0.65,
                    format!("工具 `{tool_name}` 具备凭据读取能力，需确认最小权限"),
                    "凭据读取工具仅对白名单主体开放；读取行为全量审计并告警",
                ));
            }
        }

        let mut report = DomainReport::from_hits(RiskDomain::ToolAbuse, hits, checks);
        report.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        report
    }
    // =======================================================================
    // 5. 模型与数据安全
    // =======================================================================

    /// 模型输出与数据安全检测。
    #[must_use]
    pub fn model_data(&self, output: &str, data_class: DataClass) -> DomainReport {
        let start = std::time::Instant::now();
        let checks = vec![
            "credential-in-output".to_string(),
            "pii-echo".to_string(),
            "exfil-url".to_string(),
            "data-class-mismatch".to_string(),
            "supply-chain".to_string(),
        ];
        let mut hits = Vec::new();

        // 输出中的凭据
        let creds = scan_credentials(output, &self.custom_credential_patterns);
        if !creds.is_empty() {
            let masked: Vec<String> = creds.iter().map(|c| c.masked.clone()).collect();
            hits.push(
                DomainHit::new(
                    "model-data:credential-in-output",
                    "模型输出包含凭据",
                    RiskDomain::ModelData,
                    Severity::Critical,
                    DomainVerdict::Malicious,
                    0.9,
                    format!("模型输出中出现 {} 处疑似凭据，可能是提示词泄露或知识库检索越权", creds.len()),
                    "输出侧启用凭据检测与自动打码；排查提示词/知识库中是否混入密钥",
                )
                .with_evidence(masked),
            );
        }

        // PII 回显
        let pii = detect_pii(output);
        if !pii.is_empty() {
            hits.push(
                DomainHit::new(
                    "model-data:pii-echo",
                    "模型输出包含个人敏感信息",
                    RiskDomain::ModelData,
                    Severity::Medium,
                    DomainVerdict::Suspicious,
                    0.7,
                    format!("输出中检出 {} 处 PII（手机号/身份证/邮箱等）", pii.len()),
                    "输出侧启用 PII 脱敏；限制知识库中个人信息的检索范围",
                )
                .with_evidence(pii),
            );
        }

        // 外传 URL（Markdown 图片/短链/收集器域名）
        if let Some(url) = detect_exfil_url(output) {
            hits.push(
                DomainHit::new(
                    "model-data:exfil-url",
                    "疑似数据外传 URL",
                    RiskDomain::ModelData,
                    Severity::High,
                    DomainVerdict::Malicious,
                    0.85,
                    format!("模型输出包含形似数据外传的 URL `{url}`（常见于 Markdown 图片注入）"),
                    "禁止模型输出的 Markdown 自动加载外部资源；出网域名白名单 + 出站流量审计",
                )
                .with_evidence(vec![url]),
            );
        }

        // 数据分级与输出内容不匹配
        if data_class >= DataClass::Confidential {
            for pat in ["api key", "password", "token", "内部", "confidential", "未公开"] {
                if output.to_lowercase().contains(pat) {
                    hits.push(
                        DomainHit::new(
                            "model-data:data-class-mismatch",
                            "高密级数据出现在输出",
                            RiskDomain::ModelData,
                            Severity::High,
                            DomainVerdict::Suspicious,
                            0.7,
                            format!("数据分级为 {data_class:?} 的内容中出现 `{pat}`，可能违反数据分级策略"),
                            "高密级数据只允许本地模型处理；输出侧按分级做强制脱敏",
                        )
                        .with_evidence(vec![snippet(output, pat)]),
                    );
                    break;
                }
            }
        }

        // 供应链后门特征（模型建议执行来源不明的代码）
        for pat in
            ["pip install git+http", "npm install http", "curl http", "wget http", "eval(base64", "invoke-expression"]
        {
            if output.to_lowercase().contains(pat) {
                hits.push(
                    DomainHit::new(
                        "model-data:supply-chain",
                        "供应链风险指令",
                        RiskDomain::ModelData,
                        Severity::High,
                        DomainVerdict::Suspicious,
                        0.75,
                        format!("模型建议执行来源不明的代码/安装 `{pat}`"),
                        "禁止自动执行模型给出的安装/下载指令；依赖来源必须走内部镜像与审核",
                    )
                    .with_evidence(vec![snippet(output, pat)]),
                );
                break;
            }
        }

        let mut report = DomainReport::from_hits(RiskDomain::ModelData, hits, checks);
        report.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        report
    }
    /// 由模型研判结论调整报告（融合规则与模型）。
    pub fn apply_judgement(report: &mut DomainReport, judgement: &LlmJudgement) {
        for hit in &mut report.hits {
            if !judgement.cited_evidence.is_empty() && !judgement.cited_evidence.contains(&hit.key) {
                continue;
            }
            hit.confidence = agf_core::risk::fuse_confidence(hit.confidence, Some(judgement));
            if judgement.verdict == agf_core::enums::Verdict::Benign {
                hit.verdict = DomainVerdict::Suspicious;
            }
        }
        report.verdict = if report.hits.iter().any(|h| h.verdict == DomainVerdict::Malicious) {
            DomainVerdict::Malicious
        } else if report.hits.is_empty() {
            DomainVerdict::Benign
        } else {
            DomainVerdict::Suspicious
        };
    }
}

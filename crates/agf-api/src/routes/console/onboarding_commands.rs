//! Executable, platform-specific instructions. A plan does not deploy or change an asset.
use super::onboarding_types::OnboardingStepView;

pub(super) struct PlanCommands<'a> {
    pub base: &'a str,
    pub tenant: &'a str,
    pub mode: &'a str,
    pub platform: &'a str,
    pub zh: bool,
    pub artifact: Option<&'a str>,
    pub sha256: Option<&'a str>,
}
impl PlanCommands<'_> {
    fn text(&self, zh: &str, en: &str) -> String {
        if self.zh { zh } else { en }.into()
    }
    fn windows(&self) -> bool {
        self.platform == "windows-amd64"
    }
    pub(super) fn env(&self) -> String {
        let Self { base, tenant, .. } = self;
        let (token, prompt, values) = if self.mode == "sidecar" {
            (
                "AGF_AGENT_TOKEN",
                "Collector API Key (sources:write)",
                vec![
                    ("AGF_MOCK_MODE", "0".to_string()),
                    ("AGF_AGENT_SERVER_URL", base.to_string()),
                    ("AGF_AGENT_TENANT_ID", tenant.to_string()),
                ],
            )
        } else {
            (
                "OPENAI_API_KEY",
                "Model API Key (models:read, models:write)",
                vec![("OPENAI_BASE_URL", format!("{base}/v1"))],
            )
        };
        let mut lines = values
            .into_iter()
            .map(
                |(key, value)| {
                    if self.windows() { format!("$env:{key}='{value}'") } else { format!("export {key}='{value}'") }
                },
            )
            .collect::<Vec<_>>();
        lines.push(if self.windows() {
            format!(
                "$env:{token}=[System.Net.NetworkCredential]::new('',(Read-Host '{prompt}' -AsSecureString)).Password"
            )
        } else {
            format!("printf '{prompt}: '; read -r -s {token}; export {token}; printf '\\n'")
        });
        if self.mode == "sidecar" {
            let hint = self.text(
                "# 可选：取消下一行注释并改为项目绝对路径，可发现项目级 MCP 配置",
                "# Optional: uncomment and set absolute project roots to discover project-scoped MCP settings",
            );
            lines.push(hint);
            lines.push(if self.windows() {
                "# $env:AGF_AGENT_PROJECT_ROOTS='D:\\work\\repo-a;D:\\work\\repo-b'".into()
            } else {
                "# export AGF_AGENT_PROJECT_ROOTS='/workspace/repo-a:/workspace/repo-b'".into()
            });
        }
        lines.join("\n")
    }
    pub(super) fn steps(&self) -> Vec<OnboardingStepView> {
        let rollback = if self.mode == "sidecar" {
            self.text(
                "# Ctrl+C 停止；保留 agf-data；撤销本次采集 Key",
                "# Stop with Ctrl+C; retain agf-data; revoke this collector key",
            )
        } else {
            self.text(
                "# 恢复应用原 Base URL、模型和 Key；按原发布流程重启；撤销本次平台 Key",
                "# Restore the application's original base URL, model and key; redeploy; revoke this platform key",
            )
        };
        let rows = if self.mode == "sidecar" { self.collector() } else { self.gateway() };
        rows.into_iter()
            .enumerate()
            .map(|(index, (title, command))| OnboardingStepView {
                order: i64::try_from(index + 1).unwrap_or(1),
                title,
                command,
                rollback: rollback.clone(),
            })
            .collect()
    }
    fn collector(&self) -> Vec<(String, String)> {
        let prepare = match (self.artifact, self.sha256) {
            (Some(path), Some(hash)) if self.windows() => format!(
                "Invoke-WebRequest '{}{path}' -OutFile .\\agf-agent.exe\nif ((Get-FileHash .\\agf-agent.exe -Algorithm SHA256).Hash -ne '{hash}') {{ throw 'SHA-256 mismatch' }}", self.base),
            (Some(path), Some(hash)) => {
                let verify = if self.platform == "macos-arm64" { "shasum -a 256 -c -" } else { "sha256sum -c -" };
                format!("curl --fail --location '{}{path}' --output ./agf-agent\nprintf '%s  agf-agent\\n' '{hash}' | {verify} && chmod +x ./agf-agent", self.base)
            }
            _ if self.windows() => "cargo build --release -p agf-agent --bin agf-agent\nif ($LASTEXITCODE -ne 0) { throw 'Build failed' }\nCopy-Item .\\target\\release\\agf-agent.exe .\\agf-agent.exe".into(),
            _ => "cargo build --release -p agf-agent --bin agf-agent && cp ./target/release/agf-agent ./agf-agent && chmod +x ./agf-agent".into(),
        };
        let exe = if self.windows() { ".\\agf-agent.exe" } else { "./agf-agent" };
        let data = if self.windows() { ".\\agf-data" } else { "./agf-data" };
        vec![
            (
                if self.artifact.is_some() {
                    self.text("在专用目录下载并核对摘要", "Download into a dedicated directory and verify the digest")
                } else {
                    self.text(
                        "此平台制品尚未发布：在目标系统的项目源码目录构建",
                        "Build unavailable: compile in the project source directory on the target OS",
                    )
                },
                prepare,
            ),
            (
                self.text(
                    "先设置上方环境变量，再单次采集；检查退出码和资产记录",
                    "Set the environment above, collect once, and check the exit code and inventory",
                ),
                format!("{exe} run --once --data-dir {data}"),
            ),
            (
                self.text(
                    "确认首次上报成功后持续运行；观察不等于应用调用在线",
                    "After successful ingestion, run continuously; discovery does not prove application availability",
                ),
                format!("{exe} run --interval 60 --data-dir {data}"),
            ),
        ]
    }
    fn gateway(&self) -> Vec<(String, String)> {
        let check = if self.windows() {
            "Invoke-RestMethod \"$env:OPENAI_BASE_URL/models\" -Headers @{Authorization=\"Bearer $env:OPENAI_API_KEY\"}"
                .into()
        } else {
            "curl --fail --silent --show-error \"$OPENAI_BASE_URL/models\" -H \"Authorization: Bearer $OPENAI_API_KEY\""
                .into()
        };
        let request = if self.windows() {
            "$body=@{model='auto';messages=@(@{role='user';content='Reply OK'});max_tokens=32} | ConvertTo-Json -Depth 8\nInvoke-RestMethod \"$env:OPENAI_BASE_URL/chat/completions\" -Method Post -Headers @{Authorization=\"Bearer $env:OPENAI_API_KEY\"} -ContentType 'application/json' -Body $body".into()
        } else {
            "curl --fail --silent --show-error \"$OPENAI_BASE_URL/chat/completions\" -H \"Authorization: Bearer $OPENAI_API_KEY\" -H 'Content-Type: application/json' --data '{\"model\":\"auto\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply OK\"}],\"max_tokens\":32}'".into()
        };
        vec![
            (self.text("先在模型网关登记并测试端点，复制环境配置后列出模型", "Register and test a gateway endpoint first, then set the environment and list models"), check),
            (self.text("执行小请求，核对输出及模型页的真实/Mock 计量；可能产生费用", "Send a small request and verify output and real/Mock usage; charges may apply"), request),
            (self.text("填写应用配置并按其发布流程生效；不自动注入探针或切换流量", "Apply application settings through its deployment process; no automatic probe injection or traffic switch"),
                format!("# OpenAI-compatible base URL: {}/v1\n# Model: exact ID from /v1/models, or auto\n# API key: platform key for this tenant\n# Anthropic: base URL {}, endpoint /v1/messages; see /guide", self.base, self.base)),
        ]
    }
}

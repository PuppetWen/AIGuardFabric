# Claude Code / MCP / 自研 Agent 本地接入模拟验收

此流程只用回环地址上的模拟策略和模型服务，不调用云端、不读取真实用户目录、不需要真实 Key。它验证**实际 `agf-agent` 二进制**读取项目级 `.mcp.json`、发现模型端点，并以 stdio 包装一个本地 MCP Server。模拟服务验证请求允许、策略拒绝、无效策略帧拒绝、调用租约结算和服务不可达时拒绝转发。自研 Agent 样例用标准 OpenAI 兼容请求验证模型列表和聊天响应。模拟成功不等于真实 Claude Code 安装或生产网关已经验收。

在项目根目录的 PowerShell 中执行；依赖优先使用项目 `.cargo` 内已缓存版本，Rust 与 Python 可来自 `D:\Environment`：

```powershell
$env:CARGO_HOME = (Resolve-Path .\.cargo).Path
$env:CARGO_TARGET_DIR = Join-Path (Get-Location) '.tmp\local-onboarding\target'
cargo build -p agf-agent --offline
if ($LASTEXITCODE -ne 0) { throw 'agf-agent 构建失败' }
python .\scripts\verify-stdio-onboarding.py `
  --agent-bin "$env:CARGO_TARGET_DIR\debug\agf-agent.exe" `
  --work-dir '.tmp\local-onboarding'
if ($LASTEXITCODE -ne 0) { throw '本地接入验收失败' }
```

脚本把临时 `.mcp.json`、模拟 MCP Server 和 Agent 数据目录集中放在 `--work-dir` 的临时子目录，并在结束后清理。构建目录由 Cargo 保留供下一次使用；项目最终清理时按任务归属核对。脚本只允许 `--work-dir` 指向项目内。成功输出 `PASS`；失败会显示断言或进程错误。真实平台验证仍需：给采集、MCP 和模型分别建立最小权限 Key，在目标设备按 [Agent 接入指南](agent-onboarding-guide.md) 完成一次采集和无害调用，并核对平台台账、运行时事件、Mock 标记和用量。Claude Code 的完整 Messages 扩展兼容仍在[剩余工作清单](remaining-work-2026-09-22.md)中。

同一验收已纳入 `scripts/gate.ps1 -Only onboarding`；门禁会将产物放在项目 `.tmp/gate-onboarding/target`，不使用根目录旧 `target`。

## English

Run the PowerShell commands above from the project root. The script tests the real `agf-agent` binary against loopback-only policy, MCP and model mocks. It creates and removes only a temporary child of the project-local `--work-dir`; it neither needs nor saves a real key. `PASS` proves local configuration discovery, MCP forwarding/denial/fail-closed behavior, token isolation and the OpenAI-compatible request example. It does not certify a real Claude Code installation or production gateway. For a live rollout, issue separate least-privilege keys and confirm the tenant inventory, runtime events, model usage and Mock/real indicator as described in the [onboarding guide](agent-onboarding-guide.md).

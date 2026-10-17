# Claude Code 模型网关接入 / Claude Code gateway onboarding

## 中文操作

1. 管理员在“模型网关 → 模型接入配置”添加一个 **Mock** 或 Anthropic 端点，填准确的模型 ID，保持“流式”和“工具调用”开启。先用 Mock 做以下测试；真实端点会产生厂商费用。
2. 在“设置 → API Key”创建仅供模型调用的 Key，权限选 `models:read`、`models:write`。MCP 代理另用 `policies:read` Key；不要共用。
3. 在启动 Claude Code 的**同一个 PowerShell 会话**设置环境变量。Base URL 是平台根地址，**不加 `/v1`**；Claude Code 自己请求 `/v1/messages`。模型名必须与上一步一致。

```powershell
$env:ANTHROPIC_BASE_URL = 'http://localhost:8081'
$env:ANTHROPIC_MODEL = '<模型接入配置中的模型 ID>'
$agfSecret = Read-Host '模型专用 AGF API Key' -AsSecureString
$agfPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($agfSecret)
try { $env:ANTHROPIC_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($agfPtr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($agfPtr); Remove-Variable agfSecret,agfPtr -ErrorAction SilentlyContinue }
claude --bare --print --model $env:ANTHROPIC_MODEL '只回答 OK'
```

4. 命令退出成功后，在“模型网关 → 用量明细”核对这次请求的模型、Mock/真实、Token 和费用，再在“运行时防护 → 事件”核对策略判定。`--bare` 是不读取项目配置的最小化连通性测试；正式使用时在目标项目目录运行 `claude`，再做一次无害工具调用并检查用量。项目级 MCP 接入另按 [Agent 接入指南](agent-onboarding-guide.md) 和 [stdio MCP 防护](user-handbook.md#5-stdio-mcp-防护) 配置。

平台会把 Claude Code 的扩展思考、签名块和 `context_management` 原样交给 **Anthropic** 端点，并保留上游响应中的签名和流式事件；Mock 端点可验证请求链路，但不会生成真实思考内容。策略或内容检查若改写了消息，原生请求会被明确拒绝，避免旧签名对应的未经脱敏原文到达上游。其它厂商端点不能承接这些原生字段；如需使用基础跨协议转换，可在启动 Claude Code 前设置 `CLAUDE_CODE_DISABLE_THINKING=1` 和 `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1`，但这会改变客户端行为。图片（包括工具结果中的图片）、多个客户端工具结果、文本、标准工具和 SSE 已有测试；PDF/文件、服务端工具和其它扩展字段尚未完整兼容。真实 Anthropic 账号与费用链路仍需用户凭据联调，不能把 Mock 或本地模拟上游测试当成生产验收。客户端运行在另一台电脑时须能访问平台地址；跨网部署使用组织批准的 HTTPS 入口。

Anthropic 端点会保留请求的顶层或内容块 `cache_control`、`top_k` 和工具并行选择，不会把缓存标记悄悄丢掉；若基础跨协议模式仍带这些原生选项，需改用 Anthropic 端点。用量中的输入 Token 合计包含未缓存输入、缓存写入和缓存读取；缓存读取按端点填写的缓存单价，5 分钟/1 小时缓存写入分别按输入单价的 1.25/2 倍估算。调用前预算会按缓存标记可能产生的最高写入费率预留，完成后按实际回执结算；接近预算上限时，一次预计会写入缓存的请求可能先被拒绝。费用栏仍是估值，应与实际厂商账单核对。图片无法仅从 URL 得到尺寸，调用前预算按每张 4,784 Token 保守预留，最终以厂商回执结算；若大量低分辨率图片被预算拒绝，可提高租户预算或减少图片后重试。[Anthropic 缓存用量说明](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)和[图像 Token 说明](https://platform.claude.com/docs/en/build-with-claude/vision)给出厂商口径。

排障：401 检查 Key、租户及是否把普通账号密码误填为 API Key；403 检查 `models:write` 和运行时策略。如果 Claude Code 显示 `This group does not allow /v1/messages dispatch`，且平台模型用量没有对应记录，请检查本机组织托管的客户端或代理配置；本次验收中该错误甚至在客户端指向本机临时 HTTP 服务时出现，服务端未收到连接，不能归因于平台接口。400 检查是否启用了不支持的 Messages 扩展；429 检查配额；503 检查端点/上游和运行时事件。退出 PowerShell 会话会清除本例的临时环境变量。不要把 Key 写进项目文件或命令行参数。

## English

Register a Mock or Anthropic gateway endpoint with the exact model ID and streaming/tool support. Create a separate platform key with `models:read` and `models:write`. Set `ANTHROPIC_BASE_URL` to the platform root (without `/v1`), `ANTHROPIC_MODEL` to that model ID, and `ANTHROPIC_API_KEY` to the platform key in the same shell that starts Claude Code. Run `claude --bare --print --model <model-id> 'Reply OK'`, then check the gateway usage and runtime events. Start regular `claude` from the target project only after the smoke test, and verify a harmless tool call. MCP uses its own key and onboarding path.

Native thinking, signatures and context management are preserved for Anthropic endpoints; Mock only verifies transport. Requests changed by redaction are rejected so the original signed payload cannot bypass policy. Other providers cannot receive these native fields; `CLAUDE_CODE_DISABLE_THINKING=1` and `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` enable the basic cross-provider path at the cost of changing client behavior. Server tools, PDF/file blocks and other extensions remain incomplete, and a real Anthropic account has not yet been exercised. If Claude Code reports `This group does not allow /v1/messages dispatch` with no platform usage entry, check locally managed client/proxy policy: during this verification the same error occurred against a localhost listener that received no request. Use an approved HTTPS gateway when the client cannot reach the LAN address. See the [Claude Code gateway documentation](https://docs.anthropic.com/en/docs/claude-code/llm-gateway) and [environment-variable reference](https://code.claude.com/docs/en/env-vars) for client-side settings.

Anthropic prompt-cache markers, `top_k`, and parallel tool selection are passed through natively. If the basic cross-provider path still sends these native options, select an Anthropic endpoint. Gateway input usage includes uncached, cache-write, and cache-read tokens. Reads use the configured cache rate; five-minute and one-hour writes use 1.25x and 2x the configured input rate. Preflight budgets reserve the highest possible cache-write cost indicated by the request and settle against actual usage; a request near the budget limit may be refused before the vendor call. Monetary totals remain estimates, so compare them with the vendor bill. Preflight budgeting reserves 4,784 tokens for each image when dimensions are unknown, and settles against the vendor's actual usage.

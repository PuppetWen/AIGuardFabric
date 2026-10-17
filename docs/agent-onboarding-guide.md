# Agent 与 MCP 列表及接入指南

## 首次接入

1. 选择正确租户，在“设置 → API Key”创建独立凭据。采集器使用 sources:write；模型验证使用 models:read、models:write。生成计划需要 agents:read；SDK 来源选择还需要 sources:read 和 alicloud:read，精确模型选择还需要 models:read。原身份、会话及当前角色/Key 存活在读取后复查。计划不签发密钥、不登记资产、不更改角色或执行业务。
2. 打开“Agent 管理 → Agent 接入向导”，选择三模式及精确目标：Sidecar 的 collector / mcp-stdio；SDK 注入的 python-startup / node-cjs-startup；网关注册的 model-openai / model-anthropic / mcp-http，再选实际操作系统。旧调用未传 target 时分别默认 collector、python-startup、model-openai；不支持的组合返回 400，不降级到网关。
3. 没有资产时选择“首次接入 / 通用计划”。已有资产可按全部名称、负责人、地址或属性搜索和翻页选择，不限于前 12 个。所选 Agent 是计划参考，不会改变采集器真实发现的身份或台账纳管状态。
4. 复制环境配置和命令到目标设备执行。向导使用当前控制台地址；若通过 localhost 或 SSH 隧道访问，需要改为目标设备可达的部署地址。
5. Windows 使用 PowerShell；Linux x64 和 macOS Apple Silicon 使用 Bash。凭据交互输入，避免写进脚本。目标平台没有发布制品时不显示下载；请在该系统的项目源码目录构建，遵循项目工具链要求。生成跨平台命令不等于已验证该平台探针的全部能力。

无真实凭据时，先按 [本地接入模拟验收](local-onboarding-smoke.md) 复跑 Claude Code 项目配置、MCP stdio 代理和自研 Agent 模型请求样例，再接入实际平台。模拟服务只证明本地链路，最终仍需在控制台核对真实上报与运行时事件。

## 终端采集

- 已发布制品显示 SHA-256，下载后核对。摘要不符应停止，不继续运行；下载可能在发布更新后过期，请重新生成计划。
- 先设置环境，执行一次 run --once；核对退出码、上报日志、租户及资产台账。首次上报成功后再持续运行。
- 采集器读取终端可见配置；Windows/Linux/macOS 均已接线七类采集。Linux 监听端口来自 `/proc/net`；macOS 使用本机 `lsof`，缺失命令或权限受限会在采集状态中显示错误/警告，且 macOS 尚待真机实测。macOS 上可先运行 `lsof -nP -iTCP -sTCP:LISTEN -Fpcfn` 核对当前用户可见的监听端口，再执行 Agent 的 `run --once` 对照上报；UDP 使用 `lsof -nP -iUDP -Fpcfn`。Linux 已在离线容器运行全套采集测试。Agent 自身的 `AGF_AGENT_*` 密钥不计入业务密钥扫描；模型/MCP URL 上报前移除用户信息、查询串和片段，MCP 命令参数中的常见凭据被遮盖。仅安装或启动它不会自动代理所有应用请求。未知指标不代表零，最近发现也不证明应用在线。
- 要发现 Claude Code 等**项目级** MCP 配置，运行前显式设置 `AGF_AGENT_PROJECT_ROOTS` 为项目根目录列表：Windows 用分号分隔（如 `D:\RepoA;D:\RepoB`），Linux/macOS 用冒号分隔（如 `/workspace/a:/workspace/b`）。只接受最多 8 个绝对路径，每个根只检查 `.mcp.json`、`mcp.json`、`.claude/settings.json`、`.vscode/mcp.json`，不递归遍历项目或读取项目 `.env`。首次运行后，在 MCP 管理页搜索服务器名并核对“来源文件”；没有结果时检查 Agent 运行账号能否读取这些文件。
- 每台设备使用独立数据目录及 Key，保留 agf-data。停止采集使用 Ctrl+C；回退后撤销本次 Key，不删除业务目录或历史数据。

## 启动注入：Python / Node CommonJS

1. 在 [阿里云资源盘点](/alicloud?tab=inventory) 完整盘点真实 Worker/Team；在日志来源中建立 HTTP Webhook push 源，再到 [消息与调用审计](/alicloud?tab=audit) 明确绑定当前盘点。没有完整盘点或当前有效绑定时，向导不提供示例 UUID/默认 Worker，也不自动初始化。
2. 选择 SDK 启动注入及语言，点击“只读加载当前来源与 Worker”，明确选择来源、Worker；Worker 属于多个团队时必须明确选择真实 Team，不自动预选。单团队可不填写，采集接口按唯一团队解析。Call 的被调用 Worker 遵循相同规则。显示的 source/binding/scope/mock 来自平台当前绑定。Worker Task/Call 是调用边界观测，**Message 需要显式 SDK 事件**；模型/MCP 转发不是 AgentTeams Message 证明。
3. 填实际 qualified callable、原业务入口、SDK 目录、该应用独占队列目录、配置文件绝对路径及静态操作标签。Python 选择模块+attribute 和原入口模块；目标不能是入口本身、stdlib 或 SDK 模块。Node 选择 `.cjs`/CommonJS `.js` 目标的自身 export 路径和真实 sync/promise/iterator/asyncIterator 返回模式。不能假定未测试厂商 SDK/ESM/worker thread/class/预加载模块自动支持。
4. 保存向导的原始 JSON 文本，不重命名内部字段，不写 Key。Python 的固定 `AGF_COLLECTOR_KEY` 从环境读取，JSON **没有 keyEnv**；Node JSON `keyEnv=AGF_STARTUP_KEY` 只指定环境变量名，实际值交互输入。Node 还从环境绑定 source/binding/scope/mock 与 spool；不会在浏览器接收或保存采集 Key。
5. 启动命令明确使用 Python `-m agf_agentteams.bootstrap --config … --module 原入口 -- 原参数` 或 Node `--require …/startup.cjs 原入口 原参数`；保留原返回、异常和同步/异步/流取消语义。启动入口包装明确调用，不需要编辑业务源码。Python 不会自动识别所有函数，Node 不会自动解析所有 module 格式。
6. `--drain-only` 仅重投原 UUID 队列，不装载或重新调用业务。原队列按来源身份有界持久保存；未知、撤权、绑定换版不能通过改 UUID/自动重放业务解决。停止后保留队列，按原部署流程恢复启动命令，核实后只撤销本次独立 Key。

Python 启动入口已在现有 Python 3.11.1 / 3.12 环境真实验收；Node CJS 启动入口已安装，已验证 Node 24.18.0 / 25.2.1。Node 仅接受 24.18.x / 25.2.x；其它补丁版本、平台、厂商调用和真实云授权须分别核验。这里的向导模板新回归仍待父任务执行，不能用模板生成声称完成生产部署。

## Sidecar stdio 与网关注册

- collector 只发现可见终端配置并上报资产；不会代理业务流量。新资产可从 [资产登记](/assets) 手工登记，Key 从 [设置](/settings?tab=apiKeys) 明确创建并选择实际 Agent 绑定。计划不调用不存在的 `/agent/register`。
- mcp-stdio：填写原 command 和 **JSON 字符串参数数组**，浏览器仅合并 `agf-agent mcp-proxy --server 平台 -- 原 command 原 args`，不把参数解释为 shell 代码，不上传原业务参数。构建/下载真实 agf-agent 并核摘要；把 wrapper command 路径改成实际路径，合并到项目配置，保留该条原环境及其余服务器。AGF_AGENT_TOKEN 在启动客户端的环境中提供，需 policies:read。配置消费者必须实际继承该环境；平台不写项目文件或证明代理已启用。
- model-openai 明确使用 `OPENAI_BASE_URL=平台/v1`；model-anthropic 使用 `ANTHROPIC_BASE_URL=平台根`，其请求路径为 `/v1/messages`。填当前租户**精确已启用 model ID**，不预选种子、不使用 auto 补空；平台按模型元数据核对，但不会自动切换原应用。
- mcp-http：打开 [MCP 管理](/mcps) 的 HTTP 端点入口，显式登记、探测并复制该端点模板。向导不代执行登记/探测，不把 HTTP 模板降级成 stdio 或伪工具调用。
- 模型执行 Key 需要 models:read/write；HTTP MCP 调用使用独立 mcps:execute/policies:read Key。环境变量是否生效由原应用决定；先核协议和实际请求/拒绝/用量，再安排发布窗口。付费/Mock、Unknown 与零必须分开；回退恢复原地址、模型、凭据和业务入口。
- 本机真实 Claude CLI 曾在连接平台前被管理策略阻断；本地模拟 Claude 配置、Mock `/v1/messages` 响应和 MCP 代理不能冒充真实 CLI 验收。阶段一可使用未修改自研 Agent/MCP 本地模拟；真实设备/凭据/外部压力测试属于明确授权的阶段二。

## 企业清单维护

- Agent、MCP 的搜索、筛选、排序和分页作用于服务端全部记录。Agent 支持框架、纳管方式、最近观察状态；MCP 支持传输、影子和明文标记。
- 名称、风险、最近观察及已采集计数按全部结果排序；未知值排在最后。分页总数来自同一筛选条件，切换条件返回第一页。
- MCP 工具调用次数没有采集时显示“未知”，真实 0 保留。工具能力和风险可能来自声明或名称推断，不等于已观察到实际调用。
- MCP 的“已配置认证”来自客户端配置中的 Header、URL 或令牌键名，只证明客户端准备了认证材料，不证明服务端真的拒绝匿名请求。需要确认访问控制时，在授权的测试目标上分别验证有凭据与无凭据请求，记录服务端实际响应。
- 切换账号或组织关闭旧向导/工具抽屉。只读账号可以阅读计划，需要执行权限的采集或模型请求由专用 Key 独立授权。
- 建议先在测试设备完成“配置 → 一次调用/采集 → 台账/用量核对 → 策略核对 → 回退演练”，再按组织变更流程分批上线。

## English

The three modes now select an exact target: sidecar `collector`/`mcp-stdio`, SDK `python-startup`/`node-cjs-startup`, or gateway `model-openai`/`model-anthropic`/`mcp-http`. Missing targets default respectively to collector, Python startup and OpenAI; incompatible combinations fail rather than switching mechanisms. GET and POST plan requests are pure reads. They create no key, asset, role, source, cloud request or business execution. Current agents:read is required, with sources:read+alicloud:read for SDK inventory and models:read for model selection; original identity/session/expiry is rechecked after awaited reads.

For SDK startup, complete actual Worker/Team inventory and bind a reviewed webhook push source in [Messages and call audit](/alicloud?tab=audit). Load choices and select the exact source and Worker. A Worker in multiple Teams requires an explicit inventoried Team, with no automatic selection. A single-Team Worker may omit Team and the collector resolves its unique membership. The same rule applies to the callee of a Worker call. IDs, scope and Mock mode come from this verified binding, never examples. Supply the real qualified callable, original application entry, installed SDK directory, application-owned spool and noncredential configuration file. Preserve original launch arguments locally. Python uses module/attribute and an original module entry. Node uses a CommonJS .cjs/.js file, own export path and explicit sync/promise/iterator/asyncIterator mode. No unsupported vendor, ESM, worker-thread, class or preloaded-module coverage is implied.

Python JSON has no keyEnv: AGF_COLLECTOR_KEY is read from the environment. Node keyEnv names AGF_STARTUP_KEY, with current source/binding/scope/mock/spool supplied through environment. Never put the value in JSON, scripts or the browser. The actual startup entry is Python `-m agf_agentteams.bootstrap --config … --module original -- original-arguments` or Node `--require …/startup.cjs original original-arguments`, with return/exception/async/stream cancellation preservation. Drain-only delivers existing UUIDs and loads no business modules; it is not business retry. Startup records explicit Task/Call boundaries; **Message requires the explicit SDK**. Current installed startup implementations were tested on Python 3.11.1/3.12 and Node 24.18.0/25.2.1; Node accepts only 24.18.x/25.2.x. The new wizard regressions remain pending parent execution.

Collector mode discovers endpoint-visible settings, never automatically proxies all application traffic. Published builds carry SHA-256; otherwise build on the actual target OS. Keep device-owned data and verify ingestion/tenant inventory. AGF_AGENT_PROJECT_ROOTS is at most eight absolute roots separated by semicolons on Windows or colons on Unix; only fixed MCP configuration files are read, not repository/.env traversal. Linux/macOS command templates do not certify every native probe; macOS still requires native validation. Unknown metrics are not zero.

For stdio, enter the original command and JSON string argument array. The local UI merges only the wrapper command/vector, without uploading business arguments or shell interpretation. Build/download the real agf-agent, verify its digest and use its actual path. Preserve the server's original environment and other project settings; supply a policies:read AGF_AGENT_TOKEN in the launching client's inherited environment. No project file is written automatically. For models select an exact enabled model: OpenAI uses the origin plus /v1, Anthropic the origin with /v1/messages. No seed/auto selection fills missing input. HTTP MCP uses the actual [MCP management](/mcps) registration/probe/template flow, without automatic probing or a stdio substitute. Use separately scoped model or MCP keys and verify real/Mock output, usage and refusal before rollout. Restore original settings and launch entry to roll back, retain local queues/data, then revoke the dedicated key.

The actual local Claude CLI was blocked by managed policy before reaching the platform. Simulated project configuration, Mock Messages responses and stdio smoke results do not establish CLI acceptance. Tenant inventory supports full pagination/filtering/sorting; unknowns remain unknown. Generated plans do not change management state, prove cloud authorization, claim zero downtime or authorize stage-two real-cloud testing.

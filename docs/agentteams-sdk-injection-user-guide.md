# AgentTeams Python 启动时 SDK 注入 / Python SDK startup injection

## 中文

此入口通过启动命令包裹**明确配置的 Python 调用边界**，业务文件不加 import 或装饰器。它实现 §5.1 的 SDK 注入方式；侧车代理、网关注册是另外的接入方式。Node 普通 CommonJS 应用已有独立的 [启动接入入口](agentteams-node-startup-guide.md)，用原入口加 `--require` 接入；通用 ESM 自动注入仍未支持，ESM 使用 [显式 Node SDK](../sdk/agentteams/node/README.md)。这里没有验证某个厂商 SDK、Claude Code 或真实云端业务重放支持。

1. 按 [审计接入指南](agentteams-audit-guide.md) 配置 AgentTeams、完整盘点真实 Worker，启用 HTTP Webhook 日志源并建立当前绑定。管理员绑定需要 `alicloud:write` + `sources:write`；查看来源和审计需要 `alicloud:read` + `sources:read`。从当前来源取得 source、binding、scope UUID 和 Mock 模式，填写配置；示例 UUID **不对应可用平台来源**，启动器不会创建来源、绑定或虚构 Worker。
2. 给可信采集器创建有期限的 `sources:write` Key。该权限覆盖租户日志源写入/管理，**不是单个 Worker 或来源专用 Key**。模型网关 Key 的 `models:write`、绑定 Agent 和 Role 是另一授权边界。采集器被接受不证明业务 Worker 获得了调用授权；Mock 同样不证明授权。
3. 将 SDK 的 `sdk/agentteams/python` 放到该 Python 环境的 `PYTHONPATH`，无需下载第三方依赖。Python 3.10+。复制 `examples/startup-injection.example.json`，用当前来源、实际名称、目标函数替换示例；`spool_dir` 必须是本进程独占的绝对路径。配置 JSON 不能放 Key、prompt、业务参数或结果。Key 仅使用进程环境 `AGF_COLLECTOR_KEY`。
   示例队列 `E:/MyProjects/orders/data/agentteams-outbox` 位于应用项目的数据目录；换成你实际项目的专用路径，多个进程分别配置。示例 UUID 和 Worker 名称仍须替换，复制示例不会建立平台身份。
4. 选择真正被入口导入的模块。例如 `my_app.worker` 的 `run`、`Client.run`、`Client.static_run` 或 `Client.class_run`。每个目标填 `kind:task` 或 `kind:call`；call 必须显式填 caller `worker` 和 `callee`。`operation` 是静态标签。可选 `classifier:mcp_result` 只判断解码 MCP 响应的 isError/JSON-RPC 状态，不保存内容；默认 classification 只表示函数正常返回。
5. 使用启动命令；保持原入口参数、工作目录及应用依赖。业务模块本身没有 SDK 调用。先小范围确认 safe report 的 `installed_targets` 和实际审计，再扩展配置。

```powershell
$env:PYTHONPATH = '<SDK Python目录>;<原业务模块目录>'
$secret = Read-Host 'Collector Key' -AsSecureString
$env:AGF_COLLECTOR_KEY = [System.Net.NetworkCredential]::new('', $secret).Password
python -m agf_agentteams.bootstrap --config injection.json --module my_app.main -- <原参数>
# 脚本入口：python -m agf_agentteams.bootstrap --config injection.json --script app.py -- <原参数>
Remove-Item Env:\AGF_COLLECTOR_KEY
```

目标最多 32 个，配置最多 64 KiB。仅支持普通 source-file Python 模块中的函数、类声明的方法、staticmethod 和 classmethod。不会提前导入模块，也不重写源文件。目标不可是入口模块本身、已预加载模块、SDK/标准库、导入的别名、属性、原生函数、定制 loader/metaclass 或 dunder 属性。模块未被业务导入时不强行加载；`unloaded_targets>0` 表示这些目标没有覆盖。导入目标却找不到合法函数时明确启动失败，不留下半套包装。原模块导入异常保持原异常。

同步返回/异常、协程返回/取消、生成器 next/send/throw/close 和异步生成器 asend/athrow/aclose 保持业务语义。未消费的流不制造任务，提前关闭或取消记 unknown；代理不保证 `isinstance(..., GeneratorType)` 不变。普通同步函数返回 awaitable/iterator 时仅观察该同步函数返回，不能称已观察返回对象的执行。应用返回前须等待其线程/任务完成；每个 worker 进程独立启动，fork 子进程不会使用父进程队列。局部嵌套产生真实父 Span，未采集的跨进程关系保持未知。

事件只含静态 Worker/Team、随机 event/trace/span ID、状态和时长，不保存参数、返回值、prompt、异常文本或业务凭据，不合成 heartbeat/message。SQLite 持久队列保存上述元数据而非加密业务正文；用本机目录权限保护它。业务自身原有日志不会由启动器改写。队列满/写失败丢弃新遥测并报告 dropped，不重跑业务；原未确认事件保留。默认队列最多 10,000 条/16 MiB，磁盘预算 64 MiB；可在 Config 支持范围内调整。采集不是完整观测保证，强杀进程可丢失尚未结束或入队的事件。

stderr 最终报告只含 safe counters 和固定诊断码。业务的退出码/原异常不被报告替换。退出时有界 flush；pending/quarantined/delivery_active 不是“已入平台”的证据。只有匹配 scope/mode 和完整数量的 ACK 才删除队列事件；durable 为平台回执声明。

| 情况 | 操作 |
|---|---|
| 401/403 | 业务原执行保留，pending 保留；检查 Key、到期、租户及 sources:write，修复后仅排空旧队列 |
| 网络中断/丢 ACK | 只重传原 event_id/原内容；平台去重，不再调用业务 |
| 409/3xx | 原批隔离，不自动跟随重定向/换绑定重发；人工核实来源和旧数据归属 |
| 改 source/binding/scope/mode | 用新队列；旧队列不能改身份以掩盖冲突，保留待人工处理 |
| installed=0/unloaded>0 | 检查真实 import 路径和函数是否被加载，不等于“业务没有调用” |

修复原 Key 权限后，使用**仅投递**命令，避免为了遥测重试再次执行业务：

```powershell
python -m agf_agentteams.bootstrap --config injection.json --drain-only --drain-timeout 30
```

它不导入目标/执行业务。`--drain-timeout` 只用于 `--drain-only`，取值必须有限且在 `request_timeout + 0.25` 至 60 秒之间；省略时仍使用配置的 `shutdown_timeout`，业务退出预算不变。投递、停止与线程 join 共用这一总预算，不重置原 `retry_at`、限流退避或事件 ID。连续丢 ACK 时原退避可能长于业务退出预算，可显式选 30 秒排空。仍有 pending/quarantined/active 时返回 75；配置或队列归属失败返回 78。启动业务命令仍保留业务自身退出码。隔离事件不会通过该命令自动恢复。

## English

The startup command wraps **explicitly configured Python call boundaries** without adding SDK imports or decorators to business files. It addresses the SDK injection mode in §5.1. Sidecar and gateway registration are separate modes. Ordinary Node CommonJS apps can use the separate [preload guide](agentteams-node-startup-guide.md), preserving their original entry and arguments. Generic ESM injection remains unsupported; use [explicit Node wrappers](../sdk/agentteams/node/README.md) for ESM. Vendor/Claude/cloud business replay support is not claimed.

Configure AgentTeams and complete inventory first, then enable an HTTP Webhook source and bind its current Workers. Binding requires `alicloud:write` and `sources:write`; reading sources/audit requires both `alicloud:read` and `sources:read`. Copy the real source/binding/scope UUIDs and Mock mode. Example UUIDs do not represent usable sources. The launcher creates no platform source, binding or Worker. A trusted collector uses an expiring `sources:write` Key from **process environment `AGF_COLLECTOR_KEY` only**. This grant covers tenant source management, not one Worker/source; a model gateway `models:write` Key is separate. Collection acceptance and Mock never prove business authorization.

Use Python 3.10+ and add `sdk/agentteams/python` to PYTHONPATH; no third-party dependency is required. The configuration is strict JSON up to 64 KiB, with at most 32 exact module/attribute targets, actual Worker names and static operation tags. `call` needs explicit caller/callee. Optional `mcp_result` classifies a decoded MCP response without storing its content; default success means callable completion. Put no credentials, prompt, business input or output in this JSON. Replace the example `E:/MyProjects/orders/data/agentteams-outbox` with an absolute, process-exclusive directory under your application's data path. Replace the example IDs and Worker names too. The PowerShell commands above keep the Key out of arguments/configuration.

`--module my_app.main -- original-arguments` preserves module entry behavior; `--script app.py -- original-arguments` preserves script-directory imports. The importer wraps real functions/methods/staticmethods/classmethods after normal module execution and before callers receive exports. It neither preimports targets nor rewrites source. Entry modules, already-loaded targets, stdlib/SDK modules, imported aliases, properties, native functions, custom loaders/metaclasses and dunder attributes are unsupported. Unimported targets remain uninstalled and visible in `unloaded_targets`; missing/unsupported targets in an imported module fail explicitly without partial wrapping. Original import exceptions propagate unchanged.

Returns, exceptions, coroutine cancellation and lazy stream send/throw/close protocols are preserved; unconsumed streams do not emit fake tasks, early close/cancel is unknown. Stream proxies may have a different concrete type. A sync callable returning an awaitable/iterator is only observed until its sync return. Join business tasks/threads before entry completion. Start each worker separately; a fork child cannot use its parent's collector. Local nested spans are actual evidence; absent cross-process relationships remain unknown.

Only fixed Worker metadata, random IDs, status and duration are collected. No arguments/results/prompts/exception text/keys are recorded; no synthetic heartbeat/message is added. SQLite stores telemetry metadata, not encrypted business payload; protect its directory with filesystem permissions. Existing business logging remains the application's responsibility. Bounds, immutable queue identity and strict ACK validation reuse the existing SDK. Queue faults/fullness preserve business behavior and report dropped events. Abrupt termination and uncovered callables prevent any completeness claim.

The safe stderr report does not replace business exit/errors. Shutdown uses a bounded flush; pending/quarantined/active is not acceptance proof. 401/403 retains pending events; fix current Key permissions, then use `--drain-only`. Network/lost-ACK retries retain original event IDs/content and never reexecute business. 409/redirects quarantine; no automatic rebinding or redirect credential forwarding occurs. New source/binding/scope/mode requires a separate queue. Use `python -m agf_agentteams.bootstrap --config injection.json --drain-only --drain-timeout 30` for an explicit delivery-only total budget. The finite range is `request_timeout + 0.25` to 60 seconds; omitting it preserves the configured shutdown budget. It is forbidden with a business entry. Flush, stop and join share that budget; original retry times, 429 backoff and IDs are retained. Exit 75 means keep the queue and inspect pending/quarantined/active before reopening it; it does not mean the business should run again. Delivery-only mode imports/invokes no business: unresolved queue returns 75; configuration/ownership failure returns 78. Quarantined events require investigation.

Verification status belongs to the execution receipt. The candidate defines stdlib/import/subprocess and literal-loopback tests against local business functions and a synthetic collector. It is not evidence of a tested external vendor or complete cloud coverage.

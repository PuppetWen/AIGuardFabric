# Node CommonJS 启动接入 / CommonJS startup collection

此入口在启动参数中接入现有 AgentTeams Node Collector，不改业务源文件。
完整 53 项回归已在 Node 24.18.0 与 25.2.1 实际通过；入口只支持 24.18.x 与 25.2.x，其他版本会在业务入口前拒绝。
所用 `Module._load` 和缓存标记是版本相关私有实现，不是稳定公开 hook，也不是 ESM 自动覆盖。

This preload uses the existing Collector without rewriting application source. All 53 regression
cases passed on Node 24.18.0 and 25.2.1. Only Node 24.18.x and 25.2.x are admitted; other versions fail
before the entry runs. The private loader/cache contract does not promise ESM coverage.

## 先建立真实采集身份 / Establish collection identity

在平台盘点真实 Worker/Team，建立 APIWebhook 日志源和 AgentTeams 审计绑定，取得
`sourceId`、`bindingId`、`scopeId` 和明确的 Mock 标识。采集 Key 只需现有 `sources:write`；
这是租户级权限，不能称为仅某一 Worker 或来源的权限。模型调用使用另一个 Key。
提供以下安全环境变量，凭据不放 JSON、命令行、URL 或业务实参：

After inventory, configure a real APIWebhook source and audit binding. Supply their exact IDs and
Mock flag. The collection Key uses tenant-wide `sources:write`; it grants no model execution.
Keep model credentials separate. Provide these variables from the service's secret environment:

| Variable | Meaning / 含义 |
| --- | --- |
| `AGF_PLATFORM_URL` | Fixed platform HTTP(S) origin/base; use HTTPS remotely. No URL credentials, query or fragment. |
| `AGF_SOURCE_ID` | Existing source UUID / 已有来源 UUID |
| `AGF_BINDING_ID` | Existing audit binding UUID / 已有审计绑定 UUID |
| `AGF_SCOPE_ID` | Exact observed binding scope UUID / 原范围 UUID |
| `AGF_EXPECTED_MOCKED` | Literal `true` or `false`; never inferred / 不推断模式 |
| `AGF_STARTUP_KEY` | Collection Key; the descriptor names this environment variable, not its value. |
| `AGF_SPOOL_DIR` | Absolute local, process-owned SQLite queue directory / 进程专用绝对队列目录 |
| `AGF_NODE_STARTUP_CONFIG` | Absolute path to the operator-owned startup JSON / 绝对启动配置路径 |

每个进程与平台/来源/绑定/范围使用独立队列目录。不要与 Python、别的进程或别的绑定共用。
队列身份不含 Key 值，原身份内可轮换合法 Key；不能用新身份覆盖旧待补传事件。
Each process/delivery identity needs its own local queue. Never share a queue with Python or another
process. Key rotation within the same identity is allowed; retargeting an old journal is refused.

## 精确配置 / Exact descriptor

配置最多 32 个目标、64 KiB JSON，未知字段拒绝。相对文件路径以该 JSON 所在目录为基准，
启动只检查真实文件，不导入它。业务文件可为 `.cjs` 或实际按 CommonJS 加载的 `.js`。
`.mjs`、ESM 命名空间和 ESM 自定义 `module.exports` 不会被伪装成 CJS。
The descriptor is limited to 32 targets and 64 KiB. Files resolve relative to this descriptor.
Validation checks their existence without importing them. `.js` is supported when the completed
cache proves CommonJS; file extension alone never proves that an ESM export is safe to replace.

```json
{
  "version": 1,
  "keyEnv": "AGF_STARTUP_KEY",
  "targets": [
    {
      "file": "./jobs/orders.js",
      "export": ["checkOrder"],
      "kind": "task",
      "worker": {"name": "actual-order-worker", "team": "actual-order-team"},
      "operation": "order.check",
      "mode": "promise",
      "capture": "omit"
    }
  ]
}
```

`export:null` 表示 `module.exports` 本身；数组表示 1–4 层自己的 data property，不能指向
getter、原型、`constructor` 或只读属性。`kind:call` 还要求明确的 `to:{name,team}`；
`task` 不接受 `to`。Team 可为 `null`，其余名称须与真实盘点一致。
`operation`、可选 `taskId` 是固定不透明标签，不是表达式、用户输入或云任务编号。
`mode` 必须明确为 `sync`、`promise`、`iterator` 或 `asyncIterator`。

Use `export:null` for the callable `module.exports`, or an own-data-property path of 1–4 names.
Accessors, prototypes, constructors and locked properties are skipped. A `call` requires an
explicit destination Worker; a `task` does not accept one. Select the callable mode explicitly.
No dynamic carrier, classifier, raw credentials, argument/result capture or evaluated code is accepted.

## 原入口继续运行 / Run the original entry

```text
node --require /absolute/platform/sdk/agentteams/node/startup.cjs /absolute/app/entry.js existing-argument
```

Node 仍运行原入口和原参数，`require.main` 不被替换。目标模块只有在业务原来加载它时才
执行一次，然后只对完成加载、精确匹配的配置导出包装；未配置导出保持原样。
同步返回值、`this`、实参对象与原异常对象保持；promise 保留完成值/拒绝对象，但其返回
Promise 的引用身份不承诺不变。迭代器按原 `next/return/throw` 推进，不提前消费；提前终止
只报 `unknown`。直接 `new` 与 subclass 构造透明放行，不产生 task 事件。

The original entry, argv and `require.main` remain under Node's loader. Configured modules are not
eagerly imported. Sync values and error objects are preserved; promise fulfillment/rejection values
are preserved, while Promise reference identity is not guaranteed. Streams keep lazy advancement
and backpressure. Early termination is unknown. Construction passes through without collection.

若应用有明确的关闭点，可有界关闭采集器：
An explicit application shutdown can close the collector within a fixed budget:

```js
await require('/absolute/platform/sdk/agentteams/node/startup.cjs').close(5);
```

否则 `beforeExit` 尝试有界关闭；不安装异常或信号处理器来吞业务失败。`process.exit`、崩溃、
硬终止或终态前取消会留下观测缺口；已写入自有队列的事件可随后仅补传。
Without an explicit close, `beforeExit` attempts bounded flushing. No exception/signal handler
replaces business failure. Abrupt exit can leave gaps; already-journaled events can be drained later.

## 明确的观测缺口 / Explicit gaps

`status()` 只返回队列计数、固定诊断和目标序号，不返回凭据、文件路径或实参正文。
请检查 `targets[].state`；`startup_instrumented` 仅说明导出已包装，不说明云确认或调用授权。
Check `status().targets` for fixed state codes. Instrumented means an export was wrapped, not that
cloud execution or authorization was confirmed.

- 已提前加载、循环中的部分导出、class、Proxy、getter、不可写导出：保持原业务并报告缺口。
  Preloaded/circular partial exports, classes, Proxies, accessors and locked exports are unchanged.
- ESM、动态 `import`、worker threads、自定义 loader/resolver、应用内部未导出函数或逃逸的早期
  引用不承诺覆盖。No automatic coverage for ESM, dynamic imports, workers, custom loaders or escaped references.
- `fork` 会继承 preload；若继承父进程队列，子进程只返回 `startup_owned_queue_gap` 并继续业务。
  为每个 child 显式提供独立 spool。A fork with the parent's busy queue still runs its business; use a separate spool.
- 队列满、存储故障、网络/ACK 丢失不得重新执行 handler，也不得替换原业务结果或异常。
  Queue/delivery faults never invoke a handler twice or convert telemetry acceptance into business success.

## 只补传 / Drain only

停止使用该队列的业务进程，保留原身份环境与同一个配置，然后执行：
Stop the process holding this queue and retain its original identity/configuration:

```text
node /absolute/platform/sdk/agentteams/node/startup-drain.mjs --drain-only 5
```

此入口只加载 SDK、校验配置形状并发送原 UUID/原正文队列，不导入或调用配置的业务模块；
业务文件已删除也可补传。`pending=0`、`quarantined=0`、无 `lastError` 才退出 0。
ACK 的 `durable=false` 只说明平台内存接收；ACK/重送都不是失败业务重放或厂商确认成功。
This command reads and sends the existing journal without loading configured business modules.
It exits nonzero for pending, quarantined or failed delivery. Lost ACK retries replay telemetry UUIDs,
not application handlers. Platform memory acceptance does not prove restart durability.

## 验收边界 / Validation boundary

23 项配置/真实 Node 子进程/本地 TCP 用例与原 SDK 30 项已一起通过两版本完整回归。
按 [SDK 本地验证步骤](../sdk/agentteams/node/README.md#本地验证) 为 `AGF_NODE_SDK_TEST_DIR`
和 `AGF_NODE_STARTUP_TEST_DIR` 各自创建新的独占空目录；测试清理前验证标记和绝对路径归属，
不能采用用户数据或业务队列。上述回归没有真实云凭据、厂商业务重放或生产部署验收。
The 23 startup cases and 30 existing SDK cases passed together on both verified runtimes.
Follow the [SDK test instructions](../sdk/agentteams/node/README.md#本地验证) and set the two
test-directory variables to separate new owned directories. Cleanup verifies ownership first.
These regressions do not claim real vendor execution or deployment acceptance.

接口依据 / Primary references:
[Node 24.18 CLI](https://nodejs.org/download/release/v24.18.0/docs/api/cli.html),
[CommonJS modules](https://nodejs.org/download/release/v24.18.0/docs/api/modules.html),
[24.18 private loader](https://github.com/nodejs/node/blob/v24.18.0/lib/internal/modules/cjs/loader.js),
[25.2 private loader](https://github.com/nodejs/node/blob/v25.2.1/lib/internal/modules/cjs/loader.js),
[24.18 ESM interop](https://github.com/nodejs/node/blob/v24.18.0/lib/internal/modules/esm/loader.js).

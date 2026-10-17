# AgentTeams Node SDK

服务端 Node ES module，无第三方运行时依赖，不发布或全局安装包。
要求 Node >=24，且运行时能加载 `node:sqlite` 的 `DatabaseSync`。
已验证本地 Node 25.2.1 / SQLite 3.50.4 和目标机 Node 24.18.0；
其他版本须另验收。导入入口为本目录 `index.mjs`，ESM TypeScript 声明在 `index.d.mts`。
`index.d.ts` 提供兼容转导出。所用接口已按目标机 Node 24.18.0 官方文档核对，无 Node 25 专有调用。
不能在浏览器里使用或存放采集 Key。

普通 CommonJS 应用可用 [启动接入指南](../../../docs/agentteams-node-startup-guide.md)
通过 `node --require .../startup.cjs 原入口.js 原参数` 接入明确配置的导出函数，无需改业务文件。
启动入口只支持已验证的 Node 24.18.x / 25.2.x；ESM、worker threads、class 与预加载导出不承诺自动覆盖。
ESM 应用及上述边界继续使用本页的显式包装。两种方式均不重执行业务、不证明云授权或完整观测。

## 完成接入

1. 在「阿里云 → 云连接」配置 AgentTeams，完整盘点 Worker 与真实团队关系。
2. 在「日志源」创建 APIWebhook 源，再到「阿里云 → 消息与调用审计」绑定该源。
3. 在「设置 → API Key」建立只有 `sources:write` 的采集 Key。
   这是租户级权限，不能声称限定到某个日志源或 Worker。
   业务模型网关 Key 使用独立的 `models:write` 权限与真实 Worker 资产绑定。
4. 记录平台地址、sourceId、bindingId、scopeId、Mock 标识与 Key。
   每个进程/平台/来源/绑定使用独立本地队列目录，不能与 Python spool 混用。
5. 向应用安全环境提供 `AGF_PLATFORM_URL`、`AGF_SOURCE_ID`、`AGF_BINDING_ID`、
   `AGF_SCOPE_ID`、`AGF_EXPECTED_MOCKED=true|false`、`AGF_COLLECTOR_KEY`、`AGF_SPOOL_DIR`。
   地址只能 HTTP(S)，不能含账号、密码、查询或片段；远程部署请使用 HTTPS。
6. 执行 `node sdk/agentteams/node/examples/heartbeat.mjs`。
   `pending=0` 且 `sent+deduped=1` 表示确认本次遥测接收；同时核对 `durable`。
   `durable=false` 表示服务端离线内存模式，不证明服务端重启后仍保存事件。
7. 控制台检查来源、心跳和接收时间。心跳不产生业务调用、任务、Worker 或假成功。
8. 按下述方式包装自己的真实函数，业务完成后用 `flush`，退出前用有界 `close`。

```js
import { Collector, Config, Worker, inject } from './sdk/agentteams/node/index.mjs';
const collector = new Collector(new Config(settings)); // settings 从安全配置读取
const alice = new Worker('实际Worker名称', '实际团队名称');
const bob = new Worker('实际被调用Worker名称', '实际被调用团队名称');
const task = collector.task(alice, {
  mode: 'promise', operation: 'order.check', taskId: opaqueTaskId,
})(existingTaskFunction);
const call = collector.callWorker(alice, bob, {
  mode: 'promise', operation: 'risk.check',
})(existingWorkerCall);
// existingTaskFunction 内调用 call：调用方只记录一个 call，接收方记录自己的 task。
// 跨进程时将 inject() 的标识载体交给自己的业务协议；SDK 不修改业务请求头。
// 接收方 task(...,{carrier: incomingCarrier})：非法载体形成独立 root，不猜测因果边。
try { await task(actualArguments); }
finally { await collector.close(5); }
```

`mode` 必须按实际函数选择：同步 `sync`、Promise `promise`、同步生成器 `iterator`、
异步生成器 `asyncIterator`。默认 sync；误把 Promise 当同步不会提前记录 success。
Promise 模式返回包装 Promise，原 resolve 值与 reject 错误对象保持不变。
同步函数的返回对象、`this`、参数对象与抛出对象保持不变。
不改变模型客户端 URL、Key、超时、重试、AbortSignal、Response 或网关 403/429。

流包装逐次转发 `next/return/throw` 的实际值，不预读、缓存、重放或吞错误。
完整消费记枚举完成；开始消费后提前 return/取消记 unknown，异常原样抛出。
未开始消费就关闭的生成器不产生任务事件；耗时从首次 next 开始，不计创建后的闲置时间。
自定义可恢复 iterator 的失败可能保持未终结，直到实际 done/关闭；不伪造完成。
不自动包装 Node Readable/Web ReadableStream 或读取 HTTP Response 正文。
可选 `mcpResult` 只用于显式已解码的非流 MCP/JSON-RPC 结果分类：
`classify: mcpResult` 将工具 isError/协议 error 区分为 error，坏形状为 unknown。
默认 success 只说明函数正常完成，不证明未检查的 HTTP/MCP 业务结果成功。

## 隐私与上下文

默认 `capture:'omit'`：不采集参数值、提示词、响应正文、异常文本、headers、URL 或环境变量。
可选 `shape` 仅产生静态操作标签、参数数量及 values=omitted，不遍历对象/getter。
Worker/Team 必须与盘点身份一致；taskId/operation 必须是无敏感内容的静态或不透明标识。
任务、调用、实际消息处理使用独立事件 ID；caller/callee 不重复报同一次 call。
Trace/Span 只承接真实 AsyncLocalStorage 或显式载体，跨采集器自动上下文隔离。
采集 Key 只由专用 HTTP 客户端发送到配置的平台，不写入数据库、载体或状态输出。
配置只读；`rotateKey(newKey)` 只轮换同身份 Key，不更改队列的 source/binding/platform。
采集失败通过固定诊断码、dropped、pending 可见，不覆盖业务值或异常。

## 持久队列与故障恢复

终态事件 ID/时间/规范 JSON 先在 SQLite 事务内提交，再后台发送到：
`POST /api/v1/alicloud/agentteams/audit-sources/{sourceId}/events`。
Body 严格为 `{binding_id,events}`；没有 tenant/account/assetId/authorized 等伪造字段。
200 还必须校验 received/accepted/deduped、scopeId、Mock、durable、authorizationStatus。
HTTP 响应丢失或 ack 删除事务失败会保留原事件，再发送同 ID/时间/内容，依赖平台去重。
只重传遥测，不执行原业务函数，也不是业务任务 replay。

| 状态 | SDK 行为与处理 |
|---|---|
| 网络失败、超时、5xx、坏200 | 保留事件，有限退避；检查地址/网络与 lastError |
| 429 | 保留，缩小批次与退避；核对来源 EPS，而非重做业务 |
| 401/403 | 暂停；修复采集 Key/权限，同身份轮换后 resume |
| 400/404/409/413、3xx | 隔离原事件；409/重定向暂停，排查绑定/内容/地址 |
| 队列满或磁盘故障 | 保留原未确认项，新增事件 dropped 可见；不删除最老证据 |

任何重定向都不跟随；Key 和 payload 不会送到新目标。响应错误正文不进入日志。
重绑后使用新目录：旧目录保留供人工核查，不能把旧队列改绑重发。
quarantined 不会因 resume 自动换 ID 或重投，SDK 不提供无条件删除/重绑方法。

默认最多 10,000 项、16 MiB 逻辑 payload、64 MiB SDK 文件预算。
磁盘预算支持 512 KiB–256 MiB，主库页上限扣除 256 KiB 后按 `(2*pageSize+8)` 计算；
这为独立锁库、两库 DELETE 回滚日志及头部留空间。关闭 cache_spill，使用 FULL 同步，
不使用 WAL、savepoint、ATTACH、磁盘临时表或 VACUUM；SQLite 内部开销也可能提前导致拒绝新增。
预算只包括 SDK 自有文件，不包含用户其他目录数据。禁止网络共享、符号链接/目录联接。
SQLite API 为同步调用，提交可能增加少量本地 I/O 延迟；网络投递在后台，不保证零延迟或无限无损。

同目录由独立 `collector-lock.sqlite` 保持 BEGIN EXCLUSIVE 的 OS 锁。
第二 owner 直接失败；进程崩溃后 OS 释放锁，SQLite 恢复自有 hot journal。
不根据 PID、超时或时间戳擅自抢锁。未知 DB、身份冲突、损坏或未完成初始化不自动接管。
关闭预算到期会取消自己的遥测请求，保留队列；释放锁可能要等该请求的清理完成。
未消费完的流、进程在产生终态前退出、采集丢失均可能形成观测缺口，不能宣称完整覆盖。
Mock 标签由平台绑定与 ack 核验，不证明真实云调用权限或调用授权。
Node 内置 SQLite 的状态取决于版本；24.18.0 官方说明为 release candidate，仍应固定版本并验收。

接口依据：[Node 24.18.0 SQLite](https://nodejs.org/download/release/v24.18.0/docs/api/sqlite.html)、
[SQLite 锁与崩溃恢复](https://sqlite.org/lockingv3.html)。

## 本地验证

从项目根目录执行。给原 SDK 和启动注入测试各自创建独立、全新的空目录，不能共用业务队列：

```powershell
$validation = Join-Path (Get-Location).Path ('.codex-tmp/agentteams-sdk-tests/' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $validation) { throw 'Validation directory must be new' }
$env:AGF_NODE_SDK_TEST_DIR = Join-Path $validation 'sdk-runtime'
$env:AGF_NODE_STARTUP_TEST_DIR = Join-Path $validation 'startup-runtime'
New-Item -ItemType Directory -Path $env:AGF_NODE_SDK_TEST_DIR, $env:AGF_NODE_STARTUP_TEST_DIR | Out-Null
try {
  $tests = @(Get-ChildItem -LiteralPath 'sdk/agentteams/node/tests' -Filter '*.test.mjs' | ForEach-Object { $_.FullName })
  node --test --test-concurrency=1 @tests
} finally {
  Remove-Item Env:\AGF_NODE_SDK_TEST_DIR, Env:\AGF_NODE_STARTUP_TEST_DIR -ErrorAction SilentlyContinue
}
```

回归仅使用标准库、本地 HTTP、SDK 自有临时 SQLite 与受控子进程。
两个测试组分别核对自己的根标记、绝对路径与无链接归属后清理测试案例；SDK 根标记可能保留。
清理上述新建验证目录前仍须核实路径、标记与归属，不删除业务队列或其他任务数据。
完整 53 项（原 SDK 30 + 启动注入 23）已在 Node 25.2.1 与 24.18.0 实际通过。
这些回归不构成真实云凭据、云 API、业务任务重放或消费者部署验收。

For the full suite, set both `AGF_NODE_SDK_TEST_DIR` and `AGF_NODE_STARTUP_TEST_DIR` to
separate, new absolute directories as shown above. Tests use their own ownership markers and
loopback receivers; never point them at application queues. CJS preload coverage and explicit
ESM wrappers have different boundaries. The two verified runtimes passed all 53 cases.

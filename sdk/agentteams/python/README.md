# AgentTeams Python 接入 SDK

将实际执行的 Worker 任务、Worker 调用和消息发送记录到 AIGuardFabric。
SDK 使用 Python 3.10 及以上版本和标准库，不需要安装第三方依赖。

## 接入前准备

1. 在控制台配置 AgentTeams 区域、命名空间和接入范围，执行资源同步。
2. 在审计数据源页面创建一个采集源，绑定上述接入范围。
3. 保存数据源 ID、绑定 ID、范围 ID 和采集 Key；Key 只在签发时显示。
4. 用库存中实际存在的 Worker 名称和 Team 名称标记业务参与者。
5. 将 `agf_agentteams` 目录复制到业务项目，或将本目录加入 `PYTHONPATH`。

采集 Key 属于数据源，控制台管理员密码不能用于采集接口。
测试配置使用 Mock 范围；生产接入应明确设置 `expected_mocked=False`。
`expected_scope` 和 `expected_mocked` 会核对平台返回的确认信息。
范围或绑定改变时使用新的队列目录，避免把旧事件送到其他范围。

## 最小接入

```python
import os
from pathlib import Path
from agf_agentteams import Collector, Config, Worker

collector = Collector(Config(
    platform_url=os.environ["AGF_PLATFORM_URL"],
    source_id=os.environ["AGF_SOURCE_ID"],
    binding_id=os.environ["AGF_BINDING_ID"],
    collector_key=os.environ["AGF_COLLECTOR_KEY"],
    spool_dir=Path(".agf-telemetry/orders"),
    expected_scope=os.environ["AGF_SCOPE_ID"],
    expected_mocked=False,
))
orders = Worker("orders-worker", "orders-team")
billing = Worker("billing-worker", "billing-team")

@collector.call_worker(orders, billing, operation="calculate-price")
def calculate_price(quantity):
    return quantity * 12

@collector.task(orders, operation="quote", task_id="opaque-order-42")
def quote(quantity):
    return calculate_price(quantity)

try:
    value = quote(3)
finally:
    health = collector.close(timeout=5)
```

装饰实际业务函数即可，原返回值和原异常会传给调用方。
`task_id` 是不含用户内容的业务标识，不能填写提示词、邮箱或请求正文。
`operation` 使用固定操作名。Worker 和 Team 应与实际执行者一致。
队列故障会记录在健康状态中；SDK 不会因此重新执行业务函数。

## 异步和流式函数

同一装饰器支持 `async def`、生成器和异步生成器。
流按调用方的节奏产生结果，SDK 不会预先消费响应、缓存正文或再次调用模型。
完整耗尽后记录成功；原异常记录错误；主动关闭或取消记录取消状态。
提前结束消费时，请调用原流支持的 `close()` 或 `await aclose()`。
从未开始消费的流不会制造已经执行的任务记录。

任务内的调用会继承上下文。不同线程或进程之间需显式传递标识：

```python
from agf_agentteams import inject

# 在实际任务执行期间调用。返回值只有 trace_id/span_id 和可选 task_id。
carrier = inject()
# 通过业务已有的元数据通道传递 carrier。
# 接收端将 carrier 提供给装饰器；请求级使用 callable 读取当前请求元数据。
@collector.task(billing, operation="handle-message", carrier=lambda: request_carrier())
def handle_message():
    return process_existing_message()
```

`request_carrier` 和 `process_existing_message` 是业务已有函数。
无效 carrier 会创建独立根记录，不会猜测父子关系。
跨进程上下文中的 Worker 名称不能作为云端授权证明。

## 结果判定和采集内容

默认成功表示函数正常完成。若正常返回的对象包含业务失败，应显式传入
`classify=lambda result: ...`，返回 `success`、`error` 或 `unknown`。
MCP 工具调用可使用 `agf_agentteams.classifiers.mcp_result`；不明结构保持未知。
SDK 不复制或改写原返回对象；分类器应同步、只读地检查结果。
分类器或诊断回调失败时，业务结果仍原样返回。

默认 `capture="omit"`，不采集实参、返回值、提示词、消息正文或异常文本。
`capture="shape"` 只记录固定操作名和参数数量，不记录参数名与参数值。
`collector.message(sender, receiver, status=...)` 应在实际发送或处理后调用。
SDK 不会代替业务发送消息。`collector.heartbeat()` 是显式的独立心跳。

## 队列、确认和恢复

SQLite 队列保存稳定事件 ID，只有有效平台确认才删除待发送事件。
网络失败、响应丢失或服务端临时失败会按原 ID 重传遥测。
平台支持按数据源、绑定和事件 ID 去重；这不代表业务请求可以重复执行。
`durable=True` 表示本次确认由平台持久化路径返回，不能把未确认的事件算作成功。

默认上限为 10000 个事件、16 MiB 事件正文、64 MiB SDK 自有数据库/日志/锁文件预算。
磁盘预算可设置为 256 KiB 至 256 MiB，预留活动事务日志与数据库索引空间；
因此实际可用事件容量也受磁盘预算限制。业务目录内其它文件不计入此 SDK 预算。
队列满时保留旧事件，拒绝新事件并增加 `dropped`。
每批至多 100 个事件、256 KiB，请求超时默认 5 秒。
同一个目录只允许一个 Collector；每个进程/采集源应使用独立目录。
进程退出后可使用同一平台、采集源和绑定重启恢复待发送事件。
新 Key 可以用于原队列；平台、范围或绑定不能静默替换。

| 健康状态 | 处理方式 |
| --- | --- |
| `network_error`、临时服务错误 | 检查网络和平台健康，保留队列等待重试 |
| `http_429` | 等待限流退避；SDK 会缩小批次 |
| `http_401`、`http_403` | 发送暂停，待发送数据保留；修复 Key/权限后调用 `resume()`，Key 更换需重建 Collector |
| `http_409` | 冲突事件隔离且发送暂停；核查原数据源、绑定和事件内容，不生成新 ID 重发 |
| `http_400`、`http_404`、`http_413` | 拒绝事件隔离；检查配置、接口版本或数据大小 |
| `http_3xx` | 不跟随重定向，不转发 Key；修正明确的平台 URL 后使用匹配的新目录 |
| `invalid_ack` | 保留原事件，核查平台版本、代理响应与范围/Mock 配置 |
| `queue_write_failed` | 新事件未入队，检查空间和目录权限；业务仍正常返回 |

隔离数据仍占队列容量。`resume()` 只恢复原待发送数据，不释放隔离数据。
修复配置后，应先查看健康状态和平台接收统计，不要删除含未确认事件的目录。

## 健康检查和停机

`collector.status()` 返回 `pending`、`quarantined`、`sent`、`deduped`、`dropped`、
`paused`、`last_error`、`durable` 和 `delivery_active`，不会返回 Key 或事件正文。
`on_status` 可接收同样的状态，但回调应快速完成。
`flush(timeout=5)` 等待确认，`close(timeout=5)` 拒绝新记录并停止后台发送。
超时后待发送数据仍留在磁盘；`delivery_active=True` 表示正在结束一次已发请求。
此时请等待线程结束后再用同一目录启动另一个 Collector。

## 本地检查

```powershell
$env:PYTHONPATH = (Get-Location).Path
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B -m unittest discover -s tests -p 'test_*.py' -v
```

测试只调用自有回环 HTTP 接收器，不使用真实云凭据。
运行 `examples/basic.py` 前需设置上述环境变量以及实际 Worker/Team 名称。
平台接入验收仍需核对数据源接收统计、范围、去重计数与完整调用链证据。

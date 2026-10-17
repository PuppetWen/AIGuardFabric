# MSE Nacos 平台策略发布与显式回滚

本功能把平台中已启用、已签名的指定策略版本生成可信 JSON 包，发布到管理员明确授权的专用 Nacos Data ID。它独立于资产盘点和平台策略编辑：发布成功不会改动平台策略版本，也不能证明网关、MSE/APIG 或外部应用已经加载并执行该包。`consumerApplied` 始终为未知。

## 配置专用目标

在阿里云 MSE 连接 `alicloud-mse` 中保存设置。首次保存使用配置版本 0；工作流只接受已经保存的正版本。以下目标字段必须明确填写：

| 设置 | 填写方式 |
|---|---|
| `engine_origin` | Nacos 引擎 HTTPS origin，如 `https://engine.example:8848`；不能填写路径、查询或阿里云 OpenAPI 地址 |
| `region_id`、`instance_id` | 该目标的明确地域和实例 |
| `namespace_id` | 命名空间 ID；公共命名空间明确填写空字符串 `""`，不填写显示名称 `public` |
| `config_group`、`config_data_id` | 平台专用 group 与 Data ID；保留输入原值，不自动裁剪或改名 |
| `config_dialect` | 固定 `nacos-http-v2-cas` |
| `managed_upsert_confirmed` | 明确确认平台可以管理这个专用 JSON 目标，设为 `true` |

现有 `settings.endpoint` 仍表示阿里云 OpenAPI 地址，不能代替 `engine_origin`。更换引擎 origin 会清除旧凭据，管理员可以在同次保存中明确提供新凭据。账号、实例、目标元组或 Mock/Live 模式改变会隔离来源范围；配置版本改变会使旧观察和预览失效。

凭据沿用连接的 AccessKey、STS 或受支持的角色来源。引擎 RAM 读取和写入授权须单独配置；能够查询 MSE 实例不证明能更新 Nacos 配置。参见 [MSE 配置中心细粒度授权](https://www.alibabacloud.com/help/en/mse/user-guide/fine-grained-authorization-in-configuration-centers)。

平台读取权限为 `alicloud:read` 与 `policies:read`。准备、发布、本地恢复和归档另需 `alicloud:write`；本功能不修改资产和平台策略，不要求 `assets:write` 或 `policies:write`。

## 先用持久 Mock 验证流程

启用 Mock 后使用以下固定示例目标；未知目标不会被编造成存在：

```json
{
  "engine_origin": "https://mse-agf-demo.invalid",
  "region_id": "cn-hangzhou",
  "instance_id": "inst-demo",
  "namespace_id": "",
  "config_group": "AGF",
  "config_data_id": "agf-policies.json",
  "config_dialect": "nacos-http-v2-cas",
  "managed_upsert_confirmed": true
}
```

Mock 独立持久化并加密目标内容，初始内容为 `{}`。发布会真实修改该隔离字典，随后回读；工作流审计失败不会假装撤销已被 Mock 接受的写入。租户、账号来源和模式不同的字典相互隔离。生产只接受 HTTPS；HTTP 回环仅供服务端显式注入的测试能力，不能通过用户配置授权局域网 HTTP 或任意来源。

## 发布步骤

1. 点击“观察”，读取目标的确切 UTF-8 内容和 `Content-MD5`。失败后不会继续使用旧基线。读取只显示 hash、MD5、字节数和时间，不返回配置正文。
2. 选择 1–20 条已启用的策略及明确版本，生成预览。服务器验证全部签名、当前版本、Agent 范围、配额与降级模型依赖。变化或超限会拒绝整个候选，不截断选择。
3. 核对目标、基线 MD5、期望 hash、来源版本和过期时间。明确确认专用目标的 upsert 语义。真实 Live 另需当次确认；Mock 和服务端回环测试不假称 Live。
4. 显式应用预览，以新的操作 UUID 领取。一个预览只能领取一次；同 UUID 与同请求内容只读取原事实，任何失败、取消、归档或审计回滚都不会重新发送原写入。
5. 分别查看云写入、回读、本地终态三个阶段。只有 `accepted`、`matched` 和本地 `published` 同时成立才显示 `verified`。

内容 MD5 CAS 是 **upsert**：对象被并发删除后仍可能创建，不保证“只更新已经存在的对象”。同内容改走又改回的 ABA、type/元数据变化和客户端加载不在该证据范围。精确 v2 错误码 `20005` 才按已验证协议归为 CAS 冲突；普通 HTTP 500、HTML 或未知响应保持未知。协议说明见 [Nacos v2 Open API](https://nacos.io/en/docs/v2/guide/user/open-api/) 和 [驱动指南](mse-nacos-driver-guide.md)。

## 回执、恢复与未知结果

| 状态 | 操作方式 |
|---|---|
| `verified` | 原写已接受、回读匹配且本地审计已提交；仍不能推断外部消费者生效 |
| `conflict` / `failed` | 保留原回执；显式重新观察、生成新预览后准备独立新意图 |
| `pending_audit` | 已加密保存已知云阶段，本地终态尚未提交；点击“本地恢复”，不再接触云端 |
| `uncertain` | 原写的送达或结果不确定；不能因当前内容匹配而提升为原写成功 |
| 过期 `started` | GET 仅显示未知；先显式本地恢复，把原事实记录为 Unknown，不能直接复用旧预览 |
| `superseded` | 当前账号目标范围已改变；原来源和事实保留，不能移到新账号恢复云观察 |
| `archived` | 原终态和 UUID 事实仍在；正文已移除，不再能用这条记录回滚 |

GET 回执严格只读，不完成状态、不追加成功审计、不发送 provider/STS 请求。本地恢复只发布已保存的加密事实；配置停用、变版或原策略变版不妨碍具备当前权限的用户记录原事实。`sourceCurrent` 为 `false` 表示确定已停用或来源/依赖改变，为 `null` 表示尚不能验证；两者都不是原写被撤销。

云端未知写入可能在本地租约到期后才迟到。原 UUID 永不重派。若确需独立的新业务发布，必须先恢复旧未知事实，再在旧租约过期之后开始并完成一次新观察，在新预览承认原未知操作 ID，并在应用时再次明确确认重叠风险。这个新操作不是安全重试，不能证明旧远端请求停止；旧未知事实和风险会保留。

取消或断线只取消尚在本请求中的网络 future，无法撤回已经送出的请求。取消后的本地完成任务只保存静态回执，不会继续云写。审计失败、权限撤销或原 JWT 到期后，已知云接受证据仍可加密暂存，由当前授权用户显式恢复本地记录。

## 显式回滚和长期容量

选择同租户、同账号目标、已验证且未归档的历史正文，重新观察当前目标并生成回滚预览。回滚以新的 UUID 和新的内容 MD5 CAS 发布历史的确切可信字节；它不会降低平台策略注册表的版本。当前策略必须仍启用，当前版本与实际依赖仍需验证，旧正文签名和来源不会被替换成新政策。

最多保留 128 条有正文的操作。达到容量后先勾选已发布终态、非活动领取的记录，核对数量和最新归档代次，再一次归档最多 100 条。归档原子移除所选回滚正文，保留原终态、永久 UUID 和轻量归档标记。已归档 UUID 仍不能重新派发；同代次重复归档无新审计，旧代次返回 409，须重新读取后明确确认。

明细最多显示最近 50 条操作和同目标 50 条可回滚历史；旧 UUID 可直接查询，不需要扫描全部历史。正文总预算 64 MiB、单正文 256 KiB、单记录 1 MiB；预览最多 32 条、观察正文最多 8 条。执行总预算 110 秒包含本次等待、凭据、守卫、查询、唯一 POST 和回读，租约 120 秒，驱动单次 30 秒，预览有效 120 秒，观察基线有效 300 秒。超时不能续租后重发。

## API 与实现边界

基础路径：`/api/v1/alicloud/mse/config-publication`。成功响应直接返回安全 DTO，输入使用 snake_case，输出使用 camelCase。

| 方法与路径 | 用途 |
|---|---|
| `GET /` | 本地状态、限额、最近操作与可信历史 |
| `POST /observe` | 新的只读目标观察 |
| `POST /previews` | 可信策略发布或历史回滚预览 |
| `POST /operations` | 领取并执行一次新写入 |
| `GET /operations/{id}` | 原操作纯本地回执 |
| `POST /operations/{id}/observe` | 返回新的独立 Observation；原写状态不变 |
| `POST /operations/{id}/recover` | 空对象 `{}`，纯本地终态恢复 |
| `POST /operations/archive` | `expected_generation` 与明确 UUID 列表，原子归档 |

数据库模式将领取、预览消费、终态、归档和各自审计放入一致事务，并在审计等待之后重查当前权限、原会话和 JWT 有效性。离线模式保证配置候选与可信同步审计同一配置锁发布；用户、角色、API Key 和 Agent 使用独立存储，只在提交前重查，不声称跨独立存储变更完全线性化。多实例与重启验收依赖数据库持久化，不能把纯内存进程当持久服务。

本工作流不实现自动离线补传、不把实例任务当业务任务重放，也不发布到其他适配器或验证外部消费者加载。实际云端 stage 2 写入须在明确选择的真实测试目标另行验收；本次自动验收只使用持久 Mock、专属数据库和自有 `127.0.0.1` 协议服务。

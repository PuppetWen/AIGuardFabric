# 原生任务绑定与执行回执

本指南说明原生绑定执行协议。启用前核对实际 API 与 `agf-scheduler` 镜像版本，并完成当前部署的回环验收。保存关联、健康检查或 `/tasks` 列表不能证明云任务已经注册、外部入口可达或业务执行成功。

## 个人单机

不需要云调度时使用 `AGF_SCHEDULER_BACKEND=local-cron`，按 [定时任务指南](scheduler-guide.md) 配置目录、日志源、规则和平台 Key。原生云观察/绑定不影响本地 cron。

使用云 HTTP 执行器时，分别运行主 API、PostgreSQL 与调度器。平台 origin 指向 API 根地址；回调地址指向调度器的 9101。云执行器必须能访问该入口，局域网地址不会自动变为云可达地址。

## 企业接入顺序

1. 在控制台选择实际租户，保存并启用 `alicloud-schedulerx3` Live 连接，核对地域、集群、应用与账号。平台 API Key、RAM 凭据和 callback token 是三个不同身份。
2. 在「原生调度观察」明确执行完整观察；核对云端实际 AppId、启用 HTTP Job 与精确字符串 JobId。任务名称不能代替任务身份。
3. 在观察完成后的 300 秒内明确采用最新本地 CAS 版本和所读观察，逐项选择并确认保存。已保存证明不因 300 秒到期而失效；原正文归档后证明仍保留。
4. 新观察发现任务消失、停用或已知非 HTTP 类型时，资格会撤销；未知类型/状态会变为未验证。后来正面观察不会自动恢复资格。核对后重新明确采用并保存；来源或版本改变同样需要重新采用。
5. 给此租户创建专属服务 API Key，仅授予所需权限；通过部署 Secret 注入 `AGF_SCHEDULER_API_KEY`。不要用交互登录 JWT、跨租户管理员身份或 callback token 替代它。
6. 设置 `AGF_SERVER_URL` 为固定 API 根 origin，设置非空租户 UUID、实际 AppId 与独立 callback token。`AGF_SCHEDULER_BACKEND=schedulerx3` 启动时检查身份和当前关联，不能靠旧文档或连接开关绕过。
7. 将云任务配置为 POST 调度服务 `/api/v1/internal/jobs/{kind}`，按任务类型配置目录、日志源和网络权限。HTTP 头使用独立 callback token；执行器须提供实际 AppId/JobId/JobExecutionId 与一致分片总数。
8. 先验证根任务，再按下表完成依赖批次。查看实际云回调、原平台回执和本地产物。云注册、TLS 可达性与真实业务验收分别检查，不由本地采用按钮自动完成。

| 配置 | 用途 |
|---|---|
| `AGF_SERVER_URL` | 固定平台 API 根 origin，例如 Compose 的 `http://agf-server:8080` |
| `AGF_SCHEDULER_TENANT_ID` | 与服务 Key 身份完全相同的非空租户 UUID |
| `AGF_SCHEDULER_API_KEY` | 通过 Secret 注入的当前同租户平台 Key |
| `AGF_SCHEDULER_CALLBACK_APP_ID` | 云应用规范正 int64 十进制字符串 |
| `AGF_SCHEDULER_CALLBACK_TOKEN` | 独立 32–256 字节 token，不进入 URL、SQL 关联或日志 |
| `AGF_REPORT_DIR` | 调度业务输出目录；部署身份须可读写 |
| `AGF_RULES_DIR` | 规则目录；策略重载必须能严格加载 |

平台调用带 `X-AGF-Key` 与 `X-AGF-Tenant`。新客户端不跟随重定向或使用代理覆盖；API origin 不允许用户名、密码、查询参数或非根路径。

## 六类任务和依赖

所有协议操作需要 `alicloud:read`，再加对应任务权限。业务的可选子操作仍检查各自权限，例如 AgentTeams 自动盘点另需 `alicloud:write/assets:write`。

| canonical kind | 执行器别名 | 额外平台权限 | 必须先完成的上游 |
|---|---|---|---|
| `asset-inventory` | 同名 | `assets:read` | 无 |
| `rule-hot-reload` | 同名 | `policies:write` | 无 |
| `log-pull` | 同名 | `sources:read/write` | 资产盘点 |
| `redteam-cruise` | 同名 | `redteam:read/execute` | 资产盘点 |
| `report` | `report-generate` | `reports:write` | 资产盘点、日志拉取 |
| `archive` | `cold-archive` | `reports:write` | 报表 |

上游必须来自当前可信采用映射、相同来源/App/Job/采用版本，且最新批次的全部声明分片在 24 小时内明确成功、未跳过。旧来源、旧采用、部分成功、未知、失败或跳过均不满足依赖。新批次会替代旧进度；迟到旧结果不会覆盖它。

资产汇总、规则重载、报表汇总须设置单分片 `total=1`。旧部署若把资产配置为默认 4 片，非 0 片会跳过，不能满足下游完整成功条件；请明确修改云任务路由并用新执行批次验证。新平台默认资产分片已设为 1，修改源码不自动改变既有云任务。

云回调不会悄悄补跑上游，也不会通过旧 lane 自动重试业务。412 时先检查上游最新批次与当前资格。没有配置日志源的跳过结果不能使下游报表获得上游成功条件。

## 确认启动与查看结果

领取响应的 `mayConfirmStart=true` 只允许确认启动。只有第一次成功提交的 validate 响应 `mayExecute=true` 才允许调用处理器一次。任何重复响应、GET、终态提交或未知状态都没有新启动权。启动许可受原 110 秒窗口约束；处理器最多使用服务端执行租约剩余时间，上限 300 秒。

永久身份为租户、AppId、JobId、JobExecutionId 与分区。更换 kind、来源、绑定版本或请求 UUID 不会创建原业务的新执行机会。分片总数中途改变会冲突；被新批次替代的旧批次不能再领取尚未领取的分区。

回调安全 JSON 会提供原 factId/claimId 和状态；不会提供 API Key、原始业务 note、回调参数或制品绝对路径。制品只报告实际输出文件的 SHA-256 与字节数；它是执行器报告，不是云厂商独立证明。

| 状态 | 用户操作 |
|---|---|
| `admitted` | 尚未确认启动；只有原首次许可持有者可在窗口内确认 |
| `running` | 已消费启动许可；读取原状态，不能重跑 |
| `uncertain` | 原启动/执行租约已过或响应无法确认；核对业务记录与制品，不重派原身份 |
| `pending_audit`（completionState） | 已知结果已保存；仅用原 claimId 与相同 outcome 明确再次提交 complete |
| `complete`（completionState） | 原终态与唯一业务审计已发布；核对 succeeded/failed、skipped/degraded 与产物 |

只读查询需要原同租户服务 Key 仍有效，并保有该任务权限。管理员交互 JWT 不可代替原服务身份。API Key 轮换前先核对未完成的执行；新 Key 不能接管旧事实。

在受控部署终端查询，不打印 Secret：

```powershell
$headers = @{ 'X-AGF-Key' = $env:AGF_SCHEDULER_API_KEY; 'X-AGF-Tenant' = $env:AGF_SCHEDULER_TENANT_ID }
$api = $env:AGF_SERVER_URL.TrimEnd('/')
# requestId 是此次最初提交的 UUID；factId 是回执里的原事实 UUID。
Invoke-RestMethod -Headers $headers -Uri "$api/api/v1/alicloud/schedulerx3/native/callback-executions/requests/$requestId"
Invoke-RestMethod -Headers $headers -Uri "$api/api/v1/alicloud/schedulerx3/native/callback-executions/$factId"
```

领取响应丢失时按原 request UUID 查询，启动响应丢失时按原 factId 查询。即使 GET 返回 running 或已有结果，也不能把它当作重新运行许可。未知 UUID 为 404；GET 不领取、修复、写审计或再次访问云端。

已知结果的终态提交可以晚于原租约，但仍要求当前原 Key、任务权限、租户与原 claim 身份；来源之后停用或改变不会把原业务证据伪装成新执行许可。审计故障后恢复仅发布已保存同正文结果，不调用业务处理器。

只有真实业务记录与产物能说明执行效果；本协议不能保证所有外部系统恰好一次。红队巡航仍是平台模拟战役，文件 gzip 归档与业务事件 Parquet 冷归档是不同功能，详见各业务指南。

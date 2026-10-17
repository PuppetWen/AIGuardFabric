# 阿里云连接、操作和台账指南

适用：控制台「阿里云」及「接入指南 → 阿里云接入」。模拟连接和操作已部署；真实云账号联调属于阶段二。

## 个人用户：先用模拟数据走通

1. 登录并确认右上角租户，进入「阿里云」。每个服务都有独立「配置」入口。
2. 开启连接和模拟模式；地域先选 `cn-hangzhou`。AgentTeams 的实例填 `inst-demo`；模拟模式无需真实密钥。
3. 保存。保存只写入当前租户的加密配置，不访问云端。
4. 在「操作与回执」选择查询，按表单填写必填字段，执行。结果明确标记 Mock。
5. AgentTeams 的「台账同步」可完整盘点模拟团队、Worker 和任务。团队成员名称链接到资产详情；模拟资产与真实资产分开归并。
6. 团队详情可查看云端任务、云端人员和 Worker。没有真实来源的调用次数、风险分显示 `—`。

Mock 验证接口和页面流程，不验证云端网络、授权、配额或计费。示例来源与调整记录见 [样本来源](../tests/fixtures/alicloud/SOURCES.md)。

## 企业用户：配置账号、实例和网络

为不同组织选择相应租户；配置、凭据、快照与回执按租户隔离。目前每个租户每种云服务使用一份活动连接；多个实例应分别配置租户。

1. 在云控制台准备最小权限 RAM 身份及目标实例。配置人员需要平台 `alicloud:write`；台账同步另需 `assets:write`。
2. 选择地域和官方公网/VPC 接入点。VPC 入口要求平台机器已有相应网络通路，选择它本身不会创建 PrivateLink。特殊网络可填 HTTPS 服务根地址，不能带路径、查询参数或 URL 用户名密码。
3. 选择凭据来源：
   - **ECS 实例 RAM Role**：为 ECS 绑定实例角色，选此项；角色名可留空由 IMDSv2 发现，无需 AccessKey。仅访问官方元数据地址，禁止退回无令牌的 IMDSv1。
   - **Kubernetes OIDC 工作负载身份**：部署端投射短期 ServiceAccount Token，挂载到服务容器并设置 `ALIBABA_CLOUD_OIDC_TOKEN_FILE`；配置受信任的 OIDC Provider ARN 和目标 Role ARN。平台使用 `AssumeRoleWithOIDC`，刷新时重新读取投射文件，不保存长期密钥。
   - **AssumeRole**：源 AccessKey，或源 STS 三件套及其到期时间；填写目标 Role ARN、会话名称，按需要填写 External ID 和限制策略。服务端在使用前交换 STS，并在临近到期时刷新。
   - **已有 STS**：AccessKey ID、AccessKey Secret、Security Token 和真实 RFC3339 到期时间，例如 `2026-09-20T15:00:00Z`。过期会明确失败，需换新会话。
   - **RAM 用户 AccessKey**：适用于已配置最小权限的账号。平台按租户加密保存；界面不回显秘密值。
4. 空密码框保留旧凭据；勾选清除才删除。改变账号、地址、角色或凭据来源会清除原有凭据，防止误发到新目标。看到版本冲突时重新加载再编辑。
5. 关闭模拟模式并保存，然后进入「操作与回执」，核对地址，勾选真实调用确认，运行只读自检。
6. 只有当前配置近期成功的实际只读连通性调用才显示通过。单次调用不能证明账号遵循最小权限，最小权限和云配额在缺少独立检查时保持「待核对」，且不显示虚构的检查时间。写操作权限、资源访问范围和配额需分别核对；修改配置使旧检查失效。

长期密钥、会话凭据和原始云快照均加密保存。备份数据库时须一并按部署手册保管主密钥，否则不能解密已存连接。

使用 ECS/OIDC 主机身份前，部署端须将授权租户 **UUID** 加入 `AGF_CLOUD_WORKLOAD_TENANTS`（逗号分隔，不接受 `*`）。这样其他租户无法仅靠修改连接配置读取主机身份。UUID 可在租户管理中查询。原生服务通过进程环境变量配置；Compose 已透传这些变量，但 Token 文件需要另行只读挂载，并将环境变量设为容器内路径。Kubernetes 应将投射 Token 的 audience 设为 RAM OIDC 提供商允许的值，并收窄角色的 issuer/subject/audience 信任条件。

`ALIBABA_CLOUD_OIDC_PROVIDER_ARN` 可提供部署默认值；也可以在当前租户连接中填写 Provider ARN。不要在网页中粘贴 ServiceAccount Token。ECS/OIDC 凭据只缓存在进程内，到期前按需重新获取；模拟模式完全跳过身份网络请求。

## 各服务的实际操作

| 服务 | 配置与入口 | 操作顺序 |
|---|---|---|
| CMS | 地域、应用分组 ID | 查询报警历史 → 上报测试事件 → 上报自定义指标。事件字段为 `EventInfo`，指标为 `MetricList`。公开 API 为 `PutCustomMetric`；需求文档中的 `PutResourceMetricData` 不在当前 CMS API 定义中 |
| APIG | 地域、目标网关/API 标识 | 查询网关和 HTTP API → 查询插件类型 → 安装插件 → 绑定插件或创建并绑定策略。表单保留厂商的小写字段和 JSON body；配置编码须遵循所选插件/策略要求 |
| MSE | MSE 实例 ID、Nacos 命名空间 | 查询集群 → 查询 Nacos 服务/配置 → 按 DataId/Group 读取内容 → 创建或更新配置。API 版本为 `2019-05-31`，不是旧实现中使用的版本 |
| PrivateLink | 地域、终端节点 ID | 查询节点 → 读取节点状态、可用区与关联安全组。关联安全组不等于全部网络流量已可达；实际业务端口需从部署网络验证 |
| SchedulerX3 | 集群 ID、应用名称 | 查询任务 → 创建/更新任务 → 查询执行记录。删除使用 `DeleteJobs`，JobIds 是 JSON 数组；执行器必须先按云端要求接入 |
| AgentTeams | 实例 ID | 查询团队/Worker/任务 → 完整盘点并同步台账 → 按需修改团队或 Worker。团队中的人员 `TeamMembers` 与执行 Worker 是不同概念，替换成员前先读现有值 |

所有操作保留厂商字段大小写。嵌套对象/数组以 JSON 编辑，服务端按接口定义校验；未知字段不会静默丢弃。可选参数和分页参数可展开。

平台策略的专用发布入口为 [MSE 专用配置发布](/alicloud?tab=mse-config)，完整步骤见 [发布、回执恢复、回滚与归档指南](mse-config-publication-user-guide.md)。先绑定独立 Nacos `engine_origin`、地域、实例、明确 namespace、Group 与专用 Data ID；原 OpenAPI `settings.endpoint` 不能替代引擎地址。明确观察、选择真实已启用且签名的策略版本、生成预览并确认后才发送；回执验证不代表外部消费者已经加载。

## 开发侧适配器接入约定

控制台的「操作与回执」使用已登记的公开 API。直接调用 Rust Adapter 接口时，还须遵守以下约定：

- MSE 的服务/配置操作需 `instance_id`，可选 `namespace_id`。配置列表会继续读取详情，防止把摘要当成空配置。创建配置时 `md5` 留空；更新时传最近读到的 `md5` 作为并发修改前置条件。发布返回云请求编号。同步不会自动下发演示策略。
- CMS 指标需填写真实应用分组 `group_id`；`namespace` 是平台分类，不替代云分组。上报调用 `PutCustomMetric`，值与维度按厂商要求编码。报警拉取使用 `DescribeAlertHistoryList`，通用 pull 响应通过 `next_cursor` 提示继续读取。
- APIG 使用 ROA 路径与 ACS3 签名。先在控制台查询插件类型并安装，取得 `pluginId`；Rust `push_policy` 的 `config` 填 `plugin_id` 和 `plugin_config`（插件 YAML/JSON 原文，程序编码为 Base64），可填 `environment_id`。空 `route_ids` 绑定指定网关，否则绑定指定路由。返回插件绑定 ID；断网后先查询绑定结果，禁止直接重建同一写操作。限流/配额/安全插件的配置格式必须对应实际安装的插件，不能把演示策略参数直接发布。
- APIG 访问日志应通过网关配置的 SLS/Kafka 日志源接入；APIG OpenAPI 不提供旧代码假设的 `ListAccessLogs`。
- PrivateLink 盘点读取节点、可用区和关联安全组；配置 `probe_port` 后，`probe` 参数传终端节点 ID，程序从部署机器连接该节点域名的实际 TCP 端口。连接成功不代表 TLS 或业务认证通过。
- PrivateLink 安全组规则从 ECS `DescribeSecurityGroupAttribute` 读取，须另外授权 `ecs:DescribeSecurityGroupAttribute`。私网模式必须配置可达的 `ecs_endpoint`，不自动切换公网。CIDR 非法、引用其他安全组或前缀列表时，结果为未知；规则范围检查不替代端口、优先级和业务连通性验收。

接口依据：[APIG 插件绑定](https://www.alibabacloud.com/help/en/api-gateway/ai-gateway/developer-reference/api-apig-2024-03-27-createpluginattachment)、[PrivateLink 可用区](https://www.alibabacloud.com/help/en/privatelink/latest/api-privatelink-2020-04-15-listvpcendpointzones)、[ECS 安全组规则](https://help.aliyun.com/en/ecs/developer-reference/api-ecs-2014-05-26-describesecuritygroupattribute)。

## AgentTeams 台账同步

「台账同步」依次完整读取 ListTeams、ListWorkers、GetWorker、ListTeamTasks。成功后保存加密快照，Worker 按租户、模式、云账号、地域、实例、名称归并资产。

- 云端操作均为只读；本地更新资产台账。手工归属、分级、生命周期和已有风险治理数据保留。
- 原始快照加密；普通台账只展示必要字段。云端人员不会自动成为平台管理员。
- 任一分页失败、重复资源、循环令牌、总数变化或提前结束均报错；Worker 详情须属于当前实例。失败时保留原快照和资产，不把“未读到”当成删除。完整读取后可以刷新主页面查看团队和任务。
- PostgreSQL 模式把云 Worker 资产、加密盘点快照和成功审计放在同一租户事务中提交；配置版本变化、快照或审计落库失败时，三者都不会发布。失败审计单独记录，便于排查。离线内存模式只用于本地模拟，重启后不保留盘点结果，也不保证跨存储原子性。
- 单次最多 200 个团队、200 个 Worker、每列表 20 页，超出须按实例分开接入。未从公开 API 得到的编排边、调用次数和风险分不做推测。
- 相同盘点请求编号复用已完成的查询回执。若浏览器断网，先检查操作记录；修正错误后在台账同步页重新运行，会使用新编号重新读取完整列表，避免再次读取已缓存的错误分页。平台不会自动重发。换配置后须重新加载。
- 需要每日自动盘点时，按[调度操作指南](scheduler-guide.md#个人与离线使用)为 `asset-inventory` 显式启用 AgentTeams 同步。调度器默认仅统计已有资产；Mock 可先验证，Live 必须另外确认，避免定时任务意外访问云端。

## 回执与错误处理

「刷新记录」「查看」「重新读取回执」只读取本地数据。`pending_audit` 表示已暂存执行结果、
本地回执和审计待发布，结果仍为 `uncertain`；核对编号后明确点击「恢复本地回执与审计」。
此恢复不访问云端或 STS，不重发原操作，不要求连接仍启用、原配置版本或当前凭据。
失败保留回执，修正本地原因后可明确重试。完整状态及中英文步骤见 [回执恢复指南](receipt-recovery-guide.md)。

每次操作都有请求编号、配置版本、操作者、开始时间、状态和加密回执。接口返回失败会显示失败，不会因为 HTTP 200 就一律显示成功。

| 现象 | 操作 |
|---|---|
| 参数校验失败 | 按字段提示修正类型/必填字段；检查实例和资源标识是否属于当前账号地域 |
| Forbidden / RAM 权限失败 | 在云端为当前身份补充该具体 API 所需的最小权限，再运行只读检查 |
| STS 过期或角色交换失败 | 检查真实到期时间、源凭据、信任策略、Role ARN 和 External ID |
| 配置版本冲突 | 重新加载配置，不覆盖他人的更新 |
| failed | 查看完整回执；业务拒绝不能当成执行成功 |
| uncertain / 请求曾中断 | 远端可能已执行。先在云控制台或查询 API 核对结果，禁止直接新建同一写请求 |
| 熔断 30 秒 | 检查网络/凭据和最近回执；恢复后再次运行只读检查 |
| 刷新检查记录没有发起新调用 | 正常；刷新按钮只重新读取记录。新的实际检查从各连接的「运行只读自检」发起 |

真实模式切换不会绕过部署环境的全局 `AGF_MOCK_MODE`。全局模拟开启时界面会明确标记仍使用模拟。

## 验收边界

本地假服务可以验证签名、STS 交换/到期、完整分页、租户隔离、加密保存、重复请求与错误处理。真实云账号授权、实例可达、云配额、云执行器和实际计费仍须按 [待验收清单](pending-verification.md)进行第二阶段验证。

当前公开 AgentTeams API 没有旧代码假设的 `ListCrossTeamCalls`、`ListAuditEvents`、`GetTeamQuota` 接口。跨团队调用和消息审计需接入实际网关/SDK 日志；资源列表和任务统计不能替代审计事件。

消息/任务、Trace/Span 与跨团队调用可通过控制台的「消息与调用审计」绑定完整盘点后上报。类型化 Webhook 接入、最小权限、心跳示例、去重、失效重绑与未知授权状态见 [AgentTeams 审计接入指南](agentteams-audit-guide.md)。

开发者使用类型化 AgentTeams 适配器时，配置 `instance_id`、`worker_name` 和 `quota_period`（day/week/month）。`sync_quotas` 只接收单个 Worker 的正整数 Tokens 限额，先读取 GetWorker.LimitConfig，确认周期，再调用 UpdateWorker，最后回读验证。与平台值不一致会返回冲突告警；回读未一致会报错，不宣称已生效。并发、次数和金额配额继续由平台网关执行，不能冒充云端 Token 限额。自动业务调度与平台配额页的连接仍待补齐。

控制台可在「操作」先执行 GetWorker，再用 UpdateWorker 的 LimitConfig 字段显式修改，最后再次 GetWorker 核对；不要带入本次不修改的模型、MCP 或渠道字段。对应公开字段见 [AgentTeams API 元数据](https://api.aliyun.com/meta/v1/products/AgentTeams/versions/2026-06-05/api-docs.json)。

SchedulerX3 的 UTC 日历、HTTP 回调、执行回执、凭据区分和本地验证见 [调度操作指南](scheduler-guide.md)。启停使用 OperateEnableJobs / OperateDisableJobs，立即执行使用 OperateExecuteJob。

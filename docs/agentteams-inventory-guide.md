# AgentTeams 团队关系盘点指南

控制台入口：[团队盘点与指标](http://localhost:8081/alicloud?tab=inventory)。其它部署使用自己的控制台根地址加 `/alicloud?tab=inventory`。连接凭据及网络配置见 [阿里云操作指南](alicloud-operations-guide.md)。

## 个人用户先验证 Mock

1. 登录后核对右上角组织，打开“阿里云 AgentTeams → 云连接与操作”。
2. 配置 AgentTeams，启用连接与 Mock，地域选择 `cn-hangzhou`，实例使用 `inst-demo`，保存配置。模拟模式不需要真实云凭据。
3. 打开“台账同步”，点击“完整盘点并同步台账”，等待实际成功回执。此操作读取云端数据并更新当前组织的本地台账。
4. 在“团队盘点与指标”点击团队名称，先查看 Worker 成员，再分别打开“云端人员”“云端任务”“编排 DAG”。详情顶部的“团队盘点操作指南”可随时展开。
5. Worker 名称有资产链接时，可打开详情核对实例、名称和归属；云人员表只展示人员名单，不会按同名添加 Worker 资产链接。

Mock 验证盘点和页面流程，不能证明真实云权限、网络、调用覆盖或计费数据。页面的 Mock 标记始终保留。

## 企业用户选择实例与权限

当前组织的连接、凭据、快照和回执各自隔离。先确认正确账号、地域和 InstanceId，再运行完整盘点。

| 操作 | 平台权限 |
|---|---|
| 查看团队、Worker 与任务 | `alicloud:read` |
| 修改连接配置 | `alicloud:write` |
| 完整盘点并发布本地资产台账 | `alicloud:write`、`assets:write` |
| 打开 Worker 的平台资产详情 | `assets:read` |

Live 盘点需要云端身份拥有对应实例的 `ListTeams`、`GetTeam`、`ListWorkers`、`GetWorker` 和 `ListTeamTasks` 读取权限。连接自检成功只证明该查询可调用，不推定其它读写权限。配置好 Live 后，必须在台账同步页勾选“确认云端只读查询与本地台账更新”，再点击盘点按钮。

平台读取完整团队与 Worker 列表、各自详情以及任务分页，校验资源身份与关系。每次最多 200 个团队和 200 个 Worker，每项最多 20 页。跨请求观察不是云端事务快照；采集期间资源变化可能导致关系冲突，应在变化完成后重新盘点。

## 怎样理解人数、角色与证据

| 页面内容 | 含义 |
|---|---|
| Worker 数为数字 | 本次快照已获得完整 Worker 关系；`0` 表示观察为空 |
| Worker 数为“未知” | 无法确认完整成员关系；不是没有成员，也不能凭此创建新的审计绑定 |
| 团队 WorkerNames | 关系来自团队详情明确返回的 Worker 名单，并与可用 Worker Groups 核对 |
| 完整 Worker Groups | 团队未提供 WorkerNames，但完整盘点的每个 Worker 均提供有效 Groups，可据此确定归属 |
| 关系未验证 / 证据不完整 | 缺少完整来源或旧快照不能证明关系；不得将部分名单当作全量名单 |
| 云端角色为字符串 | 展示对应 Worker Groups.Role 原文，不替换成平台预设角色 |
| 云端角色为“未知” | 上游未提供角色。成员关系可已知，但角色仍未知 |
| 云端人员表有名单 | 来源为 TeamMembers，与 Worker 成员分别读取 |
| 云端人员名单未提供 | 人员是否为空未知；明确返回的空名单才显示“没有云端人员成员” |
| 编排 DAG 未提供 | 当前公开盘点接口没有执行节点或依赖定义；不是已确认不存在编排 |

`TeamMembers` 中的人员即使与 Worker 同名，也不成为 Worker、Agent 资产或审计关系。AdminName、LeaderName 和 Groups.Role 都不会自动授予平台管理员、工具权限或其它平台角色。

任务列表的“指派对象”仅展示 AssignedTo 原文，不保证是 Worker。团队归属、任务指派和已观测跨团队调用分别表达不同事实，不能据此合成执行 DAG。

## 失败、重新盘点与审计接入

1. 盘点失败时查看实际回执，核对 InstanceId、分页、资源身份和 WorkerNames/Groups 是否矛盾。不要把权限、网络错误当成资源为空。
2. 平台保留上次已发布的快照和资产；旧记录的同步时间仍是上次成功观察时间。刷新团队列表只读取已保存记录，不会发起新的云盘点。
3. 在云端修正错误或等待资源变化完成，然后手动重新盘点。新的请求编号读取完整列表，平台不会自动重发。
4. 新盘点成功后，核对团队、证据、Worker 资产链接与云人员名单。已有 Worker 的分组或角色需要在厂商支持的云控制台/API 中维护，再重新盘点；本页面只显示关系。
5. 若审计绑定因关系变化失效，完成可信盘点后重新绑定并发送心跳，再检查实际业务事件。步骤见 [团队消息与调用审计](agentteams-audit-guide.md)。调用次数只统计最近 24 小时收到的事件；有数字也不证明覆盖完整。
6. 单个 Worker 的平台与云端 Token 限额另见 [Worker 配额指南](agentteams-quota-guide.md)。关系观察不等于该 Worker 的平台网关 Key 已绑定，也不会自动接管云流量。

当前关系盘点不下发编排、不重放任务。云角色观察也不等于授权审计结果。

## English quick start

Select the organization, configure its AgentTeams connection, and start with Mock. Run **Read complete inventory and synchronize**, select a team, and inspect **Worker members**, **Cloud users**, **Cloud tasks** and **Orchestration DAG** separately. Live requires explicit confirmation; viewing needs `alicloud:read`, inventory needs `alicloud:write` and `assets:write`.

An unknown Worker count or unavailable user roster does not mean zero members. Roles are raw provider strings or unknown; they do not grant platform access. Matching user and Worker names do not establish the same identity. **Assigned to** does not prove Worker identity. Upstream did not provide a DAG, so no dependency graph is inferred from membership or observed calls.

After a failed inventory, inspect the receipt, correct the cause, and retry manually. The last published snapshot is retained. Obtain complete relationships before rebinding audit; follow the [audit guide](agentteams-audit-guide.md) and [quota guide](agentteams-quota-guide.md) for those separate flows.

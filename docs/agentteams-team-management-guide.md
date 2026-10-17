# AgentTeams 团队维护指南

控制台入口：**阿里云 → 团队维护**，路径 `/alicloud?tab=teams`。盘点表中的“维护团队”可带入团队名称。创建、描述修改、人员名单替换和异步删除均使用预览流程；通用云操作页不执行这三类团队写入。

本页维护团队资料和已有云用户的 TeamMembers，不创建或删除用户账号，不处理密码，也不修改已有 Worker 的 Groups/角色、LeaderName 或已有 AdminName。任务 DAG 未由云接口提供。

## 1. 准备连接与权限

1. 核对右上角组织，在阿里云连接配置中选择 AgentTeams，填写实例、地域和凭据。个人用户先在 Mock 验证；企业用户使用当前业务账号的 RAM 凭据或已配置角色身份。
2. 启用连接，完成当前实例可信完整盘点。配置、账号、实例或模式变更后须重新盘点；历史回执仍可读，但不能套到新范围。
3. 平台权限如下。平台权限不代表云 RAM 已授权，云端拒绝须根据实际 RAM 策略修正。

| 操作 | 平台权限 |
|---|---|
| 查看团队维护、已有预览和回执 | `alicloud:read` |
| 读取用户、准备预览、观察已有操作的云结果 | `alicloud:read` + `alicloud:write` |
| 确认创建/修改/删除并发布台账，或重新盘点发布 | 上述权限 + `assets:write` |

云侧需按实际动作配置 `agentteams:ListUsers`、`GetUser`、`ListTeams`、`GetTeam`、`CreateTeam`、`UpdateTeam`、`DeleteTeam` 及完整盘点所需的 Worker/任务查询权限。查询失败不能被理解为没有资源。

## 2. 创建团队

1. 选择“创建团队”，填写准确名称和描述。
2. Live 先勾选确认读取当前实例真实云数据。需要选择已有人员或可选管理员时，再点击“读取云用户”；明确创建空名单或清空已有名单无需人员目录。用户候选可按名称筛选和分页；筛选为空不证明用户不存在。
3. 选择已有云人员。创建时 AdminName 可不选；选择后资格由云端最终校验，Active 状态不证明管理员资格，也不授予平台权限。
4. 点击“准备变更预览”，核对实例、配置版本、人员名单和管理员。空初始名单须作为明确期望确认，不能从未知旧名单自动推导。
5. 核对差异后勾选确认，点击“确认变更并回读”。只在云结果已验证且完整台账发布后显示全部完成。

## 3. 修改描述或人员名单

- **仅描述**：选择已有团队，勾选“修改描述”。人员默认保持，请求不发送 TeamMembers；名单未知也可单独改描述。
- **全量替换**：团队人员基线必须完整。主动勾选“替换完整云人员名单”，保留或移除现有人员，再从当前实例候选中选择新增人员。翻页和筛选不会移除未加载的已选成员。
- **清空**：主动把期望名单设为空，预览会列出全部移除人员；这是移除团队关系，不删除用户账号或 Worker。

预览逐个 GetUser 核验所有目标身份，包括候选页未加载的旧成员。每次最多选择 200 人；每个候选查询链最多 20 页、每页最多 100 人，达到上限会标为部分结果，可缩小搜索继续选择。

预览和候选观察有效期均为五分钟。过期、草稿变化或配置/范围变化须重新准备，确认复选框不会自动勾选。云接口没有条件版本 CAS，其他控制台同时修改仍可能竞争；全量替换前核对每位新增、保留和移除人员。

## 4. 删除团队

1. 选择“删除团队”，输入准确团队名称并确认关联资源将异步清理。
2. 服务端读取已知 Worker、云人员、Rooms 和完整任务清单；影响未知或读取失败时不能确认删除，不显示为零影响。
3. 核对删除影响预览后另行勾选写入确认。收到成功回执只表示接受删除；清理中仍显示 Deleting。
4. 使用“观察云端结果”。只有结构化资源不存在证据、完整台账一致并发布成功才算完成。403、网络错误或一般 404 不表示删除成功。

DeleteTeam 没有厂商 ClientToken。结果未知时没有“重试删除”；新请求编号和租约到期都不能绕过未解决删除。请保留回执并观察，不能自动重发。

## 5. 回执与恢复

页面分别显示**云端写入、回读确认、台账发布**。云回执接受但回读失败、字段不同或发布失败都不是全部成功。

确认提交前，请保留浏览器更新后的链接：`/alicloud?tab=teams&team=名称&request_id=请求UUID`。首次响应丢失或刷新页面后，可以按原请求编号恢复记录；不要改编号重发同一写操作。

| 状态 | 下一步 |
|---|---|
| 执行中 | 刷新回执，等待有效租约结束；不重复提交 |
| 结果不确定 | 恢复原回执，再明确观察云结果；未知删除只观察 |
| 删除清理中 | 继续只读观察，不能把接受回执当已删除 |
| 回读已匹配但台账失败 | 按服务端允许的动作重新完整盘点并发布，不再次云写 |
| 配置版本变化，服务端确认可恢复 | 仅在同账号指纹、地域、实例、模式及当前资源版本时，按回执的 `recoveryConfigurationVersion` / `recoveryScopeId` 观察或发布；原写入来源不变，不重发写入 |
| 跨账号或已有较新操作 | 标为 superseded，仅查看历史回执；不能把恢复字段猜成当前配置 |
| 人员或配置冲突 | 保留草稿、读取最新状态、人工核对合并并生成新预览 |

页面只提供服务端允许的“刷新回执”“观察云端结果”“重新盘点并发布台账”；没有通用重发写入。切换组织或登录会话会丢弃旧确认，旧请求不能提交到新组织。

## English quick start

Open **Alibaba Cloud → Team management** at `/alicloud?tab=teams`. Enable AgentTeams and complete trustworthy inventory. Read access is `alicloud:read`; cloud observations/previews require `alicloud:write` too; applying changes or publishing inventory additionally requires `assets:write`.

Choose existing cloud users when needed; an explicitly empty list needs no user directory. Preserve all selected members across pages and distinguish keeping membership from full replacement. Creation administrator is optional and cloud-validated. Review a five-minute preview before confirming. Inspect write, readback and inventory publication separately. Keep the request-ID URL. A newer configuration can observe/publish only using server-confirmed recovery fields for the same account, region, instance, mode and current resource version; cross-account or newer operations remain historical. Observe uncertain deletes without resending. Existing Worker groups and user-account/password management are outside this page.

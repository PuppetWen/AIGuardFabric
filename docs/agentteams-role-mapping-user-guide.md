# AgentTeams 平台角色权限约束操作指南

状态：独立控制台候选，尚未集成/构建/部署或完成真实浏览器验收。
拟入口 `/alicloud?tab=role-mapping`；共享页面注册由父任务完成后才可访问。

## 企业部署与真实目录

管理读取需要 `platform:admin + alicloud:read`；提交采用或停用还需要 `assets:write`，且只允许管理员用户会话。
完整盘点继续使用既有 `alicloud:write` 权限。平台 API Key 不能管理或自授角色。
平台目录直接使用现有同租户 SQL `roles` 记录及其真实 UUID。尚无角色时通过现有用户管理配置合法角色。
本页不创建另一套 Role，也不接受客户端 permissions。支持已保存且定义一致的
tenant-admin/soc-analyst/redteam-engineer/auditor/viewer；superadmin、asset-owner 和未验证自定义角色不可采用。
个人离线部署没有真实 Role UUID 目录，因此新增角色映射不可用；未纳管 Key 的既有 scopes 保持兼容。
不能把 Authorizer 启动时的随机内存 ID、云人员名字或 CloudRole 字符串当平台授权。

## 实际操作

1. 在“云平台 → 连接配置”保存 AgentTeams 来源、区域、实例与模式。启用后进入“团队盘点与指标”，人工完整盘点。
2. 在角色约束页读取目录，选择实际 Worker/Team/CloudRole。Role 未知或资产 UUID 未映射的成员不可采用。
3. 选择真实平台 Role UUID，核对显示的权限列表。没有默认 Role；旧 UUID 失效时仍显示供修复，不代替成另一个角色。
4. 确认既有采集或模型调用可能被缩小，然后点击“人工采用角色约束”并再次明确确认。每次提交保存当前 CAS 版本和新意图 UUID。
5. 在现有 Key 管理中绑定同租户此 Agent，配置所需原 scopes。实际运行权限是原 scopes 与 Role 权限交集，绝不叠加扩权。
6. 核对“当前有效映射数”与每条当前资格。CloudRole、adapter 的 operator/viewer/auditor 评审提示不计入授权数量。
7. 要停用，点击对应 Worker 的停用按钮，核对永久治理提示后确认。停用不删除永久标记，不解锁旧 Key 宽权限，也不复活已删除资产。

采用需 300 秒内的完整成员证明；这不是运行授权 TTL。已采用有效约束不会因五分钟过去自动停掉日/月任务。
成员移除、Role 改变、来源变化、Agent 部门/分级/身份变化会拒绝旧约束。
完整负面盘点持续撤销；随后正面观察不会自动恢复。重新盘点后仍需管理员人工采用新证明。

## 冲突和回执

401/409/网络失败保留成员、Role UUID、原保存版本和请求编号。请求在途或网络中断、408、5xx、无法核验的 2xx 后，原请求内容与编号保持不变，新采用与停用都锁定。只能 GET 原回执或比较，不自动重复 PUT。
原回执 404 不能证明未提交，不解锁，也不能另发新编号。可信原回执或确定 4xx 拒绝后，核对事实并明确确认“开始新的本地操作”，保留旧草稿 CAS，重新比较/采用和勾选风险后才手工发送新意图。
“重新加载角色与成员比较”只做 GET，不读取云、不改变草稿的 expected_version。
核对新成员证明、配置版本和当前映射版本，点击“明确采用最新比较（不保存）”并确认后，仍需重新勾选权限风险并手工提交。
当前盘点缺成员时保留旧草稿，不能采用缺失证据。已停用来源仍可保留本地停用事实、读取历史回执。

原回执需要 Worker 资产 UUID 与原请求 UUID，只能手动 GET。历史原状态不是今天的运行资格；回执 `currentQualified=null` 表示没有进行当前核验。
切换租户或重新登录清除旧选择/回执；旧请求迟到不显示到新会话。不把取消 HTTP 等待当已阻止服务端提交。
台账每页 50，后台最多 512 治理 Worker、2048 永久意图；没有后台清除或删除解锁。

## English workflow

The candidate entry is `/alicloud?tab=role-mapping`; it becomes usable only after integration.
An administrator user needs `platform:admin + alicloud:read` to read and `assets:write` to adopt or disable.
Maintain the existing AgentTeams connection and perform a complete inventory manually, then select its actual Worker/Team/cloud Role
and an actual saved tenant platform Role UUID. There is no default assignment or fabricated offline role directory.

Review permissions and acknowledge that existing collection/model calls may narrow. Confirm adoption with the reviewed CAS version and a new intent UUID.
A Key must bind the same tenant Agent and retain its own scopes; effective grants are the intersection, never a union.
The 300-second window is for human adoption, not runtime expiry. Negative inventory evidence is sticky and positive observations do not reactivate it.
Disable retains permanent governance; deleting data never unlocks old wide scopes.

After a conflict or lost response, preserve the draft and read the original receipt first. In-flight, network failure, HTTP 408/5xx and unverifiable success retain an immutable original intent and lock adoption/disable. Receipt HTTP 404 cannot unlock or prove rejection. A trusted receipt or definite 4xx rejection requires an explicitly confirmed new local action before writing again. Reload only compares current evidence;
keep the old draft CAS, explicitly adopt the latest comparison, reconfirm the risk, then submit manually. GET never dispatches cloud operations.
Historical success is separate from current qualification. Source, Role or Agent governance changes fail closed.
Tenant/session changes discard old drafts and late responses. Offline new mappings, vendor role writes and business replay are outside this slice.

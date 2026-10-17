# APIG 独立限流策略发布 / APIG independent rate-limit publication

入口：**阿里云 → APIG 策略发布**，或 `/alicloud?tab=apig-policy`。打开页面只读取本地状态；不会创建资源、初始化 Mock、观察云端或自动发布。

Open **Alibaba Cloud → APIG policy publication**, or `/alicloud?tab=apig-policy`. Entry reads local state only; it does not create resources, initialize Mock, observe the cloud or publish automatically.

## 身份与权限 / Identity and access

- 查看、读取原回执、明确只读观察：`alicloud:read` + `policies:read`。
- 绑定配置、Mock 初始化、预览、发送、本地恢复、归档：再需要 `alicloud:write`。
- 准备通用配额：`quotas:read` / `quotas:write`；手工创建或编辑来源策略：`policies:write`。
- 云端 RAM 权限单独配置：观察使用 `GetHttpApi`、`GetPolicy`、`GetPolicyAttachment`，发送使用 `UpdatePolicy`。平台权限不能替代 RAM 授权。

Viewing, original receipts and explicit read-only observation require `alicloud:read` + `policies:read`. Binding, Mock initialization, previews, sending, local recovery and archive additionally require `alicloud:write`. Preparing generic quotas needs quota read/write permissions; creating source policies needs `policies:write`. Cloud RAM grants are separate and must authorize the three observation actions and `UpdatePolicy`.

企业按业务租户、云账号与地域隔离；个人单机可先用一个租户走受控 Mock。平台 API Key、Scheduler 回调 token 与云 RAM 凭据用途不同。在“连接配置”维护云凭据，不把凭据放在五 ID、UUID、URL 或策略正文中。

Enterprises separate business tenants, cloud accounts and regions. Individuals can begin with owned Mock in one tenant. Platform API keys, Scheduler callback tokens and RAM credentials serve different purposes. Maintain cloud credentials in Connection configuration, never in IDs, URLs or policy bodies.

## 1. 绑定实际已有对象 / Bind actual existing objects

1. 在连接配置核对账号来源、服务 endpoint、地域和实际 Mock/Live 模式。
2. 展开“既有五 ID 绑定”，填写已有的 Model API ID、Gateway ID、Environment ID、独立 policy ID、Policy attachment ID。此期仅支持已有 LLM Model API 的明确部署和 `AiTokenRateLimit` 独立策略。
3. 明确确认管理这个策略，同时承认其它 API 可能也引用它；关联存在不能证明独占。人工保存使用实际配置版本 CAS，不创建 API、策略、部署或挂载。
4. 目标、来源、模式或任何凭据变化会清除旧管理确认。先保存连接设置，再回到此处核对并重新确认。
5. 遇到 401/409，草稿及原保存版本保留。用“读取最新 APIG 配置比较（GET）”查看新值；明确采用才替换草稿与版本，之后仍须人工保存。

Verify account, service endpoint, region and effective mode in Connection configuration. Enter all five existing IDs, explicitly confirm management and acknowledge unknown impact on other API references, then save with the actual configuration revision. Target, source, mode or credential changes invalidate prior consent. A conflict retains the draft and original revision; a comparison GET does not adopt or save. Explicit adoption replaces the draft, and a separate manual save remains necessary.

受控 Mock 示例仅适用于实际 Mock 模式：

| 字段 / Field | 明确示例 / Owned example |
| --- | --- |
| Region | `cn-hangzhou` |
| Model API ID | `api-agf-demo` |
| Gateway ID | `gw-agf-demo` |
| Environment ID | `env-agf-demo` |
| Independent policy ID | `policy-agf-demo` |
| Policy attachment ID | `attachment-agf-demo` |

“明确填入受控 Mock 五 ID 示例”只填表，不切模式、不保存、不初始化。手工选择 Mock、填例、确认、保存后，再勾选“明确初始化受控 Mock fixture”并点击“明确观察当前 APIG 目标”。这些 ID 不是实云目标；GET 永不生成样例。

The explicit Mock example button only fills the form. It does not change mode, save or initialize. Manually select Mock, fill, confirm and save; then consent to fixture initialization and explicitly observe. These IDs are not live targets, and GET never seeds data.

## 2. 准备真实平台来源 / Prepare a real platform source

1. 在 `/runtime#quota-rules` 新建通用配额：Tenant shared、Requests 或 Token、Minute、Deny、启用、整数额度 `1..2147483647`，**软阈值明确填 0**，不填 Agent target ID。通用默认日窗口与 80% 软阈值不会自动改成此发布要求。
2. 从配额表复制真实 UUID；表中同时可复制当前配额版本。
3. 在 `/policies` 手工新建或编辑策略：Quota 动作，代码模式选择 **JSON**（Structured），正文 `{}`，仅 AI gateway 拦截点，无条件、Agent/部门范围和降级端点，关闭 dry-run，启用并从真实配额列表明确选择该配额。
4. 保存后回到 APIG 页，按名称和真实 UUID / 策略版本选择服务端标为可投射的来源。不可投射的原因原样显示；不自动改写已有 Rego/CEL、动作、范围或其它配额。
5. 来源按服务端分页，亦可只看可投射项。已选版本跨页保留，不在此页不代表删除；预览会重新检查全部签名与配额依赖。刷新不会静默换选项或换版。

Create an enabled Tenant shared quota for Requests or Tokens, Minute, Deny, a positive int32 limit and **explicit soft threshold 0**, with no Agent target. Copy its actual UUID. Save an enabled policy with Quota action, code mode **JSON** (Structured), `{}`, only AI gateway, no conditions, narrowed scope, fallback endpoint or dry-run, and an explicitly selected actual quota. Select a server-eligible signed revision in the APIG page. Paging preserves that exact choice; it does not imply deletion or replace the selected revision. The server revalidates current signatures and quota dependencies at preview time.

平台 Tenant 的 UTC minute 计量与云端 API-global 周期不同；这里只用额度数值作蓝本。不可将平台用量、云阈值、调用次数、费用或计费数据当作相同指标。

Platform Tenant UTC-minute accounting differs from the cloud API-global period. This workflow projects a numeric threshold only; platform usage, cloud thresholds, invocation counts and billing are separate measures.

## 3. 观察、预览与唯一发送 / Observe, preview and send once

1. 明确观察执行三个只读接口。Live 先勾选只读确认；GET 本地状态不访问云端。
2. 核对唯一已有 Global `RequestPerMinute` 或 `TokenPerMinute` slot 的真实值。配置须 enabled、已有规则唯一；非空 attachment override 正文不可写。未知或不支持会显示原因，不猜值。
3. 新观察可作为草稿基线；独立刷新只比较，需明确采用最新基线。选定真实来源后生成可信预览，此时未发送云写。
4. 核对五 ID、原/新阈值、来源策略版本、状态版本及 hash。分别确认目标、平台/云周期差异、共享影响未知、**没有云 CAS**；Live 或旧 Unknown 风险还各需独立确认。
5. 点击发送一次新意图，保留实际 UUID。一个预览只尝试一次；网络错误或超时也不会自动重复 POST。改用原 UUID 读取回执。

Explicit observation performs the three read-only cloud APIs; Live requires consent. Inspect the existing unique enabled Global minute slot. Prepare against a fresh baseline and exact source revision. Confirm target, counting-period differences, unknown shared impact and **absence of cloud CAS** separately, plus any Live/Unknown risk. Send one new intent and retain its actual UUID. Even a lost response does not resend its consumed preview; read the original receipt instead.

只更新选定 slot 的 `limitValue`，保留其它规则、顺序和未知字段。写前 fingerprint 复核不是厂商 CAS，仍可能有外部并发修改。独立策略发送普通 JSON config，不用 Nacos MD5/upsert、插件 Base64 或 ClientToken。

Only the chosen slot's `limitValue` changes; other rules, ordering and unknown fields remain. The pre-write fingerprint comparison is not provider CAS. This independent policy uses ordinary JSON config, not Nacos MD5/upsert, plugin Base64 or ClientToken.

## 4. 回执、Unknown 与本地恢复 / Receipts, Unknown and local recovery

- 分别查看云 Accepted/Unknown、独立回读 Matched/Different、Local Published/pending_audit，以及消费者 Unknown。配置回读匹配不证明消费者已加载，也不能把原 Unknown 升级为 Accepted。
- 原 UUID 可复制、放入 `apig_request_id` URL，或手工输入。链接仅预填，须明确点击 GET；刷新不自动重写。切换租户或会话会清旧编号，迟回结果不能进入新界面。
- `pending_audit` 或服务端允许的过期 started，可明确恢复**本地终态与唯一审计**。该按钮不调用 provider、不加载新凭据、不重复云写；停用配置后仍可核查及本地恢复。失败保留原回执。
- 旧 Unknown 风险需先恢复成完整本地事实。租约过后明确新观察，其开始和完成时间均须晚于旧租约，再确认旧编号、生成新预览、明确承认重叠风险后发送独立新意图。新 UUID、超时或关闭标签页不能保证旧远端请求已停止。

Cloud write, independent readback, local publication/audit and consumer loading are separate. Unknown remains Unknown even after matching observation. Original UUID links only prefill, requiring a manual GET. Tenant/session changes clear the old ID and discard late responses. Local recovery finalizes only the local fact and audit, including when configuration is disabled; it never resends the cloud write. A separate new intent after Unknown requires local completion, both observation timestamps after the old lease, exact old-ID acknowledgment, a new preview and explicit overlap consent. It is not a guaranteed safe retry.

## 5. 阈值回滚与容量归档 / Threshold rollback and archive

可信历史回滚只取该次 **previousThreshold**，放在新的观察基线上，保留当前其它规则。先看服务端当前支持性及原因，再选历史、新观察、新预览、新确认，用新 UUID 发送。不能复制整个旧云对象、任意正文或已归档来源。

Trusted rollback uses that publication's **previous threshold** on a fresh observed baseline, retaining other current rules. Check server availability/reason, choose the trusted history, observe, preview, confirm and send under a new UUID. It does not restore the whole old cloud object, arbitrary content or an archived body.

详情上限 128 条 / 64 MiB。归档前人工选择已终态条目并核对数量、归档代次及正文损失；最多一次 100 条，无后台归档。原详情列表最多 50 条；更早编号可手工 GET 后单条归档。归档不变更云配置，永久事实和原 UUID 墓碑仍可读，但**失去此条可信回滚正文**。停用配置不阻止纯本地归档。

Detailed capacity is 128 runs / 64 MiB. Explicitly select terminal records and confirm count, archive generation and body loss, at most 100 at once. No background archival occurs. The recent list contains at most 50 details; an older UUID can be read and archived individually. Cloud configuration and permanent UUID facts remain, but **that trusted rollback body is lost**. Disabled configuration does not block local archive.

持久跨实例、重启后编号去重与审计事实要求配置 PostgreSQL；无数据库模式仅当前进程有效。此指南不代表实云 RAM、网络或消费者已验收，具体生产目标应由用户核对实际回执和消费者证据。

Permanent cross-instance/restart deduplication and audit facts require PostgreSQL. Database-free mode lasts only for the current process. These steps do not certify live RAM/network access or consumer loading; verify actual receipts and independent consumer evidence for each production target.

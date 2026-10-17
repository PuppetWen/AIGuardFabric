# 资产接入与治理 / Asset onboarding and governance

## 个人用户

1. 登录后确认顶部组织。打开“操作指南 → 终端采集器”，下载对应平台程序并核对 SHA256。
2. 为采集创建单独的 `sources:write` API Key，使用指南中的 `run --once` 完成首次上传。
3. 模型端点在“模型网关”添加；MCP HTTP 端点在“MCP 管理”添加并探测。保存端点后会同时登记资产；探测成功后显示实际工具清单。
4. 在“资产台账”输入名称、负责人或标签并按回车。点击名称或“详情”查看画像、来源、依赖及最近变更。
5. 有 `assets:write` 权限时，详情提供“更正资产资料”和“评审与生命周期”。前者可更正名称、负责人、部门及分级，必须填写原因；后者控制状态流转。更正只修改平台台账，不会修改外部 Agent 或端点。

采集器配置及凭据属于所选组织。相同指纹在不同组织中拥有不同资产 ID；同一组织反复采集会合并到同一条记录。

## 企业用户

1. 先创建组织、成员与角色，按组织/设备组分配独立采集凭据；不要把平台管理员凭据放进客户端。
2. 采集端使用应用所在用户的配置目录。云资源从“阿里云集成”执行盘点；云盘点会保留已经维护的归属、生命周期与分级。
3. 按部门、数据分级及暴露面筛选。筛选组之间为 AND，组内多选为 OR；修改条件回到第一页，风险排序在服务端应用于全部结果。
4. 部门从当前结果中提供建议，也可直接输入并回车；当前逗号分隔查询不支持名称中包含逗号的部门。
5. 资产投产前完成评审。已有生产资产需要重新评审时，先转为“变更中”，再补充信息并回到“生产”。
6. 两类表单都使用打开时的资产更新时间。409 表示期间有新数据；输入保留，关闭表单、刷新详情并比较后重新操作。成功更正会记录前后值和操作人；数据库模式下更正、变更台账和成功审计同一事务提交。

| 当前生命周期 | 可选择的下一状态 |
| --- | --- |
| 申请中 | 评审中、拒绝 |
| 评审中 | 试用、拒绝 |
| 试用 | 生产、拒绝、归档 |
| 生产 | 变更中、归档 |
| 变更中 | 生产、归档 |
| 归档 / 拒绝 | 终态 |

生命周期维护台账。归档不会关闭外部应用、销毁证据或自动撤销凭据；停用模型/MCP 端点、吊销 API Key 或运行时阻断请使用对应入口。

若需要更正已登记的资料，进入资产详情 → **更正资产资料**，核对当前租户和资产标识，填写新值及原因后保存。资产 ID、唯一指纹和资产类型不能在此更改；要修正错误指纹，应登记正确资产并保留旧记录的审计证据。空部门表示未分配，下一次自动发现若有部门值仍可补入。仅有 `assets:read` 的成员只能查看，无法看到更正按钮。

若资产已经退役且确需从当前台账隐藏，先评审为**归档**或**拒绝**，在详情点“从当前台账移除”。输入完全一致的资产名称、填写原因并确认。旧版本或名称不符时拒绝，不能误删另一位管理员刚修改的资产；只读成员无此按钮。此操作是软删除：列表和普通详情不再显示，但历史变更、每日快照及审计记录留存；数据库模式下删除标记、变更记录和成功审计同一事务提交。采集源若仍上报相同指纹，会复用原资产 ID 重新出现在台账，需到源头停止采集或停用服务。移除台账不会停用外部 Agent、端点、模型或凭据；先完成这些单独的停用操作。

## 保存与恢复

- 使用 PostgreSQL 时，发现批次、资产状态、变更记录与快照同步提交，成功后才更新本进程缓存。单批最多 1000 个资产；失败的批次完整回滚。
- 模型配置和台账投影同时保存或删除。MCP 配置版本、探测快照和资产投影使用同一个资产治理锁，旧探测不能覆盖新配置。
- 重新采集保留人工治理字段；已有数据库中的资产 ID 保持不变。
- 台账、Agent/MCP/Skill/模型分组、详情、拓扑、报表以及关联动作校验从 SQL 读取。另一个实例无需重启即可读取新数据；绑定到已删除 Agent 的凭据会被拒绝。
- 多实例列表分别计数和读取当前页，极短时间内有新写入时总数可能变化。刷新即可取得新窗口。
- 显式离线模式仅保存在进程内，不能用于验证重启持久性。
- 详情提供最近 100 条变更；漂移报表按时间窗读取，超过 100000 条要求缩小时间窗。全量拓扑等操作超过 100000 资产时明确报错；台账及四个资源分组仍使用分页。

## 手工登记与每日检测

1. 在资产台账点击“登记资产”，填写名称、类型、唯一资产标识、负责人、数据分级和申请用途。个人也可以填写自己的名字和用途；企业应使用组织约定的标识，例如 `finance/expense-skill`。
2. 登记资产进入 `requested`。打开详情，先评审到 `under-review`，再转 `trial`，确认负责人、分级和用途后转 `production`。登记不等于启动应用或配置模型/MCP 连接；这些仍从对应接入入口完成。
3. 同一租户的资产标识唯一。重复点击或网络失败后原样重试不会多建资产。新申请使用已存在的标识时返回 409，应搜索该标识并维护原资产。后续发现使用相同 `fingerprint` 自动归并，保留申请/评审字段。
4. “每日资产检测”列出持久化检测记录，按 UTC 每日一次；服务每分钟检查启用租户，首次启动或停机恢复后补做当天检测。每天第一份成功快照不再更改；再次“获取当日检测”返回已有记录，当天后续变化在次日检测中对比。
5. 初次检测只建立基线，空台账也保留基线。停机跨日后与最近成功日期比较，不虚构缺失日期的数据。点击检测日期查看变更前后值、需核对条目与资产链接。
6. Skill/Prompt 的内容变化需要采集器在发现项中上报 `content_sha256`（64 位十六进制 SHA-256）。未上报时不能判断文件内容。哈希变化表示需要核对，不自动认定恶意篡改。每日检测还比较端点、协议、版本、厂商、分级、生命周期、暴露分和依赖，标记新增未评审的 Agent/MCP/Skill/模型。

每日检测需要 PostgreSQL。每个租户最多 100000 个资产，超限明确失败；检测失败整笔回滚并重试，不记录成功。若页面一直无当日记录，在服务日志检索 `Daily asset inventory`，检查数据库、超时和资产规模。每日快照与报告按租户隔离，历史保留在 `asset_inventory_*` 表，应纳入数据库容量规划与备份。检测结果单独保存，不重复写入发现/评审流水。

API：`POST /api/v1/assets/register` 使用 UUID `request_id` 与完整登记字段；相同内容重试复用该 ID。`GET /api/v1/assets/inventory?page=1` 每页 20 次检测；`POST /api/v1/assets/inventory` 获取当天结果；`GET /api/v1/assets/inventory/{id}/changes?page=1` 每页 50 条变更。只读用户可查看，登记与手动获取需 `assets:write`。旧 `/assets/drift` 为独立按日期快照诊断入口，不参与每日运行账本。

更正 API：`PATCH /api/v1/assets/{id}` 必须携带 `name`、`owner`、`department`、`data_class`、`reason` 和详情中的 `governance.updated_at` 作为 `expected_updated_at`；旧版本返回 409，其他租户的资产返回 404。返回 `asset` 为保存后的台账记录。此接口不修改资产指纹、类型、生命周期或外部服务。

移除 API：`DELETE /api/v1/assets/{id}` 的 JSON 请求体必须含 `expected_updated_at`（详情中的 `governance.updated_at`）、`confirm_name`（当前完整名称）和 `reason`。仅 `assets:write` 可用，且资产须已归档或拒绝；旧版本为 409，非终态为 412，跨租户与重复移除为 404。成功返回 `removed: true`，不会硬删除历史证据。请勿把此接口当作停用外部服务的手段。

For manual onboarding, choose **Register asset**, enter a stable inventory key, owner, classification and purpose, then review Requested → Under review → Trial → Production from the detail. Registration does not connect external services. Retry an unchanged application with its original request ID after a network failure. Discovery merges by fingerprint without replacing governance fields.

**Daily inventory** runs once per UTC date and compares with the last successful immutable snapshot. The first run establishes a baseline, including an empty inventory. Same-day requests return the existing result; later changes are compared on the next day. Open a date to inspect before/after values and asset links. Report a 64-character `content_sha256` to detect content changes; a hash change requires human review, and missing hashes cannot prove unchanged content. PostgreSQL is required. Inventory is bounded at 100000 assets per tenant; failures roll back and retry. Retained snapshots and reports need database capacity planning and backups.

## Skill 目录内容观察

Windows 采集器继续为 SKILL.md、命令 Markdown 和规则文件（含 .mdc）计算单文件 SHA-256，同时为包含 SKILL.md 的 Skill 目录生成独立的 sha256-tree-v1 指纹。目录观察包含子目录脚本、隐藏文件、相对文件名与空目录；不上传文件原文或目录文件清单。只改变脚本、增删文件或重命名也会改变目录指纹。时间戳不参与哈希，文件创建顺序和绝对安装位置不影响结果。

在“资产台账 → Skill 名称 → 资产治理与变更记录”查看“最近 Skill 目录观察”，核对接收时间、文件数和字节数。首次完整观察只建立目录基线；已有可比指纹变化会标记需要核对。核对来源和发布记录后按资产生命周期评审，哈希变化不自动认定恶意，也不会自行停用 Skill。

每个目录最多 4096 个普通文件、8192 个文件及子目录条目、相对路径 16 层；单文件最多 4 MiB，总文件内容最多 64 MiB。不静默排除依赖或隐藏文件。超限、权限不足、缺失必需元数据、读取中变化、非普通文件、无法表示的文件名以及符号链接/Windows 目录联接/重解析点都会使本次目录哈希不可用。收集器不会通过这类链接读取目录内容。查看显示的原因，检查权限、停止并发写入、整理目录或将链接换为实际文件后，使用同一配置重新采集。

读取失败时“本次”不显示旧哈希为有效；“上次完整观察（历史记录）”仍保留，用于下一次读取恢复后的比较。旧采集器不带 package 字段时，不会抹除已有目录观察，也不会刷新其时间。请据此判断是否需要升级采集器或检查上报，不能把旧观察当作当前状态。

这是周期性、尽力读取的一次观察，不是实时文件拦截、原子文件系统快照或防篡改证明。它不比较权限/ACL、NTFS 备用数据流，也无法保证发现一个控制文件与元数据的本机攻击者。Linux/macOS 自动采集支持另行实现与验证；此处验收针对 Windows。

API：POST /api/v1/ingest/agent 的 extras.skills[] 可包含下列 package 对象。只能用于 kind=skill；algorithm 必须为 sha256-tree-v1；verified 要求有效的 64 位十六进制哈希、files 和 bytes。其他状态不得带哈希或计数。平台规范化哈希大小写并记录服务端接收时间。恢复比较保留上次完整观察，不因一次失败重置基线。

    {
      "name": "Expense review",
      "kind": "skill",
      "source_path": "C:/Users/example/.claude/skills/expense/SKILL.md",
      "package": {
        "algorithm": "sha256-tree-v1",
        "status": "verified",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "files": 2,
        "bytes": 46
      }
    }

兼容状态：verified、unreadable、too-large、too-many-entries、too-deep、unsupported-path、not-regular-file、changed-during-read、link-not-allowed。资产详情返回 package_observation.current / received_at / last_verified / last_verified_at，文件入口仍使用 content_observation。目录变更写入资产发现流水并参与每日检测；旧 /assets/drift 的快速治理属性哈希不覆盖此目录内容，使用每日检测及详情流水。

**English:** The Windows collector observes the whole Skill directory separately from the manifest. It includes nested scripts, hidden files, relative names and empty directories, without uploading source contents or a child-file listing. Open Inventory → Skill → Governance and change history to inspect the last received directory digest, file count and bytes. The first complete observation establishes a baseline; later digest changes require human review. Review the source/release and use the existing lifecycle process. This does not automatically disable a Skill.

Limits are 4 MiB per file, 64 MiB total, 4096 regular files, 8192 entries and 16 relative path levels. Files are never silently skipped. Read failures, budget violations, unsupported entries/names, links, junctions, reparse points and detected concurrent changes yield an unavailable observation. Check the displayed cause, permissions, concurrent writers and package structure, then collect again. A historical complete observation remains explicitly labelled and is compared after recovery. Older collectors neither erase it nor advance its timestamp.

The observation is periodic and best-effort, not live enforcement or an atomic snapshot. Permissions, ACLs and NTFS alternate data streams are excluded; a malicious local actor controlling file metadata can defeat consistency checks. Windows is the validated collector platform. The wire contract and statuses above apply equally to English clients. Use daily inventory and asset history for directory changes; the legacy drift hash compares governance attributes.

## API 操作

所有请求使用当前租户及授权凭据。接口定义见 `/api/v1/openapi.json`。

```text
GET /api/v1/assets?kinds=mcp,skill&lifecycles=active&sort=-risk_score&page=1&page_size=20
GET /api/v1/assets?classifications=confidential&departments=Security%20Ops&exposures=public-internet
GET /api/v1/assets/{id}
POST /api/v1/assets/{id}/transition
POST /api/v1/assets/drift
```

流转示例（`expected_updated_at` 必须使用详情 `governance.updated_at` 的原值）：

```json
{
  "to": "production",
  "expected_updated_at": "2026-09-21T12:00:00Z",
  "owner": "alice",
  "department": "Security Ops",
  "data_class": "confidential",
  "note": "已完成负责人和数据分级评审"
}
```

操作人取认证身份；旧客户端提供的 `actor` 不用于审计归属。漂移接口会创建快照，因此要求 `assets:write`。

## English quick guide

Select your tenant, create a dedicated collection key, and follow Guide → Endpoint collector for the first upload. Add models in Model gateway and HTTP MCP endpoints in MCP management. Inventory cloud resources in Alibaba Cloud.

Search by name, owner or tag and press Enter. Combine filters: OR within one filter, AND across filters. Department names can be entered manually; comma-containing department names are not supported by the current comma-separated query. Filtering resets pagination and risk sorting applies to the full result set.

Open an asset and use Review lifecycle when permitted. Enter the owner, classification and review note. For a production asset, choose Changing before reviewing it again. A stale form returns 409 and retains its draft; refresh and compare before reopening. Archived and rejected are final inventory states. Revoke keys, disable endpoints or use runtime controls separately when access must stop.

For an obsolete record, first review it into Archived or Rejected. In its detail choose **Remove from current inventory**, type its exact name and a reason, then confirm. The request uses the detail revision so an older form cannot remove someone else's newer edit. This is a soft deletion: current lists and ordinary detail hide it, while change history, daily snapshots and audit evidence remain. If a collector still reports the fingerprint, the same asset ID returns. Stop collection or the external service separately. Read-only users cannot remove records. API clients send `DELETE /api/v1/assets/{id}` with JSON `expected_updated_at`, `confirm_name` and `reason`.

Database-backed discovery, governance, history and snapshots commit atomically. Separate tenants can discover the same fingerprint without sharing IDs. Existing IDs and manual governance fields remain stable. Model/MCP configuration and asset projections commit together. A fresh API instance reads current SQL data. Offline demo data is explicitly ephemeral.

Asset detail includes the latest 100 changes. Full inventory operations have a 100000-row bound and return an explicit error rather than silently truncating. Use paginated inventory and narrower drift-report windows as appropriate.

Related guides: [endpoint onboarding](../apps/web/src/pages/GuidePage.tsx), [MCP HTTP](mcp-http-guide.md), [requirements audit](requirements-audit-2026-09-20.md).

## 兼容漂移诊断接口

旧 POST /api/v1/assets/drift 保留每个资产在 UTC 当天的首次观测快照，并与指定日期比较当前属性。重复采集不再覆盖该快照；重复比较只返回报告，不再向资产变更台账追加重复记录。已有历史快照不会被追溯改写。同一对前后哈希的变更编号保持稳定；报告时间表示本次计算时间。

baseline_date 必须是 YYYY-MM-DD，不能晚于 UTC 今天；未指定时取昨天。没有该日快照时按空集合比较，因此报告的“新增”不代表已认定未授权。snapshot_count 是此次参与比较的当前资产数；comparison_mode 为 first-observation。该兼容入口不提供完整的某一时刻资产集合，请使用“每日资产检测”获取包含空集合、删除与完整前后值的持久日检账本。

The legacy drift endpoint preserves each asset's first observation per UTC day. Later discovery cannot replace that baseline, and repeated comparisons do not append duplicate asset history. Historical snapshots are not rewritten retroactively. Dates must be canonical YYYY-MM-DD and no later than today; a missing date compares against an empty set, so Added is not proof of unauthorized use. snapshot_count counts current compared assets. Use Daily inventory for complete immutable daily sets and retained reports.

## 未知指标与发现计数

台账风险分只读取实际保存的 risk_score。缺少评分显示未知，0 是有效评分；排序时未知始终在已评分资产之后。exposure_score 是另一项暴露面评分，不能代替风险分，也不能推导公网、内网或完全隔离。网络范围只读取明确的 network_zone，未知可用 exposures=unknown 筛选；已有来源声明不代表本次连通性验证。

未处置发现数按本租户当前数据库记录计算，包含 pending/code-reviewed/verified，排除 fixed/false-positive 与已软删除记录。每次只汇总当前页最多 200 个资产，详情同口径；缺少 findings:read 时返回 null，页面显示未知，不能读出计数。查询失败返回错误，不能当成 0。0 表示当前没有该资产关联的未处置记录，不表示已完成扫描或证明安全。并发状态更新可能在分页与计数之间发生，刷新读取新状态。旧导入属性中的 open_findings 不再用于展示。

Risk scores remain Unknown until an actual risk_score exists; a measured zero stays 0, and unknown scores sort last in either direction. Exposure points cannot establish internet/intranet/isolation status. The network location uses explicit network_zone metadata; filter exposures=unknown to review missing metadata. A declared zone is not a connectivity test.

Open findings are tenant-scoped current saved records in pending, code-reviewed or verified state. Fixed, false-positive and deleted records are excluded. Counts are batched for the visible page (up to 200 assets) and use the same contract in detail. Missing findings:read returns null/Unknown; database failures return errors. Zero is not evidence that a scan completed or that an asset is safe. Concurrent updates can change counts between reads; refresh for the latest state. Imported counters in asset attributes are ignored.


## 观察状态与扩展指标

Agent 的 lastHeartbeatAt 是保留兼容性的字段名，实际来自资产 last_seen_at；资料编辑时间不作为心跳或观察时间。online 同样保留接口名，含义是“生命周期可用且近期被观察”：最近观察在有效 heartbeat_interval_secs 的三倍内，缺少有效间隔时使用 300 秒。无观察时间或时间在未来返回 null；过期或生命周期不可用为 false。控制台显示近期观察、未近期观察或未知。发现配置文件不等于确认进程存活、网络连通或业务调用成功。

会话、工具、Skill 挂载数、模型单价、优先级和 P95 延迟没有有效属性时返回 null，实际保存的 0 保持为 0。负数、错误 JSON 类型和越界优先级不能显示为有效数值。字段来源分别为 active_sessions、tool_count、attached_agents、input_price_per_ktok、output_price_per_ktok、priority、latency_p95_ms；该视图不会自动测量这些指标。价格单位是人民币 / 千 token，未知价格不能作为免费调用估计。工具或运行数据以最近保存的观察为准，时间过旧时重新采集。

个人用户选择当前组织，按集中指南执行终端上报，刷新 Agent/MCP 页面核对名称、观察状态及时间；缺少数据时先检查上报回执和凭据所属组织。企业用户为各组织配置独立采集身份和周期，并用业务测试账号验证真实调用。HTTP MCP 端点在配置入口保存后执行“发现”；修改端点版本会使旧工具数和旧发现时间失效，只有新发现成功返回空工具数组时才是 0。工具清单获取失败会显示错误，不能据空表判断未暴露工具。协议无法判断时显示未知，不再推断为 stdio。

### Observation and measurement contract (English)

The legacy lastHeartbeatAt field exposes asset discovery time, never inventory edit time. The online field means a recent observation in an available lifecycle, not a live process, network connectivity or a successful business call. Its window is three valid heartbeat intervals, or 300 seconds by default. Missing or future times return null; expired or unavailable assets return false.

Missing or invalid session/tool/attached-Agent counts, model prices, priority and latency return null; saved zero remains zero. Prices are CNY per thousand tokens, and unknown is not free. These are saved collector attributes, not automatically measured runtime metrics. Check the observation time before using them.

Select the organization, upload endpoint discovery and refresh. Check the upload receipt and credential organization when missing. Enterprises should configure collection identities and schedules per organization and verify business calls separately. After saving an HTTP MCP endpoint, run Discover. Reconfiguration invalidates the previous catalog; only a successful discovery with an empty tools array means zero tools. Failed tool requests show an error. Unknown transport remains unknown.

模型部署方式、模拟标记和主备角色未提供时同样保持 null。MCP 的“未标记明文”只描述发现属性，不保证凭据已托管或已完成检查。Missing deployment, simulation and fallback flags remain null. An MCP No plaintext flag label is not evidence of vaulted or inspected credentials.

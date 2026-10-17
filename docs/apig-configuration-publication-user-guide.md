# APIG 内容安全与 Model API 配置管理 / Configuration management

本入口管理已有内容安全挂载或已有 Model API 部署中的公开开关/模型槽权重。它与平台策略、APIG 独立限流发布分别使用自己的目标和确认。页面进入、刷新与原回执查询只有本地 GET，不初始化 Mock、不恢复、不续租、不派发云写。

This workflow manages public switches of an existing content-security attachment or model-slot weights of an existing Model API deployment. Platform policies and APIG independent rate-limit publication have separate targets and consent. Opening, refreshing and reading receipts perform local GET only, without Mock initialization, recovery, lease renewal or cloud writes.

## 实际操作

1. 到云连接配置选择 APIG 的真实地域、服务 endpoint、账号来源、模式和凭据。endpoint 是服务 API 根，不是 Console 网页。实云先在阿里云控制台安装 `ai-security-guard` 并绑定 Model API，或配置已有 Model API 的服务/模型及部署环境。平台不在本流程安装插件、创建服务/模型或部署。
2. 打开“APIG 内容安全与 Model API 配置管理”的“既有配置目标绑定”，明确选择类型。两类均填写实际 `httpApiId/gatewayId/environmentId`；内容安全另填写实际 `attachmentId/pluginId/classId/classVersion`。从当前已有资源复制，不猜测 ID。确认保留私密字段和未知影响，再人工保存。它使用连接配置 `expected_version`，不是云 CAS。
3. GET 不读云。人工“明确观察 APIG 配置目标”，Live 另确认只读访问。检查观察的公开字段、来源、版本、hash 与不支持原因，再“明确采用最新配置观察”。观察成功不会自动替换草稿。未知插件类/版本、错误挂载关系或不支持的 Model API 布局会拒绝准备，不能靠示例当真实证据。
4. 内容安全仅改变 `enabled/checkRequest/checkResponse/denyCode`。`checkResponse` 可能使流式响应变为非流式；认证、私密规则、其它配置保持。模型配置仅使用真实观察到的已有服务版本/模型槽，调整权重合计必须为 100。新模型/服务创建、智能路由与其它环境变更不属于此受管配置。
5. 准备预览，核对公开前后差异。分别确认目标、其它环境/私密字段保留、流式和共享影响未知、云无 CAS；Live 再确认。仅发送一次新的配置写入，保留原 UUID。写前完整观察与 fingerprint 比较不能阻止所有外部并发，无云 CAS 保证。
6. `Accepted + Matched + published` 是原请求的配置写入、独立回读及本地审计证据。**云部署与消费者加载仍未知**。Model API 配置保存后，到该地域/实例的云控制台 Model API 页面核查已保存配置，按其实际 Publish/Apply 提示执行发布，独立验证业务。平台没有猜测 `DeployHttpApi` 载荷或将配置保存说成已部署。
7. 超时、断线、无有效回包或 Unknown：禁止自动重发，先读原 UUID。404 不解锁；另一条已完成历史回执也不解锁当前意图。原事实已完成或服务端明确拒绝后，才点击明确新意图并重新预览。长写等待期间仍可读原回执，读取结果优先于迟到写回包。
8. `pending_audit`、或租约过期且没有可信终态：明确恢复本地回执，仅固定原本地事实和审计，不调用 provider、不重发。当前连接已停用或改版也可读历史、纯本地恢复及归档。另做原目标独立观察不会把 Unknown 升级成功。准备独立新意图前，完成原本地事实、租约后新观察，并明确承认旧请求仍可能到达；不能保证旧请求已经停止。
9. 可信历史回滚选择原历史公开开关/权重，采用新的观察基线和新 UUID，保留当前私密配置/其它环境，不复制整个旧云对象。历史不支持当前槽位或来源时给出原因并禁止准备。
10. 容量归档核对数量和代次后明确确认：删除所选回滚正文，保留永久原 UUID 事实，云配置不变。最多 128 条详情、64 MiB 加密正文，单次最多 100 条归档；列表只展示最新最多 50 条，旧 UUID 可单独读并归档。配置数据库才有跨实例持久保证；离线内存仅当前进程。

保存遇到 401/409 会保留草稿和旧 CAS。读取最新配置只比较，明确采用才能替换绑定草稿/版本，仍要重新确认并人工保存。连接来源、目标、模式或凭据变化清掉对应旧管理确认；目标 retarget 按连接配置提示重新填写合法凭据，保持目标时才保留原凭据。

## 实际 Mock 示例

这组字段是受控阶段一 Mock fixture，**不是实云资源**。先明确选类型，再点填入示例；不会保存、初始化或发送业务写。

| 字段 | 明确示例 |
| --- | --- |
| Region | `cn-hangzhou` |
| Model API / Gateway / Environment | `api-owned` / `gw-owned` / `env-owned` |
| 内容安全 attachment / plugin | `pa-owned` / `pl-owned` |
| 内容安全 class / version | `cls-owned` / `1.0.0` |

人工确认保存后，明确观察并另外勾选初始化 Mock。该次 POST 才在本租户持久 Mock 中初始化已有目标的模拟状态；不是云安装或真实请求。后续预览、一次写入、回读、历史回滚与归档使用真实平台状态机，不凭界面示例捏造成功。

## Permissions and English steps

Viewing and observation without initialization require `alicloud:read`. Configuration saving, Mock initialization, preview/apply, local recovery and archive additionally require `alicloud:write`. Only authorized writers load the cloud configuration editor. Responses contain public fields/IDs/hashes, not private provider configuration or credentials.

1. Configure the actual APIG region, service endpoint, account source, mode and credentials in Connection configuration. A Console webpage URL is not the API endpoint. Install/attach `ai-security-guard`, or set up existing Model API services and deployments, in the real Alibaba Cloud console first.
2. Select the managed kind explicitly. Copy actual API/Gateway/Environment IDs; content security also requires attachment/plugin/class/class-version IDs. Confirm preservation and unknown impact, then save with the real connection revision. No plugin installation, model/service creation or cloud dispatch occurs during binding save.
3. Observe manually, consenting separately to Live reads or owned Mock initialization. Inspect the public configuration and explicitly adopt the baseline. GET never initializes or observes the cloud. Source/configuration conflicts preserve the draft; compare and adopt explicitly before another manual action.
4. Edit only the supported content switches or observed existing model slots. Weights total 100; unrelated environments, authentication and private rules remain. `checkResponse` may make streaming non-streaming. Intelligent routing and new models/services are outside this profile.
5. Review the preview and all four confirmations, plus Live/Unknown-overlap consent when applicable. Send one new configuration PUT and retain its UUID. There is no cloud CAS or guarantee against external concurrency.
6. Accepted + Matched establishes configuration evidence only. Cloud deployment and consumer loading remain unknown. After saving a Model API configuration, inspect the actual regional instance in the cloud console, follow its Publish/Apply prompts and verify the real workload independently. No unsupported DeployHttpApi body is invented.
7. Lost responses, timeout and Unknown never trigger automatic retries. Read the original UUID; 404 or a historical different UUID does not unlock the held intent. Explicit local recovery does not call the cloud and remains available after disabling the connection. A post-lease observation does not upgrade an Unknown result.
8. Rollback uses trusted public history on a fresh current baseline with a new UUID. Archive requires reviewed generation and count, destroys selected rollback bodies and retains permanent facts. Database configuration is required for restart/cross-instance durability; offline memory is process-local.

The owned Mock tuple in the table above is explicit and synthetic. Choose the kind, fill the example, confirm/save, then observe with initialization consent. No credentials, plugin installations or real cloud resources are fabricated. Never substitute these IDs for live resources.

## 官方流程与契约

- [Manage Model APIs: regional instance, Edit and save](https://www.alibabacloud.com/help/en/api-gateway/ai-gateway/user-guide/managing-the-model-api)
- [Cloud console model routing workflow](https://www.alibabacloud.com/help/en/api-gateway/ai-gateway/user-guide/configure-smart-routing) — 本平台受管槽位不等于支持整套智能路由配置。
- [UpdatePluginAttachment](https://www.alibabacloud.com/help/en/api-gateway/ai-gateway/developer-reference/api-apig-2024-03-27-updatepluginattachment-ai-gateway)
- [GetPluginAttachment](https://help.aliyun.com/zh/api-gateway/ai-gateway/developer-reference/api-apig-2024-03-27-getpluginattachment-ai-gateway)
- [UpdateHttpApi](https://www.alibabacloud.com/help/en/api-gateway/ai-gateway/developer-reference/api-apig-2024-03-27-updatehttpapi-ai-gateway)
- [ai-security-guard streaming behavior](https://higress.io/en/docs/latest/user/plugins/ai/api-provider/ai-security-guard/)

这里只记录用户流程及支持边界；浏览器/SQL/实云验收必须分别依据实际执行回执，不能把本指南当通过证据。

## 内容插件配置格式 / Content-plugin configuration formats

已有 `ai-security-guard` 的 Base64 配置可为唯一字符串键的 JSON，或常见单文档 YAML 映射。
YAML 支持嵌套映射、数组、规范布尔/数字、单行引号字符串和字面/折叠块；输出仍为 YAML，
JSON 输出仍为 JSON。仅改变公开开关与拒绝码，私密凭据和未知字段保留其值；注释、键顺序和原排版不保留。
重复键、非字符串键、合并键、锚点/别名、显式标签、指令、多文档、非有限数字和不明类型会拒绝，
不将文本 `true` 当布尔开关，也不将文本或小数拒绝码当整数。此受限格式不支持多行引号字符串；
多行私密值使用 YAML 字面/折叠块。输入/输出各最多 64 KiB，YAML 最多 8,192 节点和 64 层。
原始 Base64 配置完整参与比较，因此私密值、注释或其它字段被外部改动也会阻止原预览写入。
以上是配置支持边界，不表示云 CAS、部署或消费者加载已得到验证。

An existing plugin's Base64 configuration may contain unique string-key JSON or a restricted single-document
YAML mapping. Nested objects/arrays, typed booleans/numbers, single-line quoted strings and literal/folded blocks
are supported. YAML stays YAML; JSON stays JSON. Private credentials and unknown values remain unchanged,
while comments, key order and formatting are not retained. Duplicate/non-string/merge keys, anchors/aliases,
tags, directives, multiple documents, nonfinite numbers and ambiguous types are rejected. Multiline quoted
scalars are unsupported; use a literal/folded block. Input/output are bounded to 64 KiB each; YAML has at most
8,192 nodes and 64 nesting levels. The whole original encoded document remains in the comparison fingerprint,
including private fields and comments. This does not establish cloud CAS, deployment or consumer acceptance.

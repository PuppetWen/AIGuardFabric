# 模型费用、预算与列表操作 / Model costs and browsing

## 个人接入

1. 确认当前组织，打开“模型网关 → 模型接入配置”，添加本地或 Mock 端点。台账发现的模型不等于可调用的网关配置。切换厂商时表单会填入后端提供的建议 Base URL，并清空前一厂商的模型 ID；Azure、Bedrock 和本地模型须改为自己的资源地址。手动填写的地址会保留。填写厂商控制台的模型或部署 ID、厂商凭据后保存，只有厂商及地址都未变时编辑留空才能保留旧凭据。Ollama/vLLM 的工作站 `127.0.0.1` 对 Docker 内服务不可达，须填容器可达地址；仅在确认该地址处于受控内网后开启“端点在受控内网”。`.env.example` 中历史 `AGF_OPENAI_API_KEY` 等变量当前不被模型网关读取，勿把真实密钥填在那里。
2. 配置输入、输出及缓存输入单价，单位均为 **CNY 元 / 1K Token**，支持六位小数。厂商以其他币种报价时，由负责人核对并换算后录入，平台不自动换汇。零价仅产生零估算，不代表供应商免费。
3. 创建模型调用专用 API Key，将客户端 Base URL 指向平台 `/v1`。使用简短请求验证；真实试调用会消耗厂商额度。更换端点厂商或目标地址时须重新填写厂商 API Key，避免旧密钥发往新目标。
4. 明细显示模拟和缓存标记。点击页码或页大小查询全部保留计量；模型台账的名称/负责人/标签搜索与分页同样作用于全部记录。

## 企业维护

- 使用最小权限；查看需要 `models:read`，配置、修改、启停、删除及试调用需要 `models:write`。切换组织或账号关闭上一身份的表单。
- 在路由策略中指定主端点、备用端点、选路方式；加权方式可逐端点设置权重。日预算为 CNY 元，0 表示不限。调用指定路由 ID，或使用系统自动选路时的有效默认策略；直接调用端点不受某个未使用路由的预算约束。
- 预算按 UTC 日重置，请求前预留估算费用，完成后按用量结算。取消或缺少上游用量会保守结算预留；租户/Agent 配额在设置与运行时策略中维护。路由日预算不等于整个组织的费用上限。
- 流式连接在活跃期间定期续租网关和运行时配额；向客户端发送输出持续阻塞超过五分钟时服务端结束该流并保守结算，避免长期占用并发额度。若上游在流结束后五分钟内仍不返回用量，同样按预留量结算。
- 客户端应设置 `max_tokens`。Mock 会按此截断并以 `length` 结束；真实上游若报告的输出 Token 超出请求值，或回复内容超过 4 MiB，非流式接口返回 503 且不泄露上游正文，实际用量仍结算并写入运行时拒绝事件。流式接口在超额时发错误事件、结清租约；早期已发送的分片无法撤回，客户端应丢弃部分输出并核对用量明细。上游未提供用量的错误按预留量保守结算。
- `temperature`、`top_p`、`stop` 与 `max_tokens` 会传给所选厂商；Gemini 使用 `generationConfig`，Bedrock Converse 使用 `inferenceConfig`，流式与非流式共用同一请求构造。Gemini 最多允许 5 个停止序列，超出会在触网前报错。[Gemini 参数说明](https://ai.google.dev/api/generate-content)、[Bedrock 参数说明](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InferenceConfiguration.html)。
- 上游错误响应可能含请求正文或凭据；平台只返回厂商与 HTTP 状态，不回显原始上游正文，流式失败使用固定提示。预筛拒绝、预算超限和端点调用失败会按会话写入运行时事件，管理员可据事件与厂商控制台核对；无上游用量时依既有规则保守结算预留。
- 图表和费用汇总为当前保留的真实调用估算，排除 Mock；不是供应商账单，也不是固定“今日”窗口。缓存命中以实际保存的计量为准。刷新同时更新台账、汇总、明细和路由。
- 当前回复缓存按完整请求、数据分级和端点配置计算精确指纹，不是向量相似度检索；改端点配置会产生新键。只有首选端点成功且请求可缓存时才保存回复，降级端点的回复不会冒充首选端点的缓存命中。温度采样、副作用工具和不符合端点分级的请求不缓存。
- 保存错误保留表单，网络错误不返回演示记录。编辑时不传价格、优先级、流式/工具能力的旧客户端保留现值，避免无意把价格清零。
- 多人编辑同一端点时，保存和删除必须带列表返回的当前版本。若返回 409，原草稿仍在页面中；先复制需要保留的改动，再点击“加载最新版本”确认丢弃旧草稿，对照后重新修改。删除冲突会刷新列表，避免删掉别人刚修改的端点。
- 路由策略的编辑及启停也使用列表版本。旧页面提交返回 409；路由表会刷新，编辑草稿保留到确认“加载最新路由”为止。加载前先复制需要保留的改动。
- 组织配额在“设置 → 网关配额”维护。多人同时修改时，旧版本返回 409；页面保留草稿并要求确认后再加载最新配额。只读账号可查看当前值，不显示可用的保存动作。
- 企业名称、套餐、区域及白标在“设置 → 租户与白标”维护。管理员先读取当前资料；保存时页面自动带上资料版本。若其他管理员已保存，接口返回 409，草稿与版本保留；先复制需要合并的文字，再确认“加载最新企业资料”，对照后重新保存。后台自动刷新不会覆盖冲突草稿。该页仅 `platform:admin` 可写。

## API 兼容

新字段：用量 `cost_cny`，路由 `budget_cny_per_day`，币种 `currency: "CNY"`；路由更新也接受 `budgetCnyPerDay`。
旧 `cost_usd` / `budget_usd_per_day` 返回值保留兼容，**一直是 CNY 数值**，没有乘除汇率；旧持久化预算按原值读取。不要把两种字段相加。
同一请求的新旧预算数值不一致会返回 400，非 CNY 币种、负数或超过 1,000,000 元的预算也拒绝，停用的策略同样校验。
明细保留 `mocked` 和 `cache_hit`；聚合按端点、模型及模拟标记分组，避免混合真实与模拟费用。

Mock 调用即使填写正价格，费用也为 0；调用次数、模拟标记和逻辑 Token 仍保留。精确回复缓存命中不重新产生模型费用，但仍计算请求配额；供应商自己的输入缓存有独立用量和价格，不能与平台回复缓存混淆。命中回复仍需经过当前响应过滤；缓存不是跳过策略或内容检查的通道。
端点列表返回 `version`。创建可省略 `expected_version` 或传 0；更新请求体必须传当前 `expected_version`，删除使用 `?expected_version=<当前版本>`。版本不匹配返回 409；旧版编辑/删除客户端应先读取列表再提交，不能盲目重试。
路由列表也返回 `version`。创建可省略 `expectedVersion` 或传 0；编辑和启停需带当前 `expectedVersion`。旧版本返回 409。
租户详情中的 `quota_defaults.version` 和保存配额响应中的 `version` 表示同一配置版本。首次保存可省略 `expectedVersion` 或传 0，后续更新必须传当前值；并发旧版本返回 409。

## English

Select the organization and configure a local or mock gateway endpoint first. Discovered inventory models are not automatically callable gateway endpoints. Selecting a provider fills the backend's suggested Base URL and clears the previous model ID. Enter your own resource URL for Azure, Bedrock or local models; a URL you typed yourself is preserved when switching providers. Enter the exact provider model/deployment ID and credential in the console. Leave the credential blank on an edit only if both provider and URL stay unchanged. From Docker, a workstation Ollama/vLLM at `127.0.0.1` is unreachable; enter an address reachable by the container and enable the controlled-private-network switch only after verifying its network placement. Historical vendor variables such as `AGF_OPENAI_API_KEY` in `.env.example` are not read by the gateway; do not put real secrets there. Enter input/output/cached-input prices in **CNY per 1K tokens**, up to six decimals. Verify and convert provider prices before entering them; zero is a zero estimate, not proof of free service.

Create a scoped platform API key and point the client to the platform `/v1` address. Real test calls consume provider quota. Re-enter the provider API key when changing an endpoint's provider or destination URL; the old credential cannot be reused for another target. Readers require `models:read`; configuration, toggles, deletion and calls require `models:write`. Switching organization/account closes the prior editor.

Select primary/fallback endpoints and route strategy. Weighted routes expose per-endpoint weights. Daily route budgets use CNY and reset at UTC midnight; zero means unlimited. They apply only when a request uses that route, not all tenant traffic. Requests reserve before dispatch and settle after completion; cancellation or absent upstream usage can retain conservative charges. Manage tenant/Agent limits separately.

Set `max_tokens` in clients. Mock endpoints truncate at the requested limit and return a `length` finish reason. If an upstream response exceeds that token limit or 4 MiB, non-streaming calls return 503 without exposing the upstream text; actual usage is settled and a runtime rejection is recorded. Streaming calls emit an error event and settle the lease. Discard previously received partial chunks after that event; if the upstream supplied no usage, the reserved amount is settled conservatively.

The gateway forwards `temperature`, `top_p`, `stop`, and `max_tokens` to Gemini `generationConfig` and Bedrock Converse `inferenceConfig` for both streaming and non-streaming calls. Gemini accepts at most five stop sequences; longer lists fail before a network request. See the [Gemini](https://ai.google.dev/api/generate-content) and [Bedrock](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InferenceConfiguration.html) API references.

Upstream error bodies may contain prompts or credentials. The gateway returns only the provider and HTTP status, never the raw upstream body; streaming failures use a fixed message. Runtime events classify request screening, budget, and endpoint failures by session. Compare those events with the provider console when vendor details are needed. Without upstream usage, the reserved amount is settled conservatively.

Active streams renew both gateway and runtime quota leases. If sending output to the client remains blocked for five minutes, the server closes the stream and conservatively settles the reservation. Missing upstream usage after five minutes is settled the same way.

Charts summarize retained real metering records and exclude mocks. They are estimates at configured prices, not provider invoices or a daily billing window. Detail pages show mock/cache markers and query all retained rows; inventory search and pagination run on the server. Refresh reloads all four sections. Errors retain the editor and do not switch to demo records.

Response caching currently uses exact fingerprints over the request, data classification and endpoint configuration; it does not perform vector similarity search. A changed endpoint gets a new key. Fallback responses are never cached as the primary endpoint. Sampled requests, side-effecting tools and requests outside the endpoint's data-class limit bypass this cache.

Mock calls cost zero even with positive configured prices; call counts, mock flags and logical token usage remain recorded. Exact response hits add no new model charge but still count as requests. Vendor prompt caching has separate usage and pricing. Cached replies still pass the current response screen and cannot bypass policy or content checks.

Use `cost_cny`, `budget_cny_per_day` and `currency: "CNY"` in new clients. Deprecated USD-named aliases keep the same historical CNY numeric values, without exchange-rate conversion. Conflicting aliases, a non-CNY currency or a budget outside 0–1,000,000 is rejected. Old clients omitting prices, priority or streaming/tool flags preserve existing values when editing endpoints.

Endpoint lists include `version`. Creation may omit `expected_version` or set it to 0. Updates require the current `expected_version` in the body; deletion requires `?expected_version=<current version>`. A stale version returns HTTP 409. The editor preserves a conflicting draft and offers an explicitly confirmed reload of the latest endpoint; copy any changes you need before reloading. Older edit/delete clients must fetch the current version before submitting and should not blindly retry a conflict.

Route policy lists also include `version`. Creation may omit `expectedVersion` or set it to 0; edits and enable switches require the current `expectedVersion`. HTTP 409 refreshes the route list. A conflicting editor keeps its draft until you confirm loading the latest route; copy changes you need before reloading.

Manage organization token and concurrency limits in Settings → Gateway quotas. The tenant's `quotaDefaults.version` and the save response's `version` refer to the same configuration. The first save may omit `expectedVersion` or set it to 0; later edits require the current value. A stale save returns HTTP 409, retains the draft, and requires a confirmed reload. Read-only users can inspect limits without a usable Save action.

Manage organization name, plan, region, and white-label settings in Settings → Tenant & white-label. The tenant `version` is separate from `quotaDefaults.version`. The first save may omit `expectedVersion` or set it to 0; subsequent saves require the current tenant version. An HTTP 409 keeps the draft, even during a background refresh. Copy any changes you need, confirm Load latest profile, compare, and save again. Only `platform:admin` may write this profile.

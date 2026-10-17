# 无上游 Key 的模型测试 / Testing models without an upstream key

此增量补齐阶段一 §11.5 的平台 HTTP 路径；当前已接入源码，编译、实际 HTTP/SQL 验收和生产部署仍须以本轮独立记录为准。平台自己的登录 User / 客户端 API Key 仍须具备原来的模型权限；“无 Key”仅指模型厂商的上游凭据。

在模型配置中新建启用的 OpenAI、Anthropic 或 Gemini 等云端点，填写厂商、模型和合法 Base URL，可不填写上游 API Key。保存与当前端点列表明确显示 `mocked=true`、`credential_configured=false`。请求仍走当前租户、模型选择、数据分级、签名策略和配额检查；通过后复用既有本地 Mock adapter，响应带 `X-AGF-Mocked: true`，不会向所填 URL 发请求。即使配置正价，模拟 Usage 与双费用账本费用仍为零。

平台 `/v1/chat/completions` 与 Anthropic `/v1/messages` 共用该路径。Mock 生成的内容仅用于接线测试，不能作为厂商模型质量、真实费用、真实部署或外部效果验收。现有精确缓存若返回已缓存回复，还需同时看 `X-AGF-Cached`；不能单凭内容推断厂商被调用。

编辑无凭据端点须手动提交当前 `expected_version`。空 API Key 保留已有凭据，不是删除命令；已有凭据端点更换厂商或 URL 仍需重新提供新 Key，不能将旧 Key 发给新目标。填写非空但全空白的 Key 被拒绝。添加合法 Key 后该端点恢复原真实 provider 路径；厂商拒绝 Key 不会被伪装为 Mock 成功。

以下情况继续拒绝：没有端点、全部端点停用、模型不存在、跨租户、权限或策略拒绝、分类不适合端点、坏密文或 AAD、明确空白凭据。不会通过自动创建 Mock 端点绕过这些检查。现有标为本地部署的 Ollama / vLLM 在未设 Key 时仍向配置的内网地址真实推理，不变成 Mock，也不宣称已经证明其网络位置。

SQL 原子路径的终态审计 `after.mocked` 来自真实封存的 Usage；无 Usage 时为 null。模拟成功保原事实、Usage、双账本和 Execute 审计同事务。既有 `sent-usage-known` 名称记录 adapter 完成，fresh Mock 也使用此值；它不能单独证明云网络发送，需同时看 `mocked`，验收定义要求实际监听器零请求。GET 原 Attempt / 显式本地 recover 不发模型请求。内存后端测试不证明 PostgreSQL 持久性。

Cloud endpoints may omit their upstream API key. The existing local Mock adapter is then selected after the normal tenant, authentication, model, classification, policy and quota checks. Endpoint views show `mocked=true`; successful fresh replies carry `X-AGF-Mocked: true`, use zero-cost Mock Usage, and contact no upstream provider. OpenAI chat and Anthropic Messages use the same controls.

The platform client's own User/API-Key authentication remains required. Empty key edits retain an existing credential; changing its provider or URL still requires a new key. Invalid encrypted credentials, whitespace-only keys, disabled/absent endpoints, missing models and current policy denial remain errors. Local unauthenticated Ollama/vLLM retain their real local transport. Mock results are wiring fixtures, not evidence of real vendor quality or deployment.

## 验收定义 / Acceptance definitions

- `agf-api --test gateway_no_key`：7 个普通真实 router/owned127 用例；三家 no-key Chat、SSE 与 Messages 零外发；CAS 和真实 Key 对照；签名 deny；坏 AAD/密文/显式空白；没有端点/停用/租户/平台认证；本地 Ollama/vLLM；厂商 401 不转 Mock。
- `agf-api --test gateway_no_key_database`：2 个 ignored 真 SQL 用例。原子模拟成功与重启原回执纯读；错误密文产生 NotSent/Failure、零 Usage/零发送。这里只定义，根代理须实际执行才可报告通过。
- SQL 运行前必须设置 `AGF_NO_KEY_DATABASE_OWNER="AIGuardFabric no key gateway SQL <run32>"`；数据库名精确为 `agf_requirements_test_gateway_no_key_<run32前12位>`；`AGF_TEST_DATABASE_URL` 仅 literal `127.0.0.1:5432`，无 query/fragment。数据库 COMMENT 精确等于 owner，OID>0 且后续重验；全部检查在 migrate 前。任务数据目录与清理仍由根代理的隔离 runner 负责。

没有新增依赖或真实厂商凭据。上述场景为验收定义；静态检查、实际执行和部署结果分别记录，不把源码接入视为测试通过。

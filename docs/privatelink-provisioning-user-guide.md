# PrivateLink 受管建链 / Managed PrivateLink provisioning

此入口实现选择已有服务、VPC、交换机和安全组的 Interface 端点创建，以及服务提供方的独立连接接纳。它不创建这些基础网络资源，不关闭原盘点入口，不自动配置DNS、证书、业务认证或安全组放行。

The managed entry creates an Interface endpoint from explicitly selected existing resources and separately accepts its connection. It does not establish DNS, TCP, TLS, application authentication, RAM ownership or packet reachability.

## 从控制台操作 / Console workflow

1. 在 AliCloud → PrivateLink 创建与接纳配置当前消费方来源。区域必须明确，Live凭据只在原连接配置保存。若企业端点已存在，先用现有 PrivateLink 盘点完成当前端点及两个子列表，保留其 scope UUID。
2. 填写资源表单并预览；跨地域创建必须明确带宽100–50000。既有端点接纳不发送创建带宽，不推断其费用。预览保留300秒，绑定原来源和本地generation。
3. 明确确认资源及费用、当前来源的消费方身份、观察不代表可达；Live还须明确确认真实云调用。Mock首次需显式初始化精确 cn-hangzhou / epsrv-agf-demo / vpc-agf-demo / vsw-agf-demo / sg-agf-demo。
4. Apply使用新原请求UUID；厂商 ClientToken 就是该UUID。ACK只表示请求收到，不表示创建完成。之后用独立 Observe UUID读取端点详情、完整可用区、安全组；缺页、身份不符或失败不会成为“空端点”。
5. 如需接纳，先在消费方来源仍匹配时导入完整当前盘点scope；对新创建端点，用刚完成的独立观察。然后在连接配置中明确切换到服务提供方来源。引用该观察UUID作接纳预览，重新确认当前提供方来源与原编号，单独Apply。不会自动复用消费方旧凭据或执行创建→接纳链。
6. 即使 Connected 和 requestedResourcesMatch=true，仍需运维人员分别验证DNS/TCP/TLS及业务认证。控制台 connectivityVerified/ramAuthorizationVerified 保持false。

Use a consumer source to preview/create, then observe independently. For enterprise existing endpoints, import a fresh complete inventory scope. Switch the configured source explicitly to the provider before a new accept preview. Each operation captures its own source version, original actor and UUID; labels do not verify RAM account identity. Provider authorization is decided by the cloud call.

## 原编号与恢复 / Original request and recovery

保留页面显示的原UUID或请求URL。响应丢失、超时、取消或服务重启后，先GET原编号。GET不执行云读取/发送/STS、不初始化Mock、不写审计。同UUID同输入只读；不同body/purpose为409，不自动换UUID重派。

If the response is lost, read the original UUID. A pending_audit result retains the provider fact separately from terminal audit. Explicit recover-local `{}` only publishes an already known local result or settles an expired claim; it never sends a provider request. A Started claim without a known result remains Unknown. Disabled source still permits same original subject with current read/write grants to settle locally.

Unknown资源风险不会因换account标签、region、endpoint、配置版本、凭据或归档而解除。Create风险保守关联tenant+service+VPC，Accept风险关联tenant+service+endpoint；导入既有端点也检查Create风险。厂商ClientToken不是本系统“外部恰好一次”证明。

## 归档与运行边界 / Archive and operating limits

最多32个终态请求正文一次归档，最多98个关联键；永久请求事实、原来源和Unknown风险保留。归档不删除云资源、不断开连接、不撤销费用。同原归档UUID纯读，新UUID即使changedCount=0也提交新本地回执和Create审计。

The detailed history is bounded at128 requests, encrypted body budget2MiB and permanent facts4096. Capacity never silently evicts UUIDs. SQL provides restart and multiple-instance claims; offline Mock only persists in the current ConfigStore process. Generic PrivateLink reads remain outside this workflow; generic Create/Enable must be fenced by the typed runtime admission.

## 官方协议 / Primary protocol

- [CreateVpcEndpoint](https://www.alibabacloud.com/help/en/privatelink/developer-reference/api-privatelink-2020-04-15-createvpcendpoint)
- [EnableVpcEndpointConnection](https://www.alibabacloud.com/help/en/privatelink/developer-reference/api-privatelink-2020-04-15-enablevpcendpointconnection)

当前交付为独立候选，单元、真实127、SQL与界面测试仅定义。未部署、未调用真实云；根任务实际准入后才可引用执行证据。

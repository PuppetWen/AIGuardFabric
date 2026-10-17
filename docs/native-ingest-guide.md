# 原生协议日志接入

HTTP Webhook 和 HTTP Pull 可直接在“日志接入 → 接入日志源”完成配置。Syslog、Kafka、Pulsar、NATS、MQTT、SNMP、OTLP、对象存储及 SQL 使用独立 `agf-ingest` 进程，控制台负责租户、源启停、解析模板和统计。

## 最短操作流程

1. 先选择业务租户，新建“原生接收器”日志源，选择协议，保存。也可以先部署接收器：第一条数据到达时自动登记默认源。
2. 打开该源的“接入指南”，把生成的覆盖配置保存到部署项目的 `docker-compose.native.yml`。已有文件合并修改，保留其他源的映射。
3. 在项目 `.env` 填写指南所列的协议参数；在覆盖文件 `environment` 中显式引用额外鉴权/TLS变量。仅填写 `.env` 不会自动传入未声明的容器环境变量。
4. 执行 `docker compose -f docker-compose.yml -f docker-compose.native.yml config --quiet` 校验配置，然后执行同一命令组合的 `up -d --no-deps agf-ingest`。不要把含凭据的完整渲染配置分享给他人。
5. 检查 `http://采集主机:8090/readyz`，确认 `sink=sql` 和所需协议的实际监听/连接状态；发送一条测试数据，刷新控制台检查累计保存、解析命中及最近错误。

原生 HTTP 端口 `/ingest/webhook` 使用 `AGF_WEBHOOK_TOKEN`，与 API 服务生成的 `/api/v1/ingest/sources/{id}/events` 不同。原生源不能通过后者投递。个人用户只需平台回传时优先选择控制台 HTTP Webhook。

## 租户与持久化

- 每个进程的 `AGF_INGEST_TENANT_ID` 固定为一个真实租户 UUID。多个企业组织分别部署接收器实例；分开监听端口、持久目录、订阅身份和数据库授权。
- `AGF_INGEST_INSTANCE_ID` 使用 1–64 个字母、数字、点、短横线或下划线。相同租户/实例/协议的自动源 ID 在重启后不变。
- `AGF_INGEST_SOURCE_IDS` 是 JSON 映射，例如 `{"syslog-udp":"控制台源UUID","kafka":"另一源UUID"}`。配置中绑定的原生接收器名和协议必须匹配。不要在两个不同组织复用同一源 ID。
- Compose 默认启用 `AGF_INGEST_SQL_SINK=1`。数据库不可用时启动失败，监督程序可重试；不会确认保存到临时内存。只在显式离线演示时同时设置 `AGF_INGEST_SQL_SINK=0`、`AGF_MOCK_MODE=1`。
- 控制台启停和模板选择在下一条/批数据处理前读取。删除留下不可自动恢复的记录，历史日志仍保留。重新接入需要新建源 ID 并修改映射。
- 停用前先暂停发送端。UDP/SNMP 没有可靠确认，停用、网络故障和接收器异常可能丢包；有可靠消费确认的协议应保留重试/积压策略。已经开始处理的一批可完成。

## 协议参数与设备侧设置

| 接收器 | 部署参数 | 设备或上游设置 |
|---|---|---|
| syslog-udp / syslog-tcp | `AGF_SYSLOG_UDP_PORT` / `AGF_SYSLOG_TCP_PORT`，容器默认 5514 | 填采集主机地址、实际发布端口；RFC3164/5424 文本；TCP 支持持续连接及 octet counting |
| syslog-tls | `AGF_SYSLOG_TLS_PORT`、`AGF_SYSLOG_TLS_CERT`、`AGF_SYSLOG_TLS_KEY` | RFC5425；校验采集端证书，端口需显式发布。PEM 文件以只读 volume 挂载，不把宿主机路径当成容器路径 |
| webhook | `AGF_WEBHOOK_TOKEN` | POST `/ingest/webhook`，`Authorization: Bearer ...`；对公网发布时在前置代理终止 HTTPS 并限制来源 |
| kafka | `AGF_INGEST_KAFKA_BROKERS`、`..._TOPIC`、`..._GROUP_ID` | 推荐独立消费者组；不要与其他消费应用共用组 ID。鉴权使用 `..._SASL_MECHANISM/USERNAME/PASSWORD`，TLS 使用 `..._TLS/CA/CERT/KEY` |
| pulsar-native | `AGF_INGEST_PULSAR_URL`、`..._TOPIC`、`..._SUBSCRIPTION` | `pulsar://` 或 `pulsar+ssl://` 原生入口；需要时填写 `..._TOKEN`、TLS 及订阅类型 |
| pulsar | `AGF_INGEST_PULSAR_SERVICE_URL`、`..._TOPIC`、`..._SUBSCRIPTION` | 仅使用 KoP 的 Kafka 协议端口。不是原生 6650 端口；同时配置原生 URL 时原生方式优先 |
| nats-jetstream | `AGF_INGEST_JETSTREAM_URL`、`..._IDENTITY`、`..._SUBJECT` | 固定 identity 决定 stream/durable 名；不要在重启时随机生成 |
| mqtt | `AGF_INGEST_MQTT_BROKER`、`..._TOPIC`、`..._CLIENT_ID` | 使用稳定客户端 ID 和适合业务的 QoS；broker 支持 mqtt/mqtts/ws/wss；用户名/密码分别设置，勿放入 URL |
| snmp-trap | `AGF_INGEST_SNMP_LISTEN`、`..._VERSION`、`..._COMMUNITY` | 发布对应 UDP 端口；v3 配置 `..._V3_USER`、安全级别和认证/隐私口令，详见 `apps/ingest/src/main.rs` 参数表 |
| otlp / otlp-traces / otlp-metrics | `AGF_INGEST_OTLP_ENABLED=1` | OTLP/HTTP logs/traces/metrics 分别发送到 8090 的 `/v1/logs`、`/v1/traces`、`/v1/metrics`；可使用独立 `AGF_OTLP_HTTP_LISTEN` |
| otlp-grpc / otlp-grpc-traces / otlp-grpc-metrics | `AGF_INGEST_OTLP_GRPC_ENABLED=1`、`..._LISTEN` | 共用默认 4317，分别提供 LogsService、TraceService、MetricsService；三个来源使用独立 ID。需要显式发布端口，支持 gzip、TLS/mTLS |
| object-pull | `AGF_INGEST_OBJECT_PULL_BUCKET`、可选 `..._PREFIX` | S3/OSS/MinIO 配置 `AGF_S3_ENDPOINT/REGION/ACCESS_KEY/SECRET_KEY/FORCE_PATH_STYLE`；将 `..._STATE` 指向持久目录 |
| sql-pull | `AGF_INGEST_SQL_DSN`、`..._QUERY`、`..._CURSOR_FIELD/TYPE` | 使用只读数据库账户及稳定递增游标；将 `..._CURSOR_PATH` 指向持久目录。PostgreSQL/MySQL/MSSQL/Oracle 的额外驱动要求见进程参数表 |

表中 `..._` 表示同一行的前缀，如 Kafka 的 `..._TOPIC` 是 `AGF_INGEST_KAFKA_TOPIC`。认证/TLS相关变量必须加入覆盖文件的 `environment`；在 Docker 中将游标目录挂载到持久 volume，避免重建容器后重新消费。

OTLP/gRPC 指定 TLS 或证书/CA 后，材料必须完整且有效。证书读取失败、密钥不匹配、CA 无效或只填证书却未启用 TLS，都会使该接收器拒绝启动；不会退回明文端口。其他协议仍可运行，原因见 `/readyz` 的 notes。

## 排障

- **页面没有源**：确认正在查看配置的租户；自动登记需要至少一条数据进入流水线。预建源需把 UUID 放进 `AGF_INGEST_SOURCE_IDS`。
- **源可见但无数据**：先查 `/readyz` 的实际监听、`notes` 和协议状态；再核对设备目标端口、Docker ports、Windows 防火墙及上游订阅权限。
- **有保存、没有解析命中**：源名称可进入原文回放。使用模板样本验证，再在源编辑中选择模板；失效或停用的指定模板会明确拒绝后续接入。
- **删除后仍报拒绝**：这是防止重启恢复已撤销接入。新建源并替换映射；不要删除历史数据来解决。
- **统计短暂不更新**：刷新页面；接收器需要能访问与控制台相同的数据库。收件与归一化事件分别持久化，协议重试可能保留重复原文。

数据库、TLS、消费者组和设备间网络的真实环境检查属于部署验收；页面“已保存配置”本身不表示远端平台连接成功。

## 原文预览与明确回放

1. 在“接入管理”选择日志源；“回放样例”只读取当前尚未解析的原文，用来检查来源和格式。刷新预览不会生成事件，也不会把原文标为已解析。
2. 修正解析模板并用正负样本验证后，在“重新解析原始日志”中选择同一日志源，点击“执行回放”。页面会显示检查数、新解析数、失败数及命中的解析器；切换日志源后不沿用上一源的结果。
3. 检查风险发现和事件列表中的新增结果。已解析的原文不会被重复回放，已有事件仍保留；需要再次处理时先确认原始日志状态和解析模板，不要靠刷新页面触发写入。

API 也分清方法：`GET /api/v1/ingest/replay?sourceId=<源 ID>` 仅预览，返回 `preview_only: true`；`POST /api/v1/ingest/replay` 携带 `{"source_id":"<源 ID>","limit":1000}` 才执行写入。两者都要求 `sources:write`，因为原文可能含敏感数据。未解析记录为空时返回 0 条和原因，不生成演示结果。

English: In **Ingest**, select a source to preview unparsed raw logs. Refreshing the preview is read-only. After testing the parser, use **Reparse raw logs → Run replay** to save new events and review checked, parsed, failed and parser counts. GET previews; only POST executes replay. Both require `sources:write` because raw payloads may be sensitive.

## OpenTelemetry Collector 接入

在控制台为所需信号建立对应原生源，将三个 ID 合并进同一份 `AGF_INGEST_SOURCE_IDS` JSON；重启接收器后检查 `/readyz`。Collector 的 exporter 示例：

```yaml
exporters:
  otlp/aiguardfabric:
    endpoint: aiguardfabric.example:4317
    compression: gzip
    tls:
      ca_file: /etc/otel/ca.pem
      cert_file: /etc/otel/client.pem
      key_file: /etc/otel/client-key.pem
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlp/aiguardfabric]
    traces:
      receivers: [otlp]
      exporters: [otlp/aiguardfabric]
    metrics:
      receivers: [otlp]
      exporters: [otlp/aiguardfabric]
```

此片段合并到现有 Collector 配置中，保留其 `receivers.otlp` 定义；替换目标主机和证书路径。只启用服务端 TLS 时去掉客户端 cert/key；隔离的本机明文演示才使用 `tls.insecure: true`。容器证书路径必须是已挂载的容器内路径。

成功响应不含部分失败字段；部分拒收会返回各信号拒绝数，Collector 不应重发该批。临时存储不可用返回 `Unavailable`（HTTP 为 503），便于客户端重试。请同时监测 Collector 的发送失败/丢弃指标和本平台日志源接入量。协议依据：[OTLP 规范](https://opentelemetry.io/docs/specs/otlp/)。


## 持久事件投递与排障

启用 `AGF_NATS_ENABLED=1`、设置 `AGF_NATS_URL` 与 `AGF_NATS_STREAM`。管理服务和原生接收器均可处理同库的队列，数据库租约防止多副本同时领取；租户停用时暂停其投递。日志源配置无需重复填写消息服务凭据。

原文、归一化事件与待投递记录在同一事务中保存。消息服务短暂离线不会让已确认入库的数据丢失；服务恢复或应用重启后自动续传。连接凭据留在部署环境中。接入管理顶部显示本租户待确认/待重试数；队列为空本身不能证明网络连通。

默认事件流使用文件存储、七天保留、1 GiB 上限和拒收新消息策略。容量不足时待投递记录继续保留在 SQL，修复容量后重试；应为实际数据量规划磁盘、保留期和消费者吞吐。已确认的 SQL 投递回执七天后自动清理，未确认记录不会按时间清除。

排查顺序：检查 NATS 和 JetStream 服务、认证/TLS配置、数据库空间、流容量，再检查 agf-ingest/agf-server 的 Event delivery 日志。已有同名流须使用对应主题、文件存储及兼容保留策略；不兼容时系统保留 SQL 队列并报错，不自动覆盖流。检查同主题已绑定的流，备份后调整既有配置，勿删除流来绕过报错。

确认丢失时可能再次发布相同事件。JetStream 使用租户和事件 ID 去重，默认窗口 24 小时；消费者仍须按事件 ID 幂等处理。一次投递最多等待五秒，失败后退避重试，最长间隔五分钟。

## 从接入记录到可处理的告警

1. 在接入管理中选择当前个人空间或企业组织，启用日志源和解析模板；发送一条样本并检查“解析命中”。无法匹配的记录保留在原始日志中，修复模板后回放。
2. 在检测规则中启用所需规则，确认作用目标、灰度比例与正负样本。普通事件的规则目标为 `event-payload`（扫描输入类型为 `log-payload`），AI 会话扫描 `prompt`，工具调用扫描 `tool-arguments`，模型事件扫描 `model-output`，配置变更扫描 `config`；事件类别由解析模板映射。
3. 发送命中该规则的新记录。接入页顶部“事件分析”显示待处理、重试和已处理数；零命中也算已处理。命中产生风险发现和告警，并关联事件 ID、原文哈希和解析后的证据。若需把发现和告警关联到资产，在解析模板中将 `ai.agent_id`、`ai.mcp_server_id` 或 `ai.model_endpoint_id` 映射为**资产台账中的 UUID**（不是外部主机编号或模型网关配置编号）。系统只关联当前租户内类型匹配、未删除的资产；`host.name` 等文本不会自动充当资产身份。一个事件可在告警中关联多个资产，发现归属其最相关的一个资产，资产详情的未处置发现数随之更新。
4. 在风险发现中查看证据并复核，在告警中心指派、关闭或建立案件。在系统设置中保存并启用通知渠道；自动通知按渠道最低等级筛选，相同活动告警的同等级通知会去重。
5. 通过不同浏览器或重启管理服务再次查询，告警历史、SLA、发现与证据应保持一致。

### HTTP Webhook 的 AI 工具事件示例

个人用户可在“接入管理”新建 HTTP Webhook 源，并为它选择 JSONPath 解析模板。企业用户先切换到目标租户，再为每个发送系统分配仅有 `sources:write` 的独立平台 API Key；不要在多个组织之间复用密钥。模板将原文 `message`、`severity`、`category`、`mcp` 分别映射到 `message`、`event.severity`、`event.category`、`ai.mcp_server_id`，必填字段设为 `message`、`mcp`。`mcp` 必须填写当前租户资产台账里 MCP 服务的 UUID，可从 MCP HTTP 端点详情取得；发送系统自己的字符串编号不会触发资产关联。

向该源显示的 `/api/v1/ingest/sources/{id}/events` 地址发送 JSON；示例载荷为 `{"message":"受控测试内容","severity":"high","category":"ai-tool-call","mcp":"<MCP 资产 UUID>"}`。请求使用 `Authorization: Bearer <本租户 API Key>` 和 `Content-Type: application/json`。先确认响应的 `accepted=1`、`matched=1`，再看“接入管理 → 事件投递与分析”中的已处理数；随后从风险发现、告警中心进入关联案件。工具调用类规则的目标应为 `tool-arguments`，否则已处理也可能是零发现。自动响应只处理启用后新建的告警，先按[自动响应指南](automatic-response-guide.md)核对预览、目标资产和审批人。

平台保存原文、规范事件及投递记录后由后台异步处理；推送成功仅证明接入已保存。若“待处理”持续增加，检查解析器、规则作用目标、JetStream 和服务日志，不要重复发送同一原文来代替排障。隔离 PostgreSQL + 本机 NATS 的回归已验证投递确认、后台消费、自动建案、重装配后查询和 MCP 代理拦截；客户真实设备仍需单独验收。

管理服务自动消费 JetStream，并定期补处理共享 SQL 中没有完成回执的事件。因此关闭 NATS 时，SQL 部署仍能自动分析；内存演示模式没有此后台持久链路。事件读取以数据库中的已提交记录为准，消息载荷不能替换原始证据。

风险发现、活动告警合并、事件关联和完成回执在同一 SQL 事务提交后才确认消息。进程在确认前中断会触发重投；完成回执防止重复增加告警计数。另一条新事件命中同实体、同规则时才增加合并次数；已关闭告警不会被复用。发布新规则不会重新扫描已处理事件，使用扫描或原始日志回放明确发起复核。

单条分析失败会回滚其事务并退避重试，不拦住后续记录；通知另有持久队列，重启后可继续派发。尚未配置通知渠道时只生成控制台告警。持续重试时检查规则、数据库空间和服务日志；不要删除完成回执或消息流来清空计数。

当前已验证规则匹配、跨源实体去重、SQL 事务、真实本地消息重投及 Webhook 到案件的后台链路。时序、图路径与历史基线可在“检测规则 → 关联分析”中配置，保存前需通过正负序列回归，详见 [关联分析指南](correlation-guide.md)。自动 SOAR 可创建待审批任务；队列送达或案件创建均不代表处置动作已经执行，仍须查看审批与执行记录。


## 来源白名单与客户端证书

Syslog / OTLP 的直接连接限制、Syslog TLS 客户端 CA、配置生效时机、容器挂载和负例验证，见 [来源限制与双向 TLS 指南](native-source-security-guide.md)。

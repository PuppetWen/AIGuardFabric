# AIGuardFabric 厂商日志解析模板库（`parsers/`）

本目录是 §4.5「统一日志与告警接入」的**厂商模板库**：每个 YAML 文件是一个
[`ParserDefinition`](../crates/agf-core/src/parser.rs)，由
[`ParserRegistry::load_dir`](../crates/agf-ingest/src/registry.rs) 递归加载（`*.yaml` / `*.yml`），
经 `ParserDefinition::validate()` 与 `engine::validate_pattern()` 双重校验后进入匹配集。
**加载失败的模板不会让进程崩溃**：只会 `warn` 并计入 `RegistryStats::invalid`。

模板 schema 以代码为准（`crates/agf-core/src/parser.rs` / `crates/agf-ingest/src/engine.rs`），
本文件只补充"怎么写才对"的约定。

## 目录结构

```
parsers/
  README.md                 本文件
  qingteng/                 按厂商分子目录（目录名 = 厂商英文短名，小写）
    qingteng-hive-webshell-syslog.yaml
    samples.json            该厂商的**行内正样本 + 关键字段断言**（测试逐条跑真实解析）
  aliyun/ huawei/ tencent/ sangfor/ qianxin/ nsfocus/ topsec/ venustech/
  fortinet/ paloalto/ crowdstrike/ wazuh/ suricata/ zeek/ snort/ modsecurity/
  webserver/ aws/ azure/ gcp/ k8s/ os/ generic/ ai/
```

## 命名规范

| 对象 | 规范 | 示例 |
|---|---|---|
| 目录 | 厂商英文短名，小写、无空格 | `qingteng/`、`paloalto/` |
| 文件 | `<厂商>-<产品>-<形态>.yaml`，与 `key` 同名 | `fortinet-fortigate-dns-kv.yaml` |
| `key` | 全局**唯一**，小写 kebab-case，ASCII（同 key 会按"热更新"覆盖，测试断言无重复） | `aliyun-waf-sls-json` |
| 形态后缀 | `json` / `cef` / `leef` / `kv` / `csv` / `grok` / `regex` / `jq` / `syslog` | `qianxin-tianyan-cef` |
| `vendor` / `product` | 厂商用中文或官方英文名；产品用官方产品名 | `青藤云` / `蜂巢` |

## 字段语义（模板作者必读）

| 字段 | 语义与取值 |
|---|---|
| `engine` | `grok` / `regex` / `jsonpath` / `jq` / `syslog` / `cef` / `leef` / `gelf` / `csv` / `kv`（`cel`、`plugin` **未实现**，写了会被加载期拒绝） |
| `pattern` | Grok 表达式 / 正则 / **逐行 `字段=$.路径`** 的 JsonPath 规格表 / JQ 程序 / CSV 表头。**除 `syslog` 外不允许为空**（`cef`/`leef`/`gelf`/`kv`/`csv` 也要求非空，填标记串即可） |
| `mapping.map` | **引擎输出后的字段名 → AGF-ECS 路径**。CEF/LEEF 的标准键已由引擎改写（`src`→`source.ip`、`cat`→`event.category_raw`…），映射表按改写后的名字写 |
| `mapping.severity_field` / `severity_map` | 等级字段（**源字段名**）+ 厂商取值 → `info`/`low`/`medium`/`high`/`critical`；未在表中时用通用词表推断（error/warning/notice/…） |
| `mapping.category_map` | 依次按 `event.category_raw` → `rule.id` → 动作原值 查找，值取 `event.category` 词表：`authentication`/`network`/`process`/`file`/`database`/`web`/`ai-session`/`ai-tool-call`/`ai-model`/`configuration`/`cloud-control`/`malware`/`intrusion`/`policy`/`other` |
| `mapping.action_field` | 动作字段（源字段名）；`block`/`deny`→`denied`、`allow`→`allowed`、`login`→`login`…（`event.action_raw` 保留厂商原文） |
| `mapping.time_field` / `time_format` | 时间字段（源字段名）+ 格式；支持 `unix`、`unix_millis`、strftime（`%Y-%m-%d %H:%M:%S`、`%b %e %Y %H:%M:%S`…）。**注意**：映射表里已写 `event.time` 时同样按 `time_format` 解析 |
| `mapping.defaults` | 源字段缺失时的兜底（**优先级高于 `category_map`**，模板作者意图优先） |
| `required_fields` | **引擎输出后**的字段名（Grok/Regex 是命名组名；CEF/LEEF 是改写后的 ECS 路径）。缺失即视为不匹配，用于多模板消歧 |
| `protocols` | `IngestProtocol` 取值：`syslog`/`webhook`/`kafka`/`pulsar`/`nats`/`mqtt`/`http-pull`/`http-push`/`snmp-trap`/`object-storage`/`jdbc`/`beats`/`otlp`/`sql-poll`/`file`/`mcp` |
| `sample_fixture` | 样本文件路径（相对仓库根）。**每个模板必须有正样本**；确无样本时留空并在 `samples.json` 写 `untested_reason`（等价 `sample: none`） |
| `description` | 中文说明：日志类型、关键字段、归一化取向 |

> 未映射字段**不会被丢弃**：`ParseOutcome::extra` → `Event::extra`，原始载荷保真落库可回放。

## 样本（正样本 + 真实感样本文件）

两层登记，缺一不可：

1. **行内正样本 + 关键字段断言**：`parsers/<vendor>/samples.json`
   ```json
   "qianxin-tianyan-cef": {
     "fixture": "parsers/qianxin-tianyan-cef-1.log",   // 可选：独立样本文件（相对 tests/fixtures/logs/）
     "line": "<134>Feb 21 10:28:00 ... CEF:0|...",      // 行内样本（与 fixture 同时声明时必须逐字一致）
     "protocol": "syslog",
     "expect": { "source.ip": "203.0.113.60", "event.severity": "high", "event.category": "web" }
   }
   ```
   `expect` 的键是 **`apply_mapping` 之后的字段名**，`event.severity` / `event.category` 额外做归一化交叉断言。
   模板**不显式给类别**、依赖消息关键字推断时，改用 `"category_after_normalize": "authentication"`
   （测试断言归一化后的 `Event::category`，而不是映射字段）。
2. **独立样本文件**：`tests/fixtures/logs/parsers/<name>.log`，同时登记进
   `tests/fixtures/logs/manifest.json` 的 `parser_library` 段与 `tests/fixtures/logs/SOURCES.md`。

**来源纪律**：公开原文样本同时登记在 `tests/fixtures/logs/manifest.json` 的 `public_samples` 与 `public/manifest.json`，记录固定版本、来源 URL、原始文件与摘录哈希、行号和许可证。公开实验捕获与客户生产日志分别标注；只摘取完整原始行，保留行尾，不改字段或取值。旧重建样本继续保留 `synthetic=true`，不得把格式重建改称原文；AWS/PAN-OS 原有主样本与追加原文并存。

公开样本覆盖 AWS CloudTrail、Microsoft Entra 服务主体登录、CrowdStrike FDR、Palo Alto PAN-OS 与 Zeek JSON conn.log。接入时选择对应模板，FDR 扁平进程事件与 Event Streams 包装事件、Zeek JSON 与 TSV 使用各自模板。回放步骤见 [样本来源与回放](../tests/fixtures/logs/SOURCES.md)。

## 如何新增模板

1. **先检索**：`campaign_memory_search` / 已有目录里是否已有同产品模板，避免重复 key；
2. 在对应厂商目录建 `<厂商>-<产品>-<形态>.yaml`：写 `key`/`name`/`vendor`/`product`/`protocols`/`engine`/`pattern`/`mapping`/`required_fields`/`description`；
3. 在 `parsers/<vendor>/samples.json` 加一条 `line` + `expect`（有独立样本文件则加 `fixture`）；
4. 有独立样本文件时：写到 `tests/fixtures/logs/parsers/`，并登记 `manifest.json` → `parser_library.samples` 与 `SOURCES.md`；
5. **本地校验**（必须全绿）：
   ```powershell
   $env:CARGO_HOME='<项目根>\.cargo'; cargo test -p agf-ingest --test parsers_library
   cargo clippy -p agf-ingest --all-targets -- -D warnings
   ```
   `parsers_library.rs` 会断言：模板总数 ≥ 100、`invalid == 0`、key 唯一、每个厂商目录非空、
   每个模板都有正样本（或显式 `untested_reason`）、正样本关键字段提取结果与 `expect` 一致。
   统计口径（模板总数 / 厂商分布 / 引擎分布 / 样本覆盖）见 `scripts/parsers-stats.ps1`。

## 协议声明与放宽匹配（协议白名单）

模板的 `protocols` 是**显式声明**：注册表严格趟只会尝试"声明中包含当前接入协议"的模板
（`protocols` 留空 = 不限协议）。用 `IngestProtocol` 的文本形式（`syslog` / `webhook` / `http-pull` /
`beats` / `file` / `kafka` / `pulsar` / `mqtt` / `otlp` / `object-storage` / `jdbc` / `snmp-trap` /
`http-push` / `nats` / `mcp` / `sql-poll`）。

**放宽趟**：当严格趟**零命中**时，注册表会忽略协议白名单再补试一遍（只补试"声明了协议但不含当前协议"
的模板），命中结果被标记为 `protocol-relaxed`。它的存在是因为模板库对新接入协议的声明天然滞后
（例如一条阿里云 WAF JSON 经 MQTT 进来，模板只声明了 `webhook`/`http-pull`/`kafka`，字段完全对得上
却会被白名单跳过）。放宽趟的三条安全网：

1. **只在严格趟零命中时才跑**——声明过的协议绝不会因为放宽而改选模板；
2. `required_fields` 校验照常生效（放宽的是协议白名单，不是字段要求）；
3. 命中的趟次如实暴露：`RegistryStats::matched_relaxed` / `relaxed_hits`、
   `PipelineStats::matched_relaxed`（`/stats` 直读）、解析结果里的 `matched_by`。

因此**新增模板时的正确做法**是显式声明全部适用协议；把协议补全能消掉放宽命中。判断"可以安全补声明"
的口径见下一节：**只有载荷形态本身可自证**（字面标记 + `required_fields` 不可替代）的模板才补，
其余交给放宽趟并在实测矩阵里核对是否出现跨厂商误匹配。

**实测基线（放宽趟为什么把命中率抬高这么多）**：`cargo test -p agf-ingest --test protocol_relaxed_match
-- --nocapture` 会把矩阵打出来。以完整模板库（内置 19 + `parsers/` 库）跑 `parsers/*/samples.json` 的
118 条真实样本为例：按样本**自己声明的协议**投放，严格命中 118/118、放宽命中 **0**（协议声明自足）；
改用 **MQTT** 投放，严格只剩 29、放宽补上 89 —— 其中 49 条交回样本**自己的模板**、12 条命中**同厂商**
模板、28 条命中**别的厂商**模板（这 28 条就是放宽趟的误匹配候选，逐条打印）。差距全部来自
"模板库对新接入协议（`mqtt`/`otlp`/`jdbc`/`pulsar`/`snmp-trap`）几乎没有声明"，不是解析能力差异。

## 接入方式

`agf-ingest` 启动时自动加载本目录：环境变量 `AGF_PARSERS_DIR` 优先；容器内默认 `/app/parsers`；
本机回退 `<项目根>/parsers`。加载成功数/失败数打日志，**加载失败只 warn 不崩溃**。

## 模板清单（自动生成，勿手工编辑本段）

<!-- TEMPLATES:BEGIN -->
| file | key | name | vendor | product | engine | sample |
|---|---|---|---|---|---|---|
| `ai/anthropic-messages-gateway-json.yaml` | `anthropic-messages-gateway-json` | Anthropic Messages 网关日志 | Anthropic | Messages API 网关 | `json-path` | `parsers/ai/samples.json#anthropic-messages-gateway-json` |
| `ai/coze-bot-json.yaml` | `coze-bot-json` | Coze Bot 调用日志 | Coze | Bot 应用 | `json-path` | `parsers/ai/samples.json#coze-bot-json` |
| `ai/dify-app-json.yaml` | `dify-app-json` | Dify 工作流运行日志 | Dify | LLM 应用平台 | `json-path` | `parsers/ai/samples.json#dify-app-json` |
| `ai/langgraph-agent-json.yaml` | `langgraph-agent-json` | LangGraph Agent 执行日志 | LangGraph | Agent 运行时 | `json-path` | `parsers/ai/samples.json#langgraph-agent-json` |
| `ai/llm-gateway-generic-json.yaml` | `llm-gateway-generic-json` | 自研 LLM 网关调用日志 | 自研 | LLM 网关 | `json-path` | `parsers/ai/samples.json#llm-gateway-generic-json` |
| `ai/mcp-proxy-jq.yaml` | `mcp-proxy-jq` | MCP 代理日志（JQ） | 自研 | MCP 代理 | `jq` | `parsers/ai/samples.json#mcp-proxy-jq` |
| `ai/mcp-proxy-tool-call-json.yaml` | `mcp-proxy-tool-call-json` | MCP 代理工具调用拦截 | 自研 | MCP 代理 | `json-path` | `parsers/ai/samples.json#mcp-proxy-tool-call-json` |
| `ai/openai-chat-gateway-json.yaml` | `openai-chat-gateway-json` | OpenAI 兼容网关调用日志 | OpenAI | Chat Completions 网关 | `json-path` | `parsers/ai/samples.json#openai-chat-gateway-json` |
| `aliyun/aliyun-actiontrail-json.yaml` | `aliyun-actiontrail-json` | 阿里云 ActionTrail 操作审计 | 阿里云 | ActionTrail | `json-path` | `tests/fixtures/logs/parsers/aliyun-actiontrail-1.log` |
| `aliyun/aliyun-cdn-access-log.yaml` | `aliyun-cdn-access-log` | 阿里云 CDN 访问日志 | 阿里云 | CDN | `grok` | `parsers/aliyun/samples.json#aliyun-cdn-access-log` |
| `aliyun/aliyun-cloudfw-flow-json.yaml` | `aliyun-cloudfw-flow-json` | 阿里云云防火墙流量日志 | 阿里云 | 云防火墙 | `json-path` | `parsers/aliyun/samples.json#aliyun-cloudfw-flow-json` |
| `aliyun/aliyun-oss-access-log.yaml` | `aliyun-oss-access-log` | 阿里云 OSS 访问日志 | 阿里云 | OSS | `grok` | `parsers/aliyun/samples.json#aliyun-oss-access-log` |
| `aliyun/aliyun-sas-baseline-json.yaml` | `aliyun-sas-baseline-json` | 阿里云云安全中心基线风险 | 阿里云 | 云安全中心 | `json-path` | `parsers/aliyun/samples.json#aliyun-sas-baseline-json` |
| `aliyun/aliyun-sas-vuln-json.yaml` | `aliyun-sas-vuln-json` | 阿里云云安全中心漏洞告警 | 阿里云 | 云安全中心 | `json-path` | `parsers/aliyun/samples.json#aliyun-sas-vuln-json` |
| `aliyun/aliyun-waf-sls-json.yaml` | `aliyun-waf-sls-json` | 阿里云 WAF 攻击日志（SLS JSON） | 阿里云 | Web应用防火墙 | `json-path` | `tests/fixtures/logs/parsers/aliyun-waf-sls-1.log` |
| `aws/aws-alb-access-log.yaml` | `aws-alb-access-log` | AWS ALB 访问日志 | AWS | Application Load Balancer | `grok` | `parsers/aws/samples.json#aws-alb-access-log` |
| `aws/aws-cloudtrail-json.yaml` | `aws-cloudtrail-json` | AWS CloudTrail 审计事件 | AWS | CloudTrail | `json-path` | `parsers/aws/samples.json#aws-cloudtrail-json` |
| `aws/aws-guardduty-json.yaml` | `aws-guardduty-json` | AWS GuardDuty 威胁发现 | AWS | GuardDuty | `json-path` | `parsers/aws/samples.json#aws-guardduty-json` |
| `aws/aws-s3-access-log.yaml` | `aws-s3-access-log` | AWS S3 访问日志 | AWS | S3 | `grok` | `parsers/aws/samples.json#aws-s3-access-log` |
| `aws/aws-vpc-flow-syslog.yaml` | `aws-vpc-flow-syslog` | AWS VPC Flow Logs | AWS | VPC Flow Logs | `grok` | `parsers/aws/samples.json#aws-vpc-flow-syslog` |
| `azure/azure-activity-json.yaml` | `azure-activity-json` | Azure 活动日志 | Microsoft Azure | Activity Log | `json-path` | `parsers/azure/samples.json#azure-activity-json` |
| `azure/azure-defender-alert-json.yaml` | `azure-defender-alert-json` | Azure Defender 安全告警 | Microsoft Azure | Microsoft Defender for Cloud | `json-path` | `parsers/azure/samples.json#azure-defender-alert-json` |
| `azure/azure-entra-signin-json.yaml` | `azure-entra-signin-json` | Entra ID 登录日志 | Microsoft Azure | Microsoft Entra ID | `json-path` | `parsers/azure/samples.json#azure-entra-signin-json` |
| `azure/azure-nsg-flow-json.yaml` | `azure-nsg-flow-json` | Azure NSG 流日志 | Microsoft Azure | Network Security Group Flow Logs | `json-path` | `parsers/azure/samples.json#azure-nsg-flow-json` |
| `crowdstrike/crowdstrike-falcon-detection-json.yaml` | `crowdstrike-falcon-detection-json` | Falcon 检测事件（DetectionSummary） | CrowdStrike | Falcon | `json-path` | `parsers/crowdstrike/samples.json#crowdstrike-falcon-detection-json` |
| `crowdstrike/crowdstrike-falcon-edr-telemetry-json.yaml` | `crowdstrike-falcon-edr-telemetry-json` | Falcon 端点遥测（ProcessRollup） | CrowdStrike | Falcon | `json-path` | `parsers/crowdstrike/samples.json#crowdstrike-falcon-edr-telemetry-json` |
| `crowdstrike/crowdstrike-falcon-logon-json.yaml` | `crowdstrike-falcon-logon-json` | Falcon 登录失败事件 | CrowdStrike | Falcon | `json-path` | `parsers/crowdstrike/samples.json#crowdstrike-falcon-logon-json` |
| `fortinet/fortinet-fortiedr-json.yaml` | `fortinet-fortiedr-json` | FortiEDR 终端检测事件 | Fortinet | FortiEDR | `json-path` | `parsers/fortinet/samples.json#fortinet-fortiedr-json` |
| `fortinet/fortinet-fortigate-dns-kv.yaml` | `fortinet-fortigate-dns-kv` | FortiGate DNS 过滤日志 | Fortinet | FortiGate | `kv` | `tests/fixtures/logs/parsers/fortinet-fortigate-dns-1.log` |
| `fortinet/fortinet-fortigate-traffic-kv.yaml` | `fortinet-fortigate-traffic-kv` | FortiGate 流量日志 | Fortinet | FortiGate | `kv` | `parsers/fortinet/samples.json#fortinet-fortigate-traffic-kv` |
| `fortinet/fortinet-fortigate-utm-cef.yaml` | `fortinet-fortigate-utm-cef` | FortiGate UTM 告警（CEF） | Fortinet | FortiGate | `cef` | `parsers/fortinet/samples.json#fortinet-fortigate-utm-cef` |
| `fortinet/fortinet-fortiweb-json.yaml` | `fortinet-fortiweb-json` | FortiWeb WAF 告警 | Fortinet | FortiWeb | `json-path` | `parsers/fortinet/samples.json#fortinet-fortiweb-json` |
| `gcp/gcp-cloud-audit-json.yaml` | `gcp-cloud-audit-json` | GCP Cloud Audit Log | Google Cloud | Cloud Audit Logs | `json-path` | `parsers/gcp/samples.json#gcp-cloud-audit-json` |
| `gcp/gcp-scc-finding-json.yaml` | `gcp-scc-finding-json` | GCP SCC 安全发现 | Google Cloud | Security Command Center | `json-path` | `parsers/gcp/samples.json#gcp-scc-finding-json` |
| `gcp/gcp-vpc-flow-json.yaml` | `gcp-vpc-flow-json` | GCP VPC Flow Logs | Google Cloud | VPC Flow Logs | `json-path` | `parsers/gcp/samples.json#gcp-vpc-flow-json` |
| `generic/cef-generic-syslog.yaml` | `cef-generic-syslog` | 通用 CEF | generic | CEF | `cef` | `parsers/generic/samples.json#cef-generic-syslog` |
| `generic/csv-generic-app.yaml` | `csv-generic-app` | 通用 CSV（自研应用） | generic | 自研应用 CSV | `csv` | `parsers/generic/samples.json#csv-generic-app` |
| `generic/gelf-generic-udp.yaml` | `gelf-generic-udp` | 通用 GELF | generic | GELF | `gelf` | `parsers/generic/samples.json#gelf-generic-udp` |
| `generic/jq-generic-normalize.yaml` | `jq-generic-normalize` | 通用 JQ 归一化 | generic | JQ 变换 | `jq` | `parsers/generic/samples.json#jq-generic-normalize` |
| `generic/kv-generic-app.yaml` | `kv-generic-app` | 通用 KV（自研应用） | generic | 自研应用 KV | `kv` | `parsers/generic/samples.json#kv-generic-app` |
| `generic/leef-generic-syslog.yaml` | `leef-generic-syslog` | 通用 LEEF | generic | LEEF | `leef` | `parsers/generic/samples.json#leef-generic-syslog` |
| `generic/syslog-rfc3164-generic.yaml` | `syslog-rfc3164-generic` | 通用 Syslog（RFC3164） | generic | syslog | `syslog` | `parsers/generic/samples.json#syslog-rfc3164-generic` |
| `generic/syslog-rfc5424-generic.yaml` | `syslog-rfc5424-generic` | 通用 Syslog（RFC5424） | generic | syslog | `syslog` | `parsers/generic/samples.json#syslog-rfc5424-generic` |
| `huawei/huawei-cfw-log-json.yaml` | `huawei-cfw-log-json` | 华为云 CFW 流量日志 | 华为云 | 云防火墙 CFW | `json-path` | `parsers/huawei/samples.json#huawei-cfw-log-json` |
| `huawei/huawei-cts-audit-json.yaml` | `huawei-cts-audit-json` | 华为云 CTS 云审计事件 | 华为云 | 云审计服务 CTS | `json-path` | `parsers/huawei/samples.json#huawei-cts-audit-json` |
| `huawei/huawei-hss-alert-json.yaml` | `huawei-hss-alert-json` | 华为云 HSS 异常进程告警 | 华为云 | 主机安全服务 | `json-path` | `tests/fixtures/logs/parsers/huawei-hss-alert-1.log` |
| `huawei/huawei-hss-filechange-json.yaml` | `huawei-hss-filechange-json` | 华为云 HSS 文件变更告警 | 华为云 | 主机安全服务 | `json-path` | `parsers/huawei/samples.json#huawei-hss-filechange-json` |
| `huawei/huawei-waf-access-json.yaml` | `huawei-waf-access-json` | 华为云 WAF 访问日志 | 华为云 | Web应用防火墙 | `json-path` | `parsers/huawei/samples.json#huawei-waf-access-json` |
| `huawei/huawei-waf-attack-json.yaml` | `huawei-waf-attack-json` | 华为云 WAF 攻击日志 | 华为云 | Web应用防火墙 | `json-path` | `parsers/huawei/samples.json#huawei-waf-attack-json` |
| `k8s/docker-container-json.yaml` | `docker-container-json` | Docker 容器日志 | Docker | Engine | `json-path` | `parsers/k8s/samples.json#docker-container-json` |
| `k8s/k8s-audit-jq.yaml` | `k8s-audit-jq` | Kubernetes 审计日志（JQ） | Kubernetes | API Server Audit | `jq` | `parsers/k8s/samples.json#k8s-audit-jq` |
| `k8s/k8s-audit-json.yaml` | `k8s-audit-json` | Kubernetes 审计日志 | Kubernetes | API Server Audit | `json-path` | `parsers/k8s/samples.json#k8s-audit-json` |
| `k8s/k8s-event-json.yaml` | `k8s-event-json` | Kubernetes 集群事件 | Kubernetes | Cluster Events | `json-path` | `parsers/k8s/samples.json#k8s-event-json` |
| `modsecurity/modsecurity-audit-json.yaml` | `modsecurity-audit-json` | ModSecurity JSON 审计日志 | ModSecurity | ModSecurity v3 | `json-path` | `parsers/modsecurity/samples.json#modsecurity-audit-json` |
| `modsecurity/modsecurity-error-regex.yaml` | `modsecurity-error-regex` | ModSecurity 错误日志规则命中 | ModSecurity | ModSecurity v3 | `regex` | `parsers/modsecurity/samples.json#modsecurity-error-regex` |
| `nsfocus/nsfocus-ids-kv.yaml` | `nsfocus-ids-kv` | 绿盟 IDS 告警（KV） | 绿盟 | IDS | `kv` | `parsers/nsfocus/samples.json#nsfocus-ids-kv` |
| `nsfocus/nsfocus-ips-leef.yaml` | `nsfocus-ips-leef` | 绿盟 IPS 告警（LEEF 2.0） | 绿盟 | IPS | `leef` | `parsers/nsfocus/samples.json#nsfocus-ips-leef` |
| `nsfocus/nsfocus-sas-json.yaml` | `nsfocus-sas-json` | 绿盟 SAS 安全审计 | 绿盟 | SAS | `json-path` | `parsers/nsfocus/samples.json#nsfocus-sas-json` |
| `nsfocus/nsfocus-waf-cef.yaml` | `nsfocus-waf-cef` | 绿盟 WAF 告警（CEF） | 绿盟 | WAF | `cef` | `tests/fixtures/logs/parsers/nsfocus-waf-cef-1.log` |
| `os/linux-auditd-syscall-regex.yaml` | `linux-auditd-syscall-regex` | Linux auditd SYSCALL 记录 | Linux | auditd | `regex` | `parsers/os/samples.json#linux-auditd-syscall-regex` |
| `os/linux-auditd-user-kv.yaml` | `linux-auditd-user-kv` | Linux auditd 用户登录审计 | Linux | auditd | `kv` | `parsers/os/samples.json#linux-auditd-user-kv` |
| `os/linux-sshd-auth-grok.yaml` | `linux-sshd-auth-grok` | Linux sshd 登录认证 | Linux | OpenSSH | `grok` | `tests/fixtures/logs/parsers/linux-sshd-auth-1.log` |
| `os/linux-sudo-syslog-grok.yaml` | `linux-sudo-syslog-grok` | Linux sudo 提权审计 | Linux | sudo | `grok` | `parsers/os/samples.json#linux-sudo-syslog-grok` |
| `os/windows-eventlog-json.yaml` | `windows-eventlog-json` | Windows 事件日志（JSON） | Microsoft Windows | Event Log | `json-path` | `parsers/os/samples.json#windows-eventlog-json` |
| `os/windows-eventlog-xml.yaml` | `windows-eventlog-xml` | Windows 事件日志（XML） | Microsoft Windows | Event Log | `regex` | `parsers/os/samples.json#windows-eventlog-xml` |
| `os/windows-sysmon-json.yaml` | `windows-sysmon-json` | Windows Sysmon 进程创建 | Microsoft Windows | Sysmon | `json-path` | `parsers/os/samples.json#windows-sysmon-json` |
| `paloalto/paloalto-cortex-xdr-json.yaml` | `paloalto-cortex-xdr-json` | Cortex XDR 端点告警 | Palo Alto | Cortex XDR | `json-path` | `parsers/paloalto/samples.json#paloalto-cortex-xdr-json` |
| `paloalto/paloalto-panos-json.yaml` | `paloalto-panos-json` | PAN-OS 系统日志（JSON） | Palo Alto | PAN-OS | `json-path` | `parsers/paloalto/samples.json#paloalto-panos-json` |
| `paloalto/paloalto-panos-threat-csv.yaml` | `paloalto-panos-threat-csv` | PAN-OS 威胁日志（CSV） | Palo Alto | PAN-OS | `csv` | `parsers/paloalto/samples.json#paloalto-panos-threat-csv` |
| `paloalto/paloalto-panos-traffic-csv.yaml` | `paloalto-panos-traffic-csv` | PAN-OS 流量日志（CSV） | Palo Alto | PAN-OS | `csv` | `parsers/paloalto/samples.json#paloalto-panos-traffic-csv` |
| `qianxin/qianxin-tianyan-cef.yaml` | `qianxin-tianyan-cef` | 奇安信天眼命令注入告警（CEF） | 奇安信 | 天眼 | `cef` | `tests/fixtures/logs/parsers/qianxin-tianyan-cef-1.log` |
| `qianxin/qianxin-tianyan-nta-json.yaml` | `qianxin-tianyan-nta-json` | 奇安信天眼 NTA 流量告警 | 奇安信 | 天眼 | `json-path` | `parsers/qianxin/samples.json#qianxin-tianyan-nta-json` |
| `qianxin/qianxin-tq-edr-json.yaml` | `qianxin-tq-edr-json` | 奇安信天擎病毒查杀 | 奇安信 | 天擎 | `json-path` | `parsers/qianxin/samples.json#qianxin-tq-edr-json` |
| `qianxin/qianxin-tq-edr-kv.yaml` | `qianxin-tq-edr-kv` | 奇安信天擎 syslog（KV） | 奇安信 | 天擎 | `kv` | `parsers/qianxin/samples.json#qianxin-tq-edr-kv` |
| `qianxin/qianxin-waf-cef.yaml` | `qianxin-waf-cef` | 奇安信网站卫士 WAF 告警（CEF） | 奇安信 | 网站卫士 WAF | `cef` | `parsers/qianxin/samples.json#qianxin-waf-cef` |
| `qingteng/qingteng-hive-process-json.yaml` | `qingteng-hive-process-json` | 青藤云蜂巢进程行为告警 | 青藤云 | 蜂巢 | `json-path` | `parsers/qingteng/samples.json#qingteng-hive-process-json` |
| `qingteng/qingteng-hive-webshell-syslog.yaml` | `qingteng-hive-webshell-syslog` | 青藤云蜂巢 WebShell 告警 | 青藤云 | 蜂巢 | `grok` | `parsers/qingteng/samples.json#qingteng-hive-webshell-syslog` |
| `qingteng/qingteng-rasp-java-json.yaml` | `qingteng-rasp-java-json` | 青藤云 RASP 应用攻击拦截 | 青藤云 | RASP | `json-path` | `parsers/qingteng/samples.json#qingteng-rasp-java-json` |
| `sangfor/sangfor-ac-kv.yaml` | `sangfor-ac-kv` | 深信服 AC 上网行为审计 | 深信服 | AC | `kv` | `parsers/sangfor/samples.json#sangfor-ac-kv` |
| `sangfor/sangfor-af-ips-cef.yaml` | `sangfor-af-ips-cef` | 深信服 AF IPS 告警（CEF） | 深信服 | AF | `cef` | `parsers/sangfor/samples.json#sangfor-af-ips-cef` |
| `sangfor/sangfor-af-ips-kv.yaml` | `sangfor-af-ips-kv` | 深信服 AF syslog（KV） | 深信服 | AF | `kv` | `parsers/sangfor/samples.json#sangfor-af-ips-kv` |
| `sangfor/sangfor-edr-json.yaml` | `sangfor-edr-json` | 深信服 EDR 终端告警 | 深信服 | EDR | `json-path` | `tests/fixtures/logs/parsers/sangfor-edr-1.log` |
| `sangfor/sangfor-sip-cef.yaml` | `sangfor-sip-cef` | 深信服 SIP 安全感知告警（CEF） | 深信服 | SIP | `cef` | `parsers/sangfor/samples.json#sangfor-sip-cef` |
| `snort/snort3-alert-json.yaml` | `snort3-alert-json` | Snort 3 JSON 告警 | Snort | Snort 3 | `json-path` | `parsers/snort/samples.json#snort3-alert-json` |
| `snort/snort-alert-syslog.yaml` | `snort-alert-syslog` | Snort 2.x 告警（syslog） | Snort | Snort 2 | `grok` | `parsers/snort/samples.json#snort-alert-syslog` |
| `suricata/suricata-eve-alert-json.yaml` | `suricata-eve-alert-json` | Suricata eve.json 告警 | Suricata | eve.json | `json-path` | `parsers/suricata/samples.json#suricata-eve-alert-json` |
| `suricata/suricata-eve-dns-json.yaml` | `suricata-eve-dns-json` | Suricata eve.json DNS | Suricata | eve.json | `json-path` | `tests/fixtures/logs/parsers/suricata-eve-dns-1.log` |
| `suricata/suricata-eve-flow-json.yaml` | `suricata-eve-flow-json` | Suricata eve.json 流记录 | Suricata | eve.json | `json-path` | `parsers/suricata/samples.json#suricata-eve-flow-json` |
| `suricata/suricata-eve-http-json.yaml` | `suricata-eve-http-json` | Suricata eve.json HTTP | Suricata | eve.json | `json-path` | `parsers/suricata/samples.json#suricata-eve-http-json` |
| `suricata/suricata-fast-alert-regex.yaml` | `suricata-fast-alert-regex` | Suricata fast.log 告警 | Suricata | fast.log | `regex` | `parsers/suricata/samples.json#suricata-fast-alert-regex` |
| `tencent/tencent-cdn-access-log.yaml` | `tencent-cdn-access-log` | 腾讯云 CDN 访问日志 | 腾讯云 | CDN | `grok` | `parsers/tencent/samples.json#tencent-cdn-access-log` |
| `tencent/tencent-cloudaudit-json.yaml` | `tencent-cloudaudit-json` | 腾讯云 CloudAudit 云审计 | 腾讯云 | 云审计 CloudAudit | `json-path` | `parsers/tencent/samples.json#tencent-cloudaudit-json` |
| `tencent/tencent-cls-log-json.yaml` | `tencent-cls-log-json` | 腾讯云 CLS 日志投递 | 腾讯云 | 日志服务 CLS | `json-path` | `parsers/tencent/samples.json#tencent-cls-log-json` |
| `tencent/tencent-cwp-alert-json.yaml` | `tencent-cwp-alert-json` | 腾讯云主机安全告警 | 腾讯云 | 主机安全 | `json-path` | `parsers/tencent/samples.json#tencent-cwp-alert-json` |
| `tencent/tencent-cwp-virus-json.yaml` | `tencent-cwp-virus-json` | 腾讯云主机安全病毒查杀 | 腾讯云 | 主机安全 | `json-path` | `parsers/tencent/samples.json#tencent-cwp-virus-json` |
| `tencent/tencent-waf-attack-json.yaml` | `tencent-waf-attack-json` | 腾讯云 WAF 攻击日志 | 腾讯云 | Web应用防火墙 | `json-path` | `tests/fixtures/logs/parsers/tencent-waf-attack-1.log` |
| `topsec/topsec-audit-syslog.yaml` | `topsec-audit-syslog` | 天融信日志审计登录事件 | 天融信 | 日志审计 | `grok` | `parsers/topsec/samples.json#topsec-audit-syslog` |
| `topsec/topsec-ngfw-kv.yaml` | `topsec-ngfw-kv` | 天融信 NGFW 会话日志 | 天融信 | NGFW | `kv` | `parsers/topsec/samples.json#topsec-ngfw-kv` |
| `topsec/topsec-topsap-leef.yaml` | `topsec-topsap-leef` | 天融信 TopSAP 审计（LEEF 1.0） | 天融信 | TopSAP | `leef` | `parsers/topsec/samples.json#topsec-topsap-leef` |
| `venustech/venustech-ids-cef.yaml` | `venustech-ids-cef` | 启明星辰 IDS 告警（CEF） | 启明星辰 | 天阗 IDS | `cef` | `parsers/venustech/samples.json#venustech-ids-cef` |
| `venustech/venustech-soc-leef.yaml` | `venustech-soc-leef` | 启明星辰 SOC 关联告警（LEEF 2.0） | 启明星辰 | SOC | `leef` | `parsers/venustech/samples.json#venustech-soc-leef` |
| `venustech/venustech-tianqing-edr-json.yaml` | `venustech-tianqing-edr-json` | 启明星辰终端 WebShell 处置 | 启明星辰 | 终端安全 EDR | `json-path` | `parsers/venustech/samples.json#venustech-tianqing-edr-json` |
| `venustech/venustech-waf-kv.yaml` | `venustech-waf-kv` | 启明星辰 WAF 告警（KV） | 启明星辰 | WAF | `kv` | `parsers/venustech/samples.json#venustech-waf-kv` |
| `wazuh/wazuh-alert-json.yaml` | `wazuh-alert-json` | Wazuh 告警（SSH 暴力破解） | Wazuh | Wazuh Manager | `json-path` | `parsers/wazuh/samples.json#wazuh-alert-json` |
| `wazuh/wazuh-auth-json.yaml` | `wazuh-auth-json` | Wazuh 认证事件 | Wazuh | Wazuh Manager | `json-path` | `parsers/wazuh/samples.json#wazuh-auth-json` |
| `wazuh/wazuh-fim-json.yaml` | `wazuh-fim-json` | Wazuh 文件完整性监控 | Wazuh | Wazuh Manager | `json-path` | `parsers/wazuh/samples.json#wazuh-fim-json` |
| `wazuh/wazuh-vulnerability-json.yaml` | `wazuh-vulnerability-json` | Wazuh 漏洞检测告警 | Wazuh | Wazuh Manager | `json-path` | `parsers/wazuh/samples.json#wazuh-vulnerability-json` |
| `webserver/apache-access-combined.yaml` | `apache-access-combined` | Apache 访问日志（combined） | Apache | HTTP Server | `grok` | `parsers/webserver/samples.json#apache-access-combined` |
| `webserver/apache-error-regex.yaml` | `apache-error-regex` | Apache 错误日志 | Apache | HTTP Server | `regex` | `parsers/webserver/samples.json#apache-error-regex` |
| `webserver/nginx-access-combined.yaml` | `nginx-access-combined` | Nginx 访问日志（combined） | Nginx | Nginx | `grok` | `parsers/webserver/samples.json#nginx-access-combined` |
| `webserver/nginx-error-regex.yaml` | `nginx-error-regex` | Nginx 错误日志 | Nginx | Nginx | `regex` | `parsers/webserver/samples.json#nginx-error-regex` |
| `webserver/nginx-json-access.yaml` | `nginx-json-access` | Nginx JSON 访问日志 | Nginx | Nginx | `json-path` | `parsers/webserver/samples.json#nginx-json-access` |
| `zeek/zeek-conn-tsv.yaml` | `zeek-conn-tsv` | Zeek conn.log 连接日志 | Zeek | conn.log | `csv` | `parsers/zeek/samples.json#zeek-conn-tsv` |
| `zeek/zeek-dns-tsv.yaml` | `zeek-dns-tsv` | Zeek dns.log 查询日志 | Zeek | dns.log | `csv` | `parsers/zeek/samples.json#zeek-dns-tsv` |
| `zeek/zeek-http-tsv.yaml` | `zeek-http-tsv` | Zeek http.log 请求日志 | Zeek | http.log | `csv` | `parsers/zeek/samples.json#zeek-http-tsv` |
| `zeek/zeek-notice-tsv.yaml` | `zeek-notice-tsv` | Zeek notice.log 告警 | Zeek | notice.log | `csv` | `parsers/zeek/samples.json#zeek-notice-tsv` |
| `zeek/zeek-ssl-tsv.yaml` | `zeek-ssl-tsv` | Zeek ssl.log TLS 握手 | Zeek | ssl.log | `csv` | `parsers/zeek/samples.json#zeek-ssl-tsv` |
| `azure/azure-entra-service-principal-json.yaml` | `azure-entra-service-principal-json` | Entra ID 服务主体登录日志 | Microsoft Azure | Microsoft Entra ID | `json-path` | `tests/fixtures/logs/public/azure-entra-service-principal-json.log` |
| `crowdstrike/crowdstrike-falcon-fdr-process-json.yaml` | `crowdstrike-falcon-fdr-process-json` | Falcon FDR 进程事件 | CrowdStrike | Falcon Data Replicator | `json-path` | `tests/fixtures/logs/public/crowdstrike-falcon-fdr-process-json.log` |
| `zeek/zeek-conn-json.yaml` | `zeek-conn-json` | Zeek conn.log JSON 连接日志 | Zeek | conn.log | `json-path` | `tests/fixtures/logs/public/zeek-conn-json.log` |
<!-- TEMPLATES:END -->

> 上表由脚本从各 YAML 的 `key`/`name`/`vendor`/`product`/`engine`/`sample_fixture` 汇总生成；
> 每个模板至少有一条**正样本**，样本原文与关键字段断言登记在同厂商的 `samples.json` 中，
> 有独立样本文件的模板另在 `tests/fixtures/logs/parsers/` 落盘并登记 `manifest.json` / `SOURCES.md`。

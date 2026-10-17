# 接入模板样本来源（SOURCES.md）

本目录存放 `agf-ingest` 内置解析模板的样本日志，每个模板一个文件，由
`crates/agf-ingest/src/template.rs` 的 `sample_fixture` 与 `manifest.json` 双向引用。

## 真伪标注规则

- `real`：样本**逐字取自公开来源**（URL 已在本会话中实际抓取成功，HTTP 200），仅做空白归一（JSON 压成单行以便"一行一日志"）。
- `synthetic=true`：样本为**合成**，格式忠于厂商公开文档/社区常见形态（字段名、分隔符、时间戳形态、枚举取值），但取值与主机名/IP 为编写的示例数据（RFC 5737 文档地址段与本机私网段）。
- 本文件**只登记实际抓取成功的 URL**；未能核实的一律标 `synthetic=true` 且不写 URL（避免伪造来源）。

## 样本清单

| 文件 | 厂商 | 产品 | 协议 | 真伪 | 来源 URL | 抓取日期 |
|---|---|---|---|---|---|---|
| `suricata-eve-1.log` | Suricata | eve.json | file | **real**（逐字取自文档示例，`event_type=alert` 段） | https://suricatacn.readthedocs.io/zh-cn/latest/output/eve/eve-json-format.html | 2026-09-17 |
| `zeek-conn-1.log` | Zeek | conn.log | file | `synthetic=true`（TSV 头部 `#separator \x09` / `#fields …` 与 `ts uid id.orig_h …` 字段集经文档核实；数据行合成为 TSV 形态） | https://raw.githubusercontent.com/zeek/zeek-docs/278f7b7d0cda1aab5789122d808f411cd05a20fc/logs/conn.rst | 2026-09-17 |
| `qingteng-hive-1.log` | 青藤云 | 蜂巢（Hive） | syslog + KV | `synthetic=true` | — | — |
| `aliyun-waf-1.log` | 阿里云 | Web应用防火墙 3.0 | webhook(JSON) | `synthetic=true` | — | — |
| `aliyun-sas-1.log` | 阿里云 | 云安全中心 | webhook(JSON) | `synthetic=true` | — | — |
| `huawei-waf-1.log` | 华为云 | Web应用防火墙 | webhook(JSON) | `synthetic=true` | — | — |
| `huawei-hss-1.log` | 华为云 | 主机安全服务 HSS | webhook(JSON) | `synthetic=true` | — | — |
| `tencent-cfw-1.log` | 腾讯云 | 云防火墙 | webhook(JSON) | `synthetic=true` | — | — |
| `sangfor-af-1.log` | 深信服 | AF 下一代防火墙 | syslog + CEF | `synthetic=true` | — | — |
| `qianxin-tianyan-1.log` | 奇安信 | 天眼 | syslog + CEF | `synthetic=true` | — | — |
| `nsfocus-ips-1.log` | 绿盟 | IPS | syslog + LEEF 2.0 | `synthetic=true` | — | — |
| `topsec-topsap-1.log` | 天融信 | TopSAP | syslog + LEEF 1.0（制表符） | `synthetic=true` | — | — |
| `fortinet-fortigate-1.log` | Fortinet | FortiGate | syslog + KV | `synthetic=true` | — | — |
| `paloalto-panos-1.log` | Palo Alto | PAN-OS | syslog + CSV | `synthetic=true` | — | — |
| `crowdstrike-falcon-1.log` | CrowdStrike | Falcon | webhook(JSON) | `synthetic=true` | — | — |
| `wazuh-alert-1.log` | Wazuh | Wazuh Manager | file(JSON) | `synthetic=true` | — | — |
| `linux-auditd-execve-1.log` | Linux | auditd | syslog + audit 记录 | `synthetic=true` | — | — |
| `syslog-rfc3164-1.log` | generic | syslog | syslog RFC3164 | `synthetic=true` | — | — |
| `otlp-json-1.log` | OpenTelemetry | OTLP Logs | otlp(JSON) | `synthetic=true`（形状 = OTLP 规范字段 + 本仓库 OTLP 接收器 `otlp::OtlpLogRecord::to_payload` 输出的归一化载荷，取值同 `tools/simulators/otlp_logs.py`） | https://opentelemetry.io/docs/specs/otlp/ | 2026-09-17 |

## `parsers/` 模板库样本（manifest.json → `parser_library` 段）

`parsers/` 目录模板库的样本分两层登记：

1. **行内正样本 + 关键字段断言**：`parsers/<vendor>/samples.json`（每个模板一条，测试逐条跑真实解析）；
2. **独立样本文件**（下表）：同时登记进 `manifest.json` 的 `parser_library` 段与本节。

| 文件（`parsers/` 子目录） | 模板 key | 厂商 | 产品 | 协议 | 格式来源 | 获取方式 |
|---|---|---|---|---|---|---|
| `parsers/aliyun-waf-sls-1.log` | `aliyun-waf-sls-json` | 阿里云 | Web应用防火墙 | webhook(JSON) | 阿里云 WAF 3.0 日志字段公开文档（time/host/real_client_ip/request_method/request_uri/http_user_agent/waf_action/attack_type/rule_id/rule_name/status/region/trace_id） | 按公开格式**重建**，未联网抓取（取值与 IP 为示例数据） |
| `parsers/aliyun-actiontrail-1.log` | `aliyun-actiontrail-json` | 阿里云 | ActionTrail | object-storage(JSON) | 阿里云 ActionTrail 事件结构公开文档（eventId/eventTime/eventName/eventSource/eventType/userIdentity/sourceIpAddress/requestId） | 按公开格式**重建**，未联网抓取（取值与 IP 为示例数据） |
| `parsers/huawei-hss-alert-1.log` | `huawei-hss-alert-json` | 华为云 | 主机安全服务 HSS | webhook(JSON) | 华为云 HSS 告警推送公开字段（occur_time/event_type/host_name/process_name/cmd_line/severity/action） | 按公开格式**重建**，未联网抓取 |
| `parsers/tencent-waf-attack-1.log` | `tencent-waf-attack-json` | 腾讯云 | Web应用防火墙 | webhook(JSON) | 腾讯云 WAF 攻击日志公开字段（time/domain/src_ip/method/url/attack_type/action/rule_id/user_agent） | 按公开格式**重建**，未联网抓取 |
| `parsers/sangfor-edr-1.log` | `sangfor-edr-json` | 深信服 | EDR | webhook(JSON) | 深信服 EDR 终端告警公开字段（event_type/hostname/process_name/cmd_line/file_path/md5/severity/action） | 按公开格式**重建**，未联网抓取 |
| `parsers/qianxin-tianyan-cef-1.log` | `qianxin-tianyan-cef` | 奇安信 | 天眼 | syslog + CEF | CEF 公开规范（`CEF:0\|厂商\|产品\|版本\|规则ID\|名称\|等级\|扩展`）+ 天眼扩展键（request/cs1） | 按公开格式**重建**，未联网抓取 |
| `parsers/nsfocus-waf-cef-1.log` | `nsfocus-waf-cef` | 绿盟 | WAF | syslog + CEF | CEF 公开规范 + 绿盟 WAF 扩展键（cat=WebAttack/act=block/cs1） | 按公开格式**重建**，未联网抓取 |
| `parsers/fortinet-fortigate-dns-1.log` | `fortinet-fortigate-dns-kv` | Fortinet | FortiGate | syslog + KV | FortiGate UTM DNS 日志公开字段（devname/logid/type/subtype/level/srcip/qname/catdesc/action） | 按公开格式**重建**，未联网抓取 |
| `parsers/suricata-eve-dns-1.log` | `suricata-eve-dns-json` | Suricata | eve.json | file(JSON Lines) | eve.json DNS 事件公开字段（timestamp/event_type/src_ip/dns.rrname/rrtype/rcode） | 按公开格式**重建**，未联网抓取 |
| `parsers/linux-sshd-auth-1.log` | `linux-sshd-auth-grok` | Linux | OpenSSH | syslog RFC3164 | OpenSSH `Failed password for …` 公开日志格式（syslog 信封 + TAG[PID]） | 按公开格式**重建**，未联网抓取 |

> 纪律：本节所有样本 `synthetic=true`。格式取自厂商公开文档（字段名、分隔符、时间戳形态、枚举取值），
> **取值不编造产品不存在的字段**；未能核实公开原文的结构不写入本表。上线前须用客户真实日志替换并改 `synthetic=false`。

## 抓取尝试记录（含失败）

| URL | 结果 |
|---|---|
| https://suricatacn.readthedocs.io/zh-cn/latest/output/eve/eve-json-format.html | HTTP 200，已用于 `suricata-eve-1.log` |
| https://raw.githubusercontent.com/zeek/zeek-docs/278f7b7d0cda1aab5789122d808f411cd05a20fc/logs/conn.rst | HTTP 200，用于核实 Zeek conn.log 字段集与时间戳语义 |
| https://docs.zeek.org/en/v7.2.1/logs/conn.html | HTTP 429（限流），未使用 |
| https://raw.githubusercontent.com/OISF/suricata/refs/tags/suricata-6.0.5/doc/userguide/output/eve/eve-json-format.rst | 抓取失败（连接错误），未使用 |

## 关于"合成样本"的说明

其余 15 个厂商样本无法在离线/受限网络环境内核实公开原文，因此一律按 `synthetic=true` 登记。
合成为**格式合成**而非凭空编造：字段名、分隔符（KV `key=value`、CEF `|`、LEEF 制表符/`^`、
PAN-OS CSV 列序）、严重等级枚举（CEF/LEEF `sev` 0-10、FortiGate `severity`、
Wazuh `rule.level` 0-15、Suricata `alert.severity` 1-4）均按各厂商公开文档的语义取值。
接入侧上线前须用**客户真实日志**替换这些样本，并把 `manifest.json` 的 `synthetic` 改为 `false`。

## 固定版本的公开原文捕获（public/）

以下样本来自 Splunk Apache-2.0 公开实验捕获；并非客户生产日志。原行不改写，完整来源文件与摘录哈希登记在 `public/manifest.json`，许可证见 `public/LICENSE.splunk-attack-data`。旧合成样本及其标注保持不变。

| 文件 | 模板 | 实际厂商 | 固定版本原始来源 |
|---|---|---|---|
| `public/aws-cloudtrail-json.log` | `aws-cloudtrail-json` | AWS | [原始日志](https://media.githubusercontent.com/media/splunk/attack_data/a92cc4e6d7e39d56a0840d206a0963eeee0e22db/datasets/attack_techniques/T1078.004/aws_login_sfa/cloudtrail.json) |
| `public/azure-entra-service-principal-json.log` | `azure-entra-service-principal-json` | Microsoft Azure | [原始日志](https://media.githubusercontent.com/media/splunk/attack_data/a92cc4e6d7e39d56a0840d206a0963eeee0e22db/datasets/attack_techniques/T1078.004/azure_ad_service_principal_authentication/azure_ad_service_principal_authentication.log) |
| `public/crowdstrike-falcon-fdr-process-json.log` | `crowdstrike-falcon-fdr-process-json` | CrowdStrike | [原始日志](https://media.githubusercontent.com/media/splunk/attack_data/a92cc4e6d7e39d56a0840d206a0963eeee0e22db/datasets/attack_techniques/T1003.003/atomic_red_team/crowdstrike_falcon.log) |
| `public/paloalto-panos-threat-csv.log` | `paloalto-panos-threat-csv` | Palo Alto | [原始日志](https://media.githubusercontent.com/media/splunk/attack_data/a92cc4e6d7e39d56a0840d206a0963eeee0e22db/datasets/attack_techniques/T1190/fortigate/fortinetcve202240684.log) |
| `public/zeek-conn-json.log` | `zeek-conn-json` | Zeek | [原始日志](https://media.githubusercontent.com/media/splunk/attack_data/a92cc4e6d7e39d56a0840d206a0963eeee0e22db/datasets/attack_techniques/T1021.001/remote_desktop_connection/zeek_conn.log) |

### 从控制台接入与回放

1. 在测试租户新建日志来源并选择对应生产模板；按已部署的接收器填写对象存储、Syslog 或 HTTP Pull 等配置。样本文件本身不需要厂商凭据；接收器仍需要其正常连接配置。
2. 按接收器部署指南投递对应 `public/*.log` 文件的原始字节，保留原始行尾与空白。不要给 JSON 增加二次包装，也不要把 Zeek JSON 转成 TSV；此处不提供控制台文件上传功能。
3. 事件详情可核对生产解析器名称、来源/目标、用户或进程。GET 回放接口只预览该来源尚未解析的原文，POST 才执行回放并将成功项标记为已解析；已经解析的日志返回 `replayed=0`，不会重复生成事件。
4. 存储与回放层的原文字节保真以 RawLog 的 base64/字节数/载荷 SHA-256 及 GET/POST 返回文本验证；本组夹具的哈希包含原始行尾。归一化的 `Event.raw` 对 JSON 保存结构，对其他日志保存字符串，`Event.raw_hash` 按保存的完整原文计算。不同接收器可先按协议分帧；现有 HTTP 接入的 `source_ingest::records` 还会 trim 文本、拆分数组或行，因此本组路由回归不能推导为所有接收器入口均保留文件行尾。
5. 自动化校验：`cargo test --locked -p agf-ingest --test public_log_samples --test parsers_library --test parsers_library_manifest`；真实路由回放：`cargo test --locked -p agf-api --test public_log_replay`。后者在内存仓储放入五条尚未解析原文，创建绑定生产模板的禁用来源，验证 GET 无写入、POST 实际事件字段、再次 POST 不重复和跨租户隔离；不启动接收器、不连接外网。

`fortinetcve202240684.log` 的目录记录攻击对象，原始发日志设备是 PAN-OS；因此这里正确登记为 Palo Alto，不能把目录名当作厂商。

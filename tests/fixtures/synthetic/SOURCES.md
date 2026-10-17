# 合成测试样本来源说明（tests/fixtures/synthetic/SOURCES.md）

> 本目录**全部为合成样本**（`synthetic=true`），由 `scripts/gen-fixtures.ps1` 生成，固定随机种子，
> 重复运行逐字节一致（幂等）。

## 与 tests/fixtures/logs/ 的区别

| 目录 | 内容 | 管理脚本 |
|---|---|---|
| `tests/fixtures/logs/` | 接入模板样本；含 `real`（逐字取自公开来源）与 `synthetic=true` 两类，来源与抓取日期登记在该目录的 `SOURCES.md` | `scripts/fetch-fixtures.ps1` |
| `tests/fixtures/synthetic/`（本目录） | **纯合成**样本，用于离线开发、门禁与 CI，绝不冒充真实样本 | `scripts/gen-fixtures.ps1` |

## 合成依据（格式忠于公开语义，取值是示例）

| 文件 | 形态 | 合成依据 |
|---|---|---|
| `suricata-eve-synthetic-1.log` | NDJSON，`event_type=alert` | Suricata eve.json 公开文档事件字段集：`timestamp/flow_id/event_type/src_ip/src_port/dest_ip/dest_port/proto/alert{action,gid,signature_id,rev,signature,category,severity}`；`alert.severity` 取值 1-4 |
| `cloud-waf-webhook-synthetic-1.log` | 单行 JSON | 云 WAF 告警 webhook 常见字段：`alertName/alertType/level/uuid/instanceName/internetIp/intranetIp/occurrenceTime/detail/region`；`level` 取 serious 等枚举 |
| `cef-ips-synthetic-1.log` | syslog(RFC3164) + CEF:0 | CEF 公开格式 `CEF:0\|Vendor\|Product\|Version\|SignatureID\|Name\|Severity\|Extension`；`sev` 0-10 |
| `auditd-execve-synthetic-1.log` | syslog(RFC3164) + audit | Linux auditd 记录形态 `type=EXECVE msg=audit(<epoch>.<ms>:<seq>): argc=N a0="..." uid=... comm=... exe=... addr=...` |

## 取值约定（避免与现实混淆）

* IP 一律使用**文档地址段**：`203.0.113.0/24`、`198.51.100.0/24`（RFC 5737）与私网段
  `10.20.30.0/24`（RFC 1918）——不对应任何真实资产。
* 时间戳固定故事日 `2026-02-21`，与 `tests/fixtures/logs/` 既有样本同日，便于跨目录对账。
* 每个文件都带 `synthetic=true` 标注（JSON 字段、日志尾部 `synthetic=true`），
  不会与真实样本混淆。

## 替换为真实样本

接入侧上线前必须用**客户真实日志**替换本目录样本，并把上层 `manifest.json` 的
`synthetic` 改为 `false`；采集真实样本请用 `scripts/fetch-fixtures.ps1 -Execute`
抓取公开样本，或由客户提供脱敏日志。
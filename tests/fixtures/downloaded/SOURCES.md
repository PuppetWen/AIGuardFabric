# 公开样本来源登记（tests/fixtures/downloaded/SOURCES.md）

> 本目录文件由 `scripts/fetch-fixtures.ps1 -Execute` 从**公开来源**抓取，逐字保存（不改写内容）。
> 本文件与 `manifest.json` 由脚本自动维护：**只登记实际抓取成功的 URL**，失败项不写来源。

最后抓取时间：2026-09-17 18:36:11 +08:00（本机时间）

## 来源清单

| 来源名 | 厂商 | URL | 本地文件 | HTTP | 字节 | sha256(前 16) | 抓取日期 | 用途 |
|---|---|---|---|---|---|---|---|---|
| `suricata-eve-json` | Suricata / OISF | https://raw.githubusercontent.com/OISF/suricata/master/doc/userguide/output/eve/eve-json-format.rst | `tests\fixtures\downloaded\suricata\eve-json-format.rst` | 200 | 98478 | `9d7e5c0e560c922d` | 2026-09-17 | Suricata eve.json 事件字段集与枚举原文（校验 agf-ingest 解析模板） |
| `zeek-conn-log` | Zeek | https://raw.githubusercontent.com/zeek/zeek-docs/master/logs/conn.rst | `tests\fixtures\downloaded\zeek\conn-log.rst` | 200 | 17159 | `668d92b3a4639313` | 2026-09-17 | Zeek conn.log 字段集与 TSV 头格式原文 |
| `fluentbit-parsers` | Fluent Bit | https://raw.githubusercontent.com/fluent/fluent-bit/master/conf/parsers.conf | `tests\fixtures\downloaded\fluentbit\parsers.conf` | 200 | 6487 | `760e6a347874a6cb` | 2026-09-17 | Fluent Bit 官方解析器定义（regex/JSON 解析器的真实配置形态） |
| `prometheus-scrape-config` | Prometheus | https://raw.githubusercontent.com/prometheus/prometheus/main/documentation/examples/prometheus.yml | `tests\fixtures\downloaded\prometheus\prometheus.yml` | 200 | 1128 | `aafcee2a237ad599` | 2026-09-17 | Prometheus 官方抓取配置样例（指标门禁与自监控接入参考） |
| `minio-config-doc` | MinIO | https://raw.githubusercontent.com/minio/minio/master/docs/config/README.md | `tests\fixtures\downloaded\minio\config-README.md` | 200 | 18584 | `08c5b1a7af3db546` | 2026-09-17 | MinIO 配置项原文（证据包对象存储接入参考） |
| `timescaledb-readme` | TimescaleDB | https://raw.githubusercontent.com/timescale/timescaledb/main/README.md | `tests\fixtures\downloaded\timescaledb\README.md` | 200 | 19720 | `e1b995d3ad7a4728` | 2026-09-17 | TimescaleDB 能力与版本说明（时序事件表设计参考） |
| `nats-server-readme` | NATS | https://raw.githubusercontent.com/nats-io/nats-server/main/README.md | `tests\fixtures\downloaded\nats\README.md` | 200 | 4576 | `af1a7d8d9cc9314a` | 2026-09-17 | NATS JetStream 说明（事件总线接入参考） |

## 使用与替换说明

* 这些文件是**上游公开原文**（多为文档 / 配置样例），用于校验解析模板的字段集与格式；
  它们不是客户日志。解析器上线前必须用**客户真实日志**或者本仓库
  `tests/fixtures/logs/`（含 real/synthetic 标注）与 `tests/fixtures/synthetic/`（纯合成）替换。
* 上游文件可能随时变更：`sha256` 与抓取日期用于判断本地副本是否过期，
  重新执行 `fetch-fixtures.ps1 -Execute` 即可刷新（内容一致则不改写）。
* 任何来源抓取失败时脚本会明确报错并非零退出，**不会**用合成内容冒充真实来源。

# 总览指标 / Overview metrics

打开总览前确认顶部组织。资产、告警、发现、模型、红队和云集成分别按账号权限读取；有资产读取权限不代表能查看全部统计。无权读取的数据不会以零值返回，也不会写入风险趋势。快捷入口按实际权限显示。

| 指标 | 口径 |
|---|---|
| AI 资产总数 | 当前组织未删除资产 |
| 未处置告警 | 当前仍活跃的告警 |
| 严重发现 | 未修复、非误报的严重发现 |
| 红队成功率 | 明确为真实执行且已完成的战役中，成功用例占已执行用例的比例；排除模拟和模式未知历史，无真实执行时未知 |
| 累计模型估算费用 | 已保留的真实调用记录，按端点价格计量，微元换算成人民币；排除 Mock |
| 资产未处置发现 | 包含待处理、代码已审查和已验证，排除已修复及误报 |

“未知”表示没有观测或没有权限；实际零值保留 0。估算费用不等于供应商账单，也不是日费用，不叠加不同范围的配额用量。没有可比的历史窗口时不展示昨日变化率。云适配器没有历史探活样本时，可用率为未知；需要主动检查时打开云环境自检。

风险趋势每小时保留最近一次观测的未关闭高危/严重发现数量，最多 168 个点，没有观测时不补零。默认每 5 分钟写入本实例数据目录下 `state/risk-history.json`，保存周期由 `AGF_RISK_HISTORY_SAVE_SECS` 控制。多副本各自采样，不共享或合并曲线；长期指标使用 Prometheus/Grafana。

旧版风险历史混入过启动零值，无法可靠区分实际零值。升级先在原文件旁完整保存 `.pre-v2-<SHA256>.json`，再开始真实采样；不推算旧值。归档内容逐字节核对，绝不覆盖已有归档。归档、读取或格式检查失败时服务继续运行，但当前进程停用自动写盘以保护原文件，运维修复后重启恢复。归档是保留的数据，不属于清理用的临时文件。

总览资产名称可直达详情，最近告警可直达对应告警；刷新和分享链接保留对象定位。API 为 `GET /api/v1/overview`，`access` 表示可读类别，`generated_at` 为服务端采样时间，空指标为 JSON null。

## English

Select the organization before opening Overview. Assets, alerts, findings, models, red-team results and cloud integration each require their own read permission. Asset access alone does not grant access to all metrics. Unauthorized data is not returned as zero or recorded into risk history; quick actions follow your permissions.

Unknown means no observation or no permission. Measured zero stays zero. Model cost estimates sum retained non-Mock usage using endpoint pricing in CNY; they are neither daily costs nor provider invoices. Different quota scopes are not added together. Red-team success rate includes only completed, explicitly live campaigns. Simulated and unknown historical runs are excluded; without live runs it is unknown. Daily comparisons and adapter uptime are unknown without sufficient observations.

Risk history keeps the latest hourly observation of open high/critical findings, up to 168 points. Missing observations do not become zero. The instance saves to `state/risk-history.json` every 5 minutes by default (`AGF_RISK_HISTORY_SAVE_SECS`). Instances do not merge histories; use Prometheus/Grafana for long-term and multi-instance monitoring.

Legacy histories may contain fabricated startup zeros. Their original bytes are archived next to the source with a `.pre-v2-<SHA256>.json` suffix before observation restarts. Archives are retained data, never cleanup targets. If archiving, reading or format validation fails, the service continues with in-memory observations and disables automatic writes for that process to protect the source. Repair the file/permissions and restart to restore persistence.

Asset and alert links open exact records. `GET /api/v1/overview` returns resource access flags, server observation time and null for unavailable metrics.

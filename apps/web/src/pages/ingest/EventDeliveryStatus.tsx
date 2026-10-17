import { Alert, Space } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { AnalysisRecovery } from './AnalysisRecovery';
import { BrokerQuarantine } from './BrokerQuarantine';

interface DeliveryStatus {
  storage: 'memory' | 'sql'; workerEnabled: boolean;
  canInspectBroker?: boolean;
  broker?: {quarantined: number; retrying: number};
  pending: number | null; failed: number | null;
  analysis?: { pending: number; retrying: number; quarantined?: number; paused?: number; processed: number; lastProcessedAt: string | null };
}

export function EventDeliveryStatus() {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const query = useApiQuery('event-delivery', () => callApi<DeliveryStatus>(
    '/api/v1/sources/delivery', () => { throw new Error('Event delivery status is unavailable'); }, { noFallback: true },
  ), { refetchInterval: 15_000 });
  if (query.error) return <Alert type="error" showIcon message={zh ? '无法读取事件投递队列' : 'Unable to read the event delivery queue'} />;
  const status = query.data?.data;
  if (!status) return null;
  if (status.storage === 'memory') return <Alert type="warning" showIcon
    message={zh ? '当前为内存演示模式，重启后不会保留接入事件' : 'Memory demonstration: ingested events do not survive a restart'} />;
  const warning = (status.failed ?? 0) > 0;
  return <Space direction="vertical" style={{ width: '100%' }}><Alert type={warning ? 'warning' : 'info'} showIcon
    message={zh ? `事件投递：待确认 ${status.pending ?? 0} 条，等待重试 ${status.failed ?? 0} 条`
      : `Event delivery: ${status.pending ?? 0} pending, ${status.failed ?? 0} awaiting retry`}
    description={zh
      ? (status.workerEnabled ? '事件已与原文一同保存；收到消息服务的存储确认后清除待投递状态。队列为空不表示网络已验证。持续积压时请按原生接入指南检查 NATS、流容量和投递日志。'
        : '当前管理服务未启用消息总线，数据库中的事件仍会自动分析。已有投递队列保留至消息服务恢复。')
      : (status.workerEnabled ? 'Events are stored with raw evidence. Pending status clears after broker storage confirmation. An empty queue does not verify connectivity. See the native ingest guide for persistent backlog.'
        : 'Broker delivery is disabled. Committed SQL events are still analyzed automatically; existing delivery jobs are retained.')} />
    {status.analysis && <Alert showIcon type={status.analysis.retrying + (status.analysis.quarantined ?? 0) + (status.analysis.paused ?? 0) > 0 ? 'warning' : 'info'}
      message={zh ? `事件分析：已处理 ${status.analysis.processed} 条，待处理 ${status.analysis.pending} 条，重试 ${status.analysis.retrying} 条`
        : `Event analysis: ${status.analysis.processed} processed, ${status.analysis.pending} pending, ${status.analysis.retrying} retrying`}
      description={zh ? '命中已发布规则后自动生成风险发现和告警。可在风险发现中查看证据，在告警中心处理，在系统设置中启用通知渠道。'
        : 'Published rule matches create findings and alerts automatically. Review evidence in Findings, handle Alerts, and enable notification channels in Settings.'} />}
    {status.analysis && <><span>{zh ? `隔离 ${status.analysis.quarantined ?? 0} 条，暂停 ${status.analysis.paused ?? 0} 条`
      : `${status.analysis.quarantined ?? 0} quarantined, ${status.analysis.paused ?? 0} paused`}</span><AnalysisRecovery /></>}
    {status.canInspectBroker && <BrokerQuarantine summary={status.broker} />}
  </Space>;
}

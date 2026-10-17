import { Alert, Descriptions, Table, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { SettlementReceipt as Receipt } from '@/api/gatewaySettlement';

export function SettlementReceipt({ value }: { value: Receipt }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const states = { reserved: text('已预留，执行结果未知', 'Reserved, execution outcome unknown'),
    'pending-audit': text('已知结果待提交审计', 'Known outcome awaiting audit'),
    'conservatively-settled': text('已保守结算，结果未证明', 'Conservatively settled, outcome unproven'),
    settled: text('本地结算已提交', 'Local settlement committed') };
  const evidence = (kind: Receipt['outcomeEvidence']) => kind === 'sent-usage-partial'
    ? text('仅有部分用量，最终用量未知', 'Partial usage observed; final usage unknown') : kind ?? text('未知', 'Unknown');
  const partial = value.outcomeEvidence === 'sent-usage-partial'
    || value.components?.some(component => component.evidence === 'sent-usage-partial');
  return <>
    <Descriptions size="small" bordered column={2} items={[
      { key: 'id', label: text('原请求编号', 'Original attempt ID'), children: <Typography.Text copyable>{value.attemptId}</Typography.Text> },
      { key: 'state', label: text('结算状态', 'Settlement state'), children: states[value.state] },
      { key: 'created', label: text('原提交时间', 'Original submitted time'), children: value.originalSubmittedAt },
      { key: 'deadline', label: text('原执行期限', 'Original execution deadline'), children: value.originalExecuteBefore },
      { key: 'charge', label: text('计费证据', 'Charge evidence'), children: value.chargeState ?? text('未知', 'Unknown') },
      { key: 'evidence', label: text('用量证据', 'Usage evidence'), children: evidence(value.outcomeEvidence) },
      { key: 'audit', label: text('终态审计编号', 'Terminal audit ID'), children: value.auditId ?? text('尚未提交', 'Not committed') },
    ]} />
    {partial && <Alert type="warning" showIcon message={text(
      '流中断或取消时，部分用量不能证明调用成功。已知费用只是下限，结算可能保留更高的预留估算；恢复不会再次调用模型。',
      'After interruption or cancellation, partial usage does not prove success. Known costs are lower bounds; settlement may retain a higher reservation estimate. Recovery does not call a model again.')} />}
    {value.components && <Table size="small" pagination={false} rowKey="usageId" dataSource={value.components} columns={[
      { title: text('组件用量编号', 'Component usage ID'), dataIndex: 'usageId' },
      { title: text('发送与用量证据', 'Dispatch and usage evidence'), dataIndex: 'evidence', render: evidence },
      { title: text('已知费用（CNY）', 'Known cost (CNY)'), dataIndex: 'costMicro', render: (value: number | null, component: NonNullable<Receipt['components']>[number]) => value === null
        ? component.evidence === 'not-sent' ? text('未发送，无新增费用', 'Not sent, no new charge')
          : text('费用未知，请核对结算计费状态', 'Cost unknown; check the settlement charge state')
        : (value / 1_000_000).toFixed(6) },
    ]} />}
  </>;
}

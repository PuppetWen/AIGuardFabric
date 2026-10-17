import { Alert, Space } from 'antd';
import { useTranslation } from 'react-i18next';
import type { ModelMeterProjectionStatus } from '@/api/modelMeterProjection';

interface Props { status?: ModelMeterProjectionStatus; loading: boolean; failed: boolean }
export function MeterProjectionNotice({ status, loading, failed }: Props) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('计量记录数按组件计数', 'Metering records count components')}
      description={text('一次模型请求可分别产生 chat 与 embedding 两条费用记录；记录数不是模型 HTTP 请求次数。下方费用图汇总当前组织保留的真实记录，可能不含未知用量的保守账本费用，也不是厂商账单。',
        'One model request can produce separate chat and embedding charges. The record count is not the number of model HTTP requests. Charts total retained real records for this tenant; they may omit conservative ledger charges for unknown usage and are not provider invoices.')} />
    {(failed || (!loading && !status)) && <Alert type="warning" showIcon
      message={text('累计投影范围未知', 'Cumulative projection coverage is unknown')}
      description={text('未能读取当前节点投影状态；不要把显示的小计当作完整历史账本。刷新重新查询，读取不会修复或修改收费。',
        'Node projection status could not be read. Do not treat displayed subtotals as a complete historical ledger. Refresh to read again; reading does not repair or change charges.')} />}
    {status?.committedProjectionIncomplete === true && <Alert type="warning" showIcon
      message={text('当前节点累计投影不完整', 'This node’s cumulative projection is incomplete')}
      description={text('旧或 legacy 记录、缺失或损坏的证据、扫描超界等原因使完整范围无法确认。已验证的小计仍保留；后台未迁移旧费用、重新扣费或删除历史。当前组织保留记录的下方汇总是独立查询，预算以原请求的持久账本和结算回执为准。',
        'Legacy records, missing or damaged evidence, or bounded scans can leave historical coverage unconfirmed. Verified subtotals remain; no historical fees were migrated, charged again, or deleted. The retained-record totals below are a separate query. Budget charges follow the original durable ledgers and settlement receipts.')} />}
    {status?.committedGroupsMerged === true && <Alert type="info" showIcon
      message={text('累计投影部分分组已合并', 'Some cumulative projection groups were merged')}
      description={text('有界显示会合并分组或缩短最近记录；这不表示删除持久计量记录，也不能单独证明历史覆盖完整。',
        'Bounded display can merge groups or shorten recent detail. It does not delete durable metering records or by itself prove complete historical coverage.')} />}
  </Space>;
}

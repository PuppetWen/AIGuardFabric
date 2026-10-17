import { Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { Campaign } from '@/types/domain';
import { DataState } from '@/components/DataState';
import { categoryLabel } from './redteam.data';

export function CampaignTable({ loading, error, campaigns, onSelect, page, total, onPage }: {
  loading: boolean; error: unknown; campaigns: Campaign[]; onSelect: (id: string) => void;
  page: number; total: number; onPage: (page: number) => void;
}) {
  const { t, i18n } = useTranslation(); const zh = i18n.language.startsWith('zh');
  return <DataState loading={loading} error={error}>
    <Table<Campaign> rowKey="id" dataSource={campaigns} scroll={{ x: 1250 }}
      pagination={{ current: page, total, pageSize: 10, showSizeChanger: false, onChange: onPage }} columns={[
        { title: t('redteam.column.name'), dataIndex: 'name', render: (name, row) => <><Typography.Link onClick={() => onSelect(row.id)}>{name}</Typography.Link>{row.scheduled && <Tag>{zh ? '定时巡航' : 'Scheduled'}</Tag>}</> },
        { title: zh ? '模式' : 'Mode', render: (_, row) => <Tag color="blue">{row.executionMode === 'simulator' ? (zh ? '模拟' : 'Simulated') : row.executionMode === 'agent-http' ? (zh ? '真实 Agent HTTP' : 'Real Agent HTTP') : row.executionMode === 'mcp-http' ? (zh ? '真实 MCP HTTP' : 'Real MCP HTTP') : row.executionMode ?? (zh ? '历史未知' : 'Legacy: unknown')}</Tag> },
        { title: t('redteam.column.status'), render: (_, row) => ({ planned: zh ? '排队' : 'Queued', running: zh ? '执行中' : 'Running', succeeded: zh ? '已完成' : 'Completed', failed: zh ? '失败' : 'Failed', aborted: zh ? '已取消' : 'Cancelled' })[row.status] },
        { title: t('redteam.column.categories'), render: (_, row) => row.categories.map(v => categoryLabel(v, zh)).join(' / ') },
        { title: zh ? '已执行 / 总数' : 'Executed / total', render: (_, row) => `${row.executedCases ?? 0} / ${row.totalCases}` },
        { title: zh ? '攻击成功率' : 'Attack success rate', render: (_, row) => row.successRate === null ? '—' : `${(row.successRate * 100).toFixed(1)}%` },
        { title: 'CI', render: (_, row) => !row.ciGateEnabled ? t('common.disabled') : typeof row.ciPassed !== 'boolean' ? '—' : row.ciPassed ? (zh ? '通过' : 'Passed') : (zh ? '未通过' : 'Failed') },
        { title: t('redteam.column.operator'), dataIndex: 'operator' },
      ]} />
  </DataState>;
}

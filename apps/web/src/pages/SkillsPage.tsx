import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Input, Select, Space, Table, Tag, Typography, message } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined } from '@ant-design/icons';
import { api, useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import type { Skill, SkillStatus } from '@/types/domain';
import { formatDateTime } from '@/utils/format';
import { toolCapabilityKey } from '@/utils/labels';
import { ObservationGuide } from './ObservationGuide';
import { SkillReviewModal } from './skills/SkillReviewModal';
import { skillLifecycleLabel } from './skills/skillLifecycle';
import { SkillGuide } from './skills/SkillGuide';

const FILTERS: Record<SkillStatus, string> = {
  pending: 'requested,under-review,trial,changing', approved: 'production', rejected: 'rejected', revoked: 'archived',
};
export default function SkillsPage() {
  const identity = useAuthStore(state => `${state.tenant?.id}:${state.sessionGeneration}`);
  return <SkillInventory key={identity} />;
}
function SkillInventory() {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const locale = useAppLocale();
  const access = useSessionAccess();
  const [query, setQuery] = useState({ page: 1, pageSize: 20, keyword: '', sort: 'name' });
  const [filter, setFilter] = useState<SkillStatus>();
  const [target, setTarget] = useState<{ skill: Skill; mode: 'review' | 'allowlist' } | null>(null);
  const skills = useApiQuery('skills', () => api.skills({ ...query, lifecycles: filter ? FILTERS[filter] : undefined }),
    { key: [query, filter] });
  const columns: ColumnsType<Skill> = [
    { title: t('skills.column.name'), dataIndex: 'name', width: 230, sorter: true,
      render: (name: string, row) => <Space direction="vertical" size={2}>
        <Typography.Text strong>{name}</Typography.Text>
        <Typography.Text type="secondary" className="agf-mono">{row.id}</Typography.Text>
        {row.version && <Tag>{row.version}</Tag>}
      </Space> },
    { title: t('skills.column.publisher'), dataIndex: 'publisher', width: 140 },
    { title: t('skills.column.status'), dataIndex: 'status', width: 155,
      render: (status: SkillStatus, row) => <Space direction="vertical" size={2}>
        <Tag color={status === 'approved' ? 'green' : status === 'pending' ? 'gold' : 'default'}>{t(`status.${status}`)}</Tag>
        {row.review && <Typography.Text type="secondary">{skillLifecycleLabel(row.review.lifecycle, zh)}</Typography.Text>}
      </Space> },
    { title: t('skills.column.capability'), dataIndex: 'capabilities', width: 180,
      render: (values: string[]) => values.map(value => <Tag key={value}>{t(toolCapabilityKey(value))}</Tag>) },
    { title: t('common.riskScore'), dataIndex: 'riskScore', width: 100, sorter: true,
      render: (value: number | null) => value ?? t('common.unknown') },
    { title: t('skills.column.attached'), dataIndex: 'attachedAgents', width: 100,
      render: (value: number | null) => value ?? t('common.unknown') },
    { title: t('skills.column.whitelist'), width: 140, render: (_, row) =>
      <Button type="link" onClick={() => setTarget({ skill: row, mode: 'allowlist' })}>
        {text('查看声明', 'View declaration')} ({row.whitelist.domains.length}/{row.whitelist.paths.length})
      </Button> },
    { title: text('负责人 / 登记时间', 'Owner / registered at'), dataIndex: 'requestedBy', width: 160,
      render: (owner: string, row) => <Space direction="vertical" size={0}><span>{owner}</span>
        <Typography.Text type="secondary">{formatDateTime(row.requestedAt, locale)}</Typography.Text></Space> },
    { title: t('skills.column.decided'), dataIndex: 'decidedAt', width: 180,
      render: (at: string | null, row) => at ? <Space direction="vertical" size={0}>
        <span>{formatDateTime(at, locale)}</span><Typography.Text type="secondary">{row.decidedBy}</Typography.Text>
      </Space> : t('common.unknown') },
    { title: t('common.actions'), key: 'actions', fixed: 'right', width: 150,
      render: (_, row) => <Button onClick={() => setTarget({ skill: row, mode: 'review' })}>
        {text('查看 / 评审', 'View / review')}
      </Button> },
  ];
  return <>
    <PageHeader title={t('skills.title')} subtitle={t('skills.subtitle')} actions={<Space wrap>
      <Input.Search allowClear placeholder={text('搜索名称、负责人或标签', 'Search name, owner or tag')}
        onSearch={keyword => setQuery(value => ({ ...value, page: 1, keyword }))} style={{ width: 250 }} />
      <Select allowClear placeholder={t('skills.filter.status')} value={filter} style={{ width: 160 }}
        onChange={(value: SkillStatus | undefined) => { setFilter(value); setQuery(current => ({ ...current, page: 1 })); }}
        options={Object.keys(FILTERS).map(value => ({ value, label: t(`status.${value}`) }))} />
      <Button icon={<ReloadOutlined />} onClick={() => void skills.refetch()}>{t('common.refresh')}</Button>
    </Space>} />
    <SkillGuide /><ObservationGuide />
    <DataState loading={skills.isLoading} error={skills.error} skeletonRows={6}>
      <Table<Skill> rowKey="id" columns={columns} dataSource={skills.data?.data.items ?? []} scroll={{ x: 1640 }}
        onChange={(pagination, _, sort, extra) => {
          const sorter = Array.isArray(sort) ? sort[0] : sort;
          const key = sorter.field === 'riskScore' ? 'risk_score' : 'name';
          setQuery(value => ({ ...value, page: extra.action === 'sort' ? 1 : pagination.current ?? 1,
            pageSize: pagination.pageSize ?? 20,
            sort: sorter.order ? `${sorter.order === 'descend' ? '-' : ''}${key}` : 'name' }));
        }}
        pagination={{ current: query.page, pageSize: query.pageSize, total: skills.data?.data.total ?? 0,
          showSizeChanger: true, showTotal: total => t('common.total', { count: total }) }} />
    </DataState>
    {target && <SkillReviewModal key={`${target.skill.id}:${target.mode}`} skill={target.skill} mode={target.mode}
      canWrite={access.has('skills:write')} onClose={() => setTarget(null)}
      onSaved={() => { message.success(text('已保存', 'Saved')); void skills.refetch(); }} />}
  </>;
}

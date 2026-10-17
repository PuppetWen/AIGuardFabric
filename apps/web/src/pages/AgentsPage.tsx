import { observationStatus } from '@/utils/measurements';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Badge, Button, Input, Progress, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { FilterValue } from 'antd/es/table/interface';
import { ReloadOutlined, RocketOutlined } from '@ant-design/icons';
import { useAuthStore } from '@/stores/authStore';
import { OnboardingWizard } from './agents/OnboardingWizard';
import { AgentConnectionGuide } from './agents/AgentConnectionGuide';
import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Chip } from '@/components/Tags';
import type { Agent, ManagementMode } from '@/types/domain';
import { formatDateTime, fromNow } from '@/utils/format';
import { managementModeKey } from '@/utils/labels';

import { ObservationGuide } from './ObservationGuide';

const MANAGEMENT_COLOR: Record<ManagementMode, string> = {
  sidecar: '#3dd68c',
  'sdk-inject': '#3d8bfd',
  'gateway-register': '#9b5cf6',
  unmanaged: '#ff8b90',
};

const FLAVORS = ['langchain', 'langgraph', 'autogen', 'crewai', 'dify', 'coze', 'qwen-agent', 'custom'];

export default function AgentsPage() {
  const identity = useAuthStore(state => `${state.tenant?.id}:${state.sessionGeneration}`);
  return <AgentInventory key={identity} />;
}
function AgentInventory() {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [wizard, setWizard] = useState<{ agent: Agent | null } | null>(null);
  const [query, setQuery] = useState({ page: 1, pageSize: 20, keyword: '', sort: 'name' });
  const [filters, setFilters] = useState<Record<string, FilterValue | null>>({});
  const agents = useApiQuery('agents', () => api.agents({ ...query,
    flavor: filters.flavor?.join(','), management: filters.management?.join(','), observed: filters.online?.join(','),
  }), { key: [query, filters], refetchInterval: 30_000 });

  const items = agents.data?.data.items ?? [];

  // Render must stay pure, so the "stale heartbeat" comparison reads a clock that
  // is refreshed on a timer rather than calling Date.now() during render.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const columns: ColumnsType<Agent> = [
    {
      title: t('agents.column.name'),
      dataIndex: 'name', sorter: true,
      width: 240,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong>{name}</Typography.Text>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id} · v{record.version}
          </span>
        </Space>
      ),
    },
    {
      title: t('agents.column.flavor'),
      dataIndex: 'flavor', filteredValue: filters.flavor ?? null,
      width: 128,
      filters: FLAVORS.map((flavor) => ({
        text: flavor,
        value: flavor,
      })),
      render: (flavor: string) => <Tag color="geekblue">{flavor}</Tag>,
    },
    {
      title: t('agents.column.host'),
      dataIndex: 'host',
      width: 230,
      render: (host: string, record) => (
        <Space direction="vertical" size={2}>
          <span className="agf-mono" style={{ fontSize: 12 }}>
            {host}
          </span>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.ip}
          </span>
        </Space>
      ),
    },
    {
      title: t('agents.column.management'),
      dataIndex: 'management', filteredValue: filters.management ?? null,
      width: 148,
      filters: (['sidecar', 'sdk-inject', 'gateway-register', 'unmanaged'] as ManagementMode[]).map(
        (value) => ({ text: t(managementModeKey(value)), value }),
      ),
      render: (value: ManagementMode) => (
        <Chip color={MANAGEMENT_COLOR[value]}>{t(managementModeKey(value))}</Chip>
      ),
    },
    {
      title: t('agents.column.online'),
      dataIndex: 'online', filteredValue: filters.online ?? null,
      width: 104,
      filters: [
        { text: t('agents.online'), value: true },
        { text: t('agents.offline'), value: false },
        { text: t('common.unknown'), value: 'unknown' },
      ],
      render: (online: boolean | null, record) => {
        const observed = observationStatus(online, record.lastHeartbeatAt, record.heartbeatIntervalSec, now);
        return (
          <Badge
            status={observed === true ? 'success' : 'default'}
            text={
              <span style={{ fontSize: 13 }}>
                {observed === null ? t('common.unknown') : t(observed ? 'agents.online' : 'agents.offline')}
              </span>
            }
          />
        );
      },
    },
    {
      title: t('agents.column.heartbeat'),
      dataIndex: 'lastHeartbeatAt',
      width: 168,
      sorter: true,
      render: (value: string | null, record) => value === null ? t('common.unknown') : (
        <Tooltip title={formatDateTime(value, locale)}>
          <Space direction="vertical" size={0}>
            <span className="agf-mono" style={{ fontSize: 12 }}>
              {fromNow(value, locale)}
            </span>
            <span className="agf-tertiary" style={{ fontSize: 11 }}>
              {record.heartbeatIntervalSec !== null && record.heartbeatIntervalSec > 0 ? `${record.heartbeatIntervalSec}s` : '—'}
            </span>
          </Space>
        </Tooltip>
      ),
    },
    {
      title: t('agents.column.sessions'),
      dataIndex: 'activeSessions',
      width: 108,
      align: 'right',
      sorter: true,
      render: (value: number | null) => value ?? t('common.unknown'),
    },
    { title: t('agents.column.tools'), dataIndex: 'toolCount', width: 88, align: 'right', render: (value: number | null) => value ?? t('common.unknown') },
    {
      title: t('common.riskScore'),
      dataIndex: 'riskScore',
      width: 130,
      sorter: true,
      render: (score: number | null) => score === null ? <span>{t('common.unknown')}</span> : (
        <Progress
          percent={score}
          size="small"
          strokeColor={score >= 80 ? '#ff8b90' : score >= 60 ? '#ffab7a' : '#8fbaff'}
          format={(value) => `${value}`}
        />
      ),
    },
    {
      title: t('common.actions'),
      key: 'actions',
      fixed: 'right',
      width: 108,
      render: (_value, record) => (
        <Button
          size="small"
          type="link"
          onClick={() => setWizard({ agent: record })}
        >
          {t('agents.wizard.button')}
        </Button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t('agents.title')}
        subtitle={t('agents.subtitle')}
        actions={
          <Space wrap>
            <Input.Search allowClear placeholder={zh ? '搜索全部 Agent' : 'Search all agents'}
              onSearch={keyword => setQuery(value => ({ ...value, page: 1, keyword }))} style={{ width: 240 }} />
            <Button icon={<ReloadOutlined />} onClick={() => void agents.refetch()}>
              {t('common.refresh')}
            </Button>
            <Button
              type="primary"
              icon={<RocketOutlined />}
              onClick={() => setWizard({ agent: null })}
            >
              {t('agents.wizard.button')}
            </Button>
          </Space>
        }
      />

      <AgentConnectionGuide /><ObservationGuide />
      <DataState loading={agents.isLoading} error={agents.error} onRetry={() => void agents.refetch()} skeletonRows={6}>
        <Table<Agent>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={items}
          scroll={{ x: 1560 }}
          onChange={(pagination, nextFilters, sort, extra) => {
            const sorter = Array.isArray(sort) ? sort[0] : sort;
            const fields: Record<string, string> = { name: 'name', riskScore: 'risk_score', lastHeartbeatAt: 'last_seen_at', activeSessions: 'active_sessions' };
            const field = fields[String(sorter.field)] ?? 'name';
            setFilters(nextFilters);
            setQuery(value => ({ ...value, page: extra.action === 'paginate' ? pagination.current ?? 1 : 1,
              pageSize: pagination.pageSize ?? 20, sort: sorter.order ? `${sorter.order === 'descend' ? '-' : ''}${field}` : 'name' }));
          }}
          pagination={{ current: query.page, pageSize: query.pageSize, total: agents.data?.data.total ?? 0,
            showSizeChanger: true, showTotal: total => t('common.total', { count: total }) }}
        />
      </DataState>

      {wizard && <OnboardingWizard agent={wizard.agent} onClose={() => setWizard(null)} />}

    </>
  );
}

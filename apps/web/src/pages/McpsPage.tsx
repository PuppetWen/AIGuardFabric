import { compareMeasurements } from '@/utils/measurements';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Alert,
  Badge,
  Button,
  Drawer,
  Progress,
  Input,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { FilterValue } from 'antd/es/table/interface';
import { useAuthStore } from '@/stores/authStore';
import { ReloadOutlined, WarningOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Chip, SeverityTag } from '@/components/Tags';
import type { McpServer, McpTool, ToolCapability } from '@/types/domain';
import { formatDateTime } from '@/utils/format';
import { mcpTransportKey, toolCapabilityKey } from '@/utils/labels';
import { HttpEndpointConsole } from './mcp/HttpEndpointConsole';

import { ObservationGuide } from './ObservationGuide';

const TRANSPORT_COLOR: Record<McpServer['transport'], string> = {
  unknown: '#6f7683',
  stdio: '#6f7683',
  sse: '#3d8bfd',
  'streamable-http': '#12a594',
  websocket: '#9b5cf6',
};

const CAPABILITY_COLOR: Record<ToolCapability, string> = {
  read: '#3d8bfd',
  write: '#9b5cf6',
  execute: '#ff8b90',
  network: '#12a594',
  filesystem: '#f0cc6a',
  credential: '#ffab7a',
  payment: '#c2185b',
};



export default function McpsPage() {
  const identity = useAuthStore(state => `${state.tenant?.id}:${state.sessionGeneration}`);
  return <McpInventory key={identity} />;
}
function McpInventory() {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const [selected, setSelected] = useState<McpServer | null>(null);
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [query, setQuery] = useState({ page: 1, pageSize: 20, keyword: '', sort: 'name' });
  const [filters, setFilters] = useState<Record<string, FilterValue | null>>({});

  const servers = useApiQuery('mcps', () => api.mcps({ ...query, transport: filters.transport?.join(','),
    shadow: filters.shadow?.join(','), plaintext: filters.plaintextCredential?.join(','),
  }), { key: [query, filters], refetchInterval: 45_000 });
  const tools = useApiQuery('mcp-tools', () => api.mcpTools(selected?.id ?? ''), {
    key: [selected?.id],
    enabled: Boolean(selected),
  });

  const rows = servers.data?.data.items ?? [];

  const columns: ColumnsType<McpServer> = [
    {
      title: t('mcps.column.name'),
      dataIndex: 'name', sorter: true,
      width: 200,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Space size={6}>
            <Typography.Link onClick={() => setSelected(record)}>{name}</Typography.Link>
            {record.shadow ? (
              <Tooltip title={t('mcps.shadow.tip')}>
                <WarningOutlined style={{ color: 'var(--agf-danger)' }} />
              </Tooltip>
            ) : null}
          </Space>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id}
          </span>
        </Space>
      ),
    },
    {
      title: t('mcps.column.transport'),
      dataIndex: 'transport', filteredValue: filters.transport ?? null,
      width: 152,
      filters: (['stdio', 'sse', 'streamable-http', 'websocket', 'unknown'] as McpServer['transport'][]).map((value) => ({
        text: t(mcpTransportKey(value)),
        value,
      })),
      render: (value: McpServer['transport']) => (
        <Chip color={TRANSPORT_COLOR[value]}>{t(mcpTransportKey(value))}</Chip>
      ),
    },
    {
      title: t('mcps.column.endpoint'),
      dataIndex: 'endpoint',
      width: 300,
      render: (endpoint: string) => (
        <Tooltip title={endpoint}>
          <span
            className="agf-mono"
            style={{
              fontSize: 12,
              display: 'inline-block',
              maxWidth: 290,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              verticalAlign: 'middle',
            }}
          >
            {endpoint}
          </span>
        </Tooltip>
      ),
    },
    {
      title: t('mcps.column.tools'),
      dataIndex: 'toolCount',
      width: 92,
      align: 'right',
      sorter: true,
      render: (count: number | null, record) => (
        <Button size="small" type="link" onClick={() => setSelected(record)}>
          {count ?? t('common.unknown')}
        </Button>
      ),
    },
    {
      title: t('mcps.column.shadow'),
      dataIndex: 'shadow', filteredValue: filters.shadow ?? null,
      width: 128,
      filters: [
        { text: t('mcps.shadow.yes'), value: true },
        { text: t('mcps.shadow.no'), value: false },
      ],
      render: (shadow: boolean) =>
        shadow ? (
          <Tooltip title={t('mcps.shadow.tip')}>
            <Tag color="red" style={{ marginInlineEnd: 0 }}>
              {t('mcps.shadow.yes')}
            </Tag>
          </Tooltip>
        ) : (
          <Tag color="green" style={{ marginInlineEnd: 0 }}>
            {t('mcps.shadow.no')}
          </Tag>
        ),
    },
    {
      title: t('mcps.column.plaintext'),
      dataIndex: 'plaintextCredential', filteredValue: filters.plaintextCredential ?? null,
      width: 144,
      filters: [
        { text: t('mcps.plaintext.yes'), value: true },
        { text: t('mcps.plaintext.no'), value: false },
      ],
      render: (plain: boolean) =>
        plain ? (
          <Tooltip title={t('mcps.plaintext.tip')}>
            <Tag color="orange" style={{ marginInlineEnd: 0 }}>
              {t('mcps.plaintext.yes')}
            </Tag>
          </Tooltip>
        ) : (
          <Tag style={{ marginInlineEnd: 0 }}>{t('mcps.plaintext.no')}</Tag>
        ),
    },
    { title: t('mcps.column.owner'), dataIndex: 'owner', width: 116 },
    {
      title: t('mcps.column.online'),
      dataIndex: 'online',
      width: 100,
      render: (online: boolean | null) => (
        <Badge status={online ? 'success' : 'default'} text={online === null ? t('common.unknown') : t(online ? 'agents.online' : 'agents.offline')} />
      ),
    },
    {
      title: t('mcps.column.lastSeen'),
      dataIndex: 'lastSeenAt',
      width: 168,
      sorter: true,
      render: (value: string | null) => <span className="agf-mono">{value === null ? t('common.unknown') : formatDateTime(value, locale)}</span>,
    },
    {
      title: t('common.riskScore'),
      dataIndex: 'riskScore',
      width: 128,
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
  ];

  const toolColumns: ColumnsType<McpTool> = [
    {
      title: t('mcps.tools.column.name'),
      dataIndex: 'name',
      width: 156,
      render: (name: string) => <span className="agf-mono">{name}</span>,
    },
    { title: t('mcps.tools.column.description'), dataIndex: 'description', width: 250 },
    {
      title: t('mcps.tools.column.capability'),
      dataIndex: 'capabilities',
      width: 200,
      render: (capabilities: ToolCapability[]) => (
        <span className="agf-inline-list">
          {capabilities.map((capability) => (
            <Chip key={capability} color={CAPABILITY_COLOR[capability]}>
              {t(toolCapabilityKey(capability))}
            </Chip>
          ))}
        </span>
      ),
    },
    {
      title: t('mcps.tools.column.risk'),
      dataIndex: 'riskLevel',
      width: 108,
      sorter: (a, b) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(a.riskLevel) - ['info', 'low', 'medium', 'high', 'critical'].indexOf(b.riskLevel),
      render: (_value, record) => <SeverityTag severity={record.riskLevel} />,
    },
    {
      title: t('mcps.tools.column.invocations'),
      dataIndex: 'invocations24h',
      width: 118,
      align: 'right',
      sorter: (a, b, order) => compareMeasurements(a.invocations24h, b.invocations24h, order),
      render: (value: number | null) => value === null ? t('common.unknown') : value.toLocaleString(),
    },
    {
      title: t('mcps.tools.column.sensitive'),
      dataIndex: 'sensitiveParams',
      width: 190,
      render: (params: string[]) =>
        params.length === 0 ? (
          <span className="agf-tertiary">—</span>
        ) : (
          <span className="agf-inline-list">
            {params.map((param) => (
              <Tag key={param} color="orange" style={{ marginInlineEnd: 0 }}>
                {param}
              </Tag>
            ))}
          </span>
        ),
    },
    {
      title: t('mcps.tools.column.datasources'),
      dataIndex: 'datasources',
      width: 200,
      render: (sources: string[]) => (
        <span className="agf-inline-list">
          {sources.map((source) => (
            <Tag key={source} style={{ marginInlineEnd: 0 }}>
              {source}
            </Tag>
          ))}
        </span>
      ),
    },
  ];

  const toolList = tools.data?.data ?? [];

  return (
    <>
      <PageHeader
        title={t('mcps.title')}
        subtitle={t('mcps.subtitle')}
        actions={
          <Space>
            <HttpEndpointConsole />
            <Input.Search allowClear placeholder={zh ? '搜索全部 MCP' : 'Search all MCP servers'}
              onSearch={keyword => setQuery(value => ({ ...value, page: 1, keyword }))} style={{ width: 240 }} />
            <Button icon={<ReloadOutlined />} onClick={() => { void servers.refetch(); if (selected) void tools.refetch(); }}>
              {t('common.refresh')}
            </Button>
          </Space>
        }
      />

      <ObservationGuide />
      <DataState loading={servers.isLoading} error={servers.error} onRetry={() => void servers.refetch()} skeletonRows={6}>
        <Table<McpServer>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={rows}
          scroll={{ x: 1820 }}
          onChange={(pagination, nextFilters, sort, extra) => {
            const sorter = Array.isArray(sort) ? sort[0] : sort;
            const fields: Record<string, string> = { name: 'name', riskScore: 'risk_score', lastSeenAt: 'last_seen_at', toolCount: 'tool_count' };
            const field = fields[String(sorter.field)] ?? 'name';
            setFilters(nextFilters);
            setQuery(value => ({ ...value, page: extra.action === 'paginate' ? pagination.current ?? 1 : 1,
              pageSize: pagination.pageSize ?? 20, sort: sorter.order ? `${sorter.order === 'descend' ? '-' : ''}${field}` : 'name' }));
          }}
          pagination={{
            current: query.page, pageSize: query.pageSize, total: servers.data?.data.total ?? 0,
            showSizeChanger: true,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>

      <Drawer
        width={860}
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={t('mcps.tools.title', { name: selected?.name ?? '' })}
        destroyOnClose
        loading={tools.isLoading}
      >
        {selected ? (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            {selected.shadow ? (
              <Alert
                type="error"
                showIcon
                message={t('mcps.tools.shadowWarning')}
                description={t('mcps.shadow.tip')}
              />
            ) : null}
            {selected.plaintextCredential ? (
              <Alert type="warning" showIcon message={t('mcps.plaintext.tip')} />
            ) : null}

            <Space size={8} wrap>
              <Chip color={TRANSPORT_COLOR[selected.transport]}>
                {t(mcpTransportKey(selected.transport))}
              </Chip>
              <Tag>{selected.toolCount === null ? t('common.unknown') : t('mcps.tools.count', { count: selected.toolCount })}</Tag>
              <span className="agf-mono agf-tertiary">{selected.endpoint}</span>
            </Space>

            <DataState loading={tools.isLoading} error={tools.error} onRetry={() => void tools.refetch()}>
            <Table<McpTool>
              rowKey="id"
              size="small"
              columns={toolColumns}
              dataSource={toolList}
              pagination={false}
              scroll={{ x: 1180, y: 460 }}
            />
            </DataState>
          </Space>
        ) : null}
      </Drawer>
    </>
  );
}

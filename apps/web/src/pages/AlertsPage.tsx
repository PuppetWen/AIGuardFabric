import { EscalationDrawer } from './alerts/EscalationDrawer';
import { useAlertActions } from './alerts/useAlertActions';
import { useAuthStore } from '@/stores/authStore';
import { AlertDetail } from './alerts/AlertDetail';
import { useSearchParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Alert as ErrorNotice,
  Badge,
  Button,
  Input,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { BellOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Chip, SeverityTag } from '@/components/Tags';
import type {
  Alert,
  AlertStatus,
  RiskDomain,
  Severity,
} from '@/types/domain';
import { DOMAIN_HEX } from '@/utils/palette';
import { countdown, formatDateTime } from '@/utils/format';

const STATUSES: AlertStatus[] = ['open', 'acknowledged', 'escalated', 'resolved', 'suppressed'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const DOMAINS: RiskDomain[] = ['data', 'identity', 'runtime'];

/** SLA countdown cell. Re-renders every 30s so the clock stays honest. */
function SlaCell({ alert }: { alert: Alert }) {
  const { t } = useTranslation();
  const [, setTick] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => setTick((value) => value + 1), 30_000);
    return () => clearInterval(timer);
  }, []);

  const remaining = countdown(alert.slaDueAt);
  if (!alert.slaDueAt) return <span className="agf-tertiary">—</span>;
  if (['acknowledged', 'resolved', 'suppressed'].includes(alert.status)) return <span className="agf-tertiary">{t(`status.${alert.status}`)}</span>;
  const minutesLeft = remaining.totalMs / 60_000;
  const color = remaining.breached
    ? '#ff8b90'
    : minutesLeft <= 15
      ? '#f0cc6a'
      : 'var(--agf-text)';

  return (
    <Space direction="vertical" size={0}>
      <span className="agf-mono" style={{ color, fontWeight: remaining.breached ? 600 : 400 }}>
        {remaining.breached
          ? t('alerts.sla.breached')
          : t('alerts.sla.remaining', { time: remaining.text })}
      </span>
      {!remaining.breached && minutesLeft <= 15 ? (
        <span className="agf-tertiary" style={{ fontSize: 11 }}>
          {t('alerts.sla.dueSoon')}
        </span>
      ) : null}
    </Space>
  );
}

export default function AlertsPage() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const session = useAuthStore(state => state.sessionGeneration);
  const [params] = useSearchParams();
  return <AlertConsole key={`${tenant}:${session}:${params.get('q') ?? ''}`} />;
}

function AlertConsole() {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const [params, setParams] = useSearchParams();
  const urlKeyword = params.get('q') ?? '';
  const [search, setSearch] = useState(urlKeyword);
  const [status, setStatus] = useState<AlertStatus[]>([]);
  const [severity, setSeverity] = useState<Severity[]>([]);
  const [domain, setDomain] = useState<RiskDomain[]>([]);
  const [selectedKeys, setSelectedKeys] = useState<React.Key[]>([]);
  const [routesOpen, setRoutesOpen] = useState(false);
  const [query, setQuery] = useState({ page: 1, pageSize: 10, sortBy: "lastSeenAt", sortOrder: "desc" as "asc" | "desc", keyword: urlKeyword });

  const submitSearch = (value: string) => {
    const keyword = value.trim();
    setParams(previous => {
      const next = new URLSearchParams(previous);
      if (keyword) next.set('q', keyword); else next.delete('q');
      return next;
    });
    setQuery(current => ({ ...current, page: 1, keyword }));
    setSelectedKeys([]);
  };

  const filters = { severity: severity.join(','), state: status.map(value => value === 'resolved' ? 'closed' : value).join(','),
    domain: domain.flatMap(value => ({ data: ['rag-poison', 'model-data'], identity: ['credential-leak'], runtime: ['prompt-attack', 'tool-abuse'] })[value as 'data' | 'identity' | 'runtime']).join(',') };
  const alerts = useApiQuery('alerts', () => api.alerts({ ...query, ...filters }), { key: [query, filters], refetchInterval: 30_000 });
  const actions = useAlertActions(async () => {
    const result = await alerts.refetch();
    const total = result.data?.data.total;
    if (total !== undefined) setQuery(current => ({ ...current, page: Math.min(current.page, Math.max(1, Math.ceil(total / current.pageSize))) }));
    return result;
  }, ids => setSelectedKeys(ids));
  const canWrite = alerts.data?.data.canWrite === true;
  const resetPage = () => { setQuery(current => ({ ...current, page: 1 })); setSelectedKeys([]); };
  const rows = alerts.data?.data.items ?? [];

  const columns: ColumnsType<Alert> = [
    {
      title: t('alerts.column.title'),
      dataIndex: 'title',
      width: 320,
      render: (title: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Link strong style={{ fontSize: 13 }} onClick={() => setParams(previous => { const next = new URLSearchParams(previous); next.set("alert", record.id); return next; })}>
            {title}
          </Typography.Link>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id} · {record.source}
          </span>
        </Space>
      ),
    },
    {
      title: t('alerts.column.severity'),
      dataIndex: 'severity',
      width: 108,
      sorter: true,
      render: (_value, record) => <SeverityTag severity={record.severity} />,
    },
    {
      title: t('alerts.column.domain'),
      dataIndex: 'domain',
      width: 116,
      render: (value: RiskDomain) => value ? <Chip color={DOMAIN_HEX[value]}>{t(`domain.${value}`)}</Chip> : '—',
    },
    { title: t('alerts.column.asset'), dataIndex: 'assetName', width: 190 },
    {
      title: t('alerts.column.aggregate'),
      dataIndex: 'aggregateCount',
      width: 116,
      align: 'right',
      sorter: true,
      render: (value: number) => (
        <Tooltip title={t('alerts.aggregate.tip')}>
          <Badge count={value} overflowCount={9999} color="#3d8bfd" />
        </Tooltip>
      ),
    },
    {
      title: t('alerts.column.status'),
      dataIndex: 'status',
      width: 168,
      render: (_value, record) => (
        <Select<AlertStatus>
          size="small"
          value={record.status}
          disabled={!canWrite || actions.busy}
          style={{ width: 140 }}
          onChange={next => void actions.update([record.id], next)}
          options={STATUSES.map((value) => ({ value, label: t(`status.${value}`) }))}
        />
      ),
    },
    {
      title: t('alerts.column.sla'),
      key: 'sla',
      width: 190,
      sorter: true,
      dataIndex: "slaDueAt",
      render: (_value, record) => <SlaCell alert={record} />,
    },
    {
      title: t('alerts.column.escalation'),
      dataIndex: 'escalationTier',
      width: 110,
      render: (value: number) => value === 0 ? '—' : <Tag color={value >= 3 ? 'red' : value === 2 ? 'orange' : 'blue'}>
        {t('alerts.escalation.tier', { tier: value })}
      </Tag>,
    },
    {
      title: t('alerts.column.assignee'),
      dataIndex: 'assignee',
      width: 108,
      render: (value: string | null) => value ?? <span className="agf-tertiary">—</span>,
    },
    {
      title: t('alerts.column.lastSeen'),
      dataIndex: 'lastSeenAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
  ];


  return (
    <>
      <AlertDetail />
      <PageHeader
        title={t('alerts.title')}
        subtitle={t('alerts.subtitle')}
        actions={
          <Space>
            <Button icon={<BellOutlined />} onClick={() => setRoutesOpen(true)}>
              {t('alerts.escalation.title')}
            </Button>
            <Button icon={<ReloadOutlined />} onClick={() => void alerts.refetch()}>
              {t('common.refresh')}
            </Button>
          </Space>
        }
      />

      <div className="agf-toolbar">
        <Input.Search value={search} onChange={event => setSearch(event.target.value)} onSearch={submitSearch}
          maxLength={64} allowClear style={{ width: 300 }}
          placeholder={t('common.search') + (locale.startsWith('zh') ? '告警 / 战役编号' : ' alert / campaign ID')} />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 180 }}
          placeholder={t('findings.filter.severity')}
          value={severity}
          onChange={values => { setSeverity(values); resetPage(); }}
          options={SEVERITIES.map((value) => ({ value, label: t(`severity.${value}`) }))}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 180 }}
          placeholder={t('findings.filter.domain')}
          value={domain}
          onChange={values => { setDomain(values); resetPage(); }}
          options={DOMAINS.map((value) => ({ value, label: t(`domain.${value}`) }))}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 180 }}
          placeholder={t('common.status')}
          value={status}
          onChange={values => { setStatus(values); resetPage(); }}
          options={STATUSES.map((value) => ({ value, label: t(`status.${value}`) }))}
        />
        <Button
          onClick={() => {
            setSeverity([]);
            setDomain([]);
            setStatus([]);
            setSearch('');
            submitSearch('');
            resetPage();
          }}
        >
          {t('common.reset')}
        </Button>
        <span className="agf-header__spacer" />
        {canWrite && selectedKeys.length > 0 ? (
          <Space size={6}>
            <span className="agf-muted">{t('alerts.batch.selected', { count: selectedKeys.length })}</span>
            <Button size="small" disabled={actions.busy} onClick={() => void actions.update(selectedKeys.map(String), 'acknowledged')}>
              {t('alerts.batch.ack')}
            </Button>
            <Button size="small" type="primary" disabled={actions.busy} onClick={() => void actions.update(selectedKeys.map(String), 'resolved')}>
              {t('alerts.batch.resolve')}
            </Button>
            <Button size="small" danger disabled={actions.busy} onClick={() => void actions.update(selectedKeys.map(String), 'suppressed')}>
              {t('alerts.batch.suppress')}
            </Button>
          </Space>
        ) : (
          <span className="agf-muted">{t('common.total', { count: alerts.data?.data.total ?? 0 })}</span>
        )}
      </div>

      {actions.failures.length > 0 && <ErrorNotice type="error" showIcon style={{ marginBottom: 12 }}
        message={t('error.server')} description={actions.failures.map(error => <div key={error}>{error}</div>)} />}
      <DataState loading={alerts.isLoading} error={alerts.error} onRetry={() => void alerts.refetch()} skeletonRows={6}>
        <Table<Alert>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={rows}
          scroll={{ x: 1840 }}
          rowSelection={canWrite ? { selectedRowKeys: selectedKeys, onChange: setSelectedKeys, getCheckboxProps: () => ({ disabled: actions.busy }) } : undefined}
          onChange={(pagination, _filters, sorter) => {
            const sort = Array.isArray(sorter) ? sorter[0] : sorter;
            setSelectedKeys([]);
            setQuery(current => ({ ...current, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? 10,
              sortBy: sort.order ? ({ aggregateCount: 'dedupCount' }[String(sort.field)] ?? String(sort.field)) : 'lastSeenAt',
              sortOrder: sort.order === 'ascend' ? 'asc' : 'desc' }));
          }}
          pagination={{
            current: alerts.data?.data.page ?? 1,
            pageSize: alerts.data?.data.pageSize ?? 10,
            total: alerts.data?.data.total ?? 0,
            showSizeChanger: true,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>

      {routesOpen && <EscalationDrawer onClose={() => setRoutesOpen(false)} />}
    </>
  );
}

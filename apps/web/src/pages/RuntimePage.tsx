import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Alert,
  Button,
  Col,
  Form,
  Input,
  Modal,
  Row,
  Segmented,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PauseOutlined, PlayCircleOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, summariseQuotas, useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { MiniChart, useChartTokens } from '@/components/MiniChart';
import { Panel } from '@/components/Panel';
import { ActionTag, Chip, HealthTag, Meter } from '@/components/Tags';
import type { BlacklistEntry, InterceptEvent, PolicyAction, QuotaScope } from '@/types/domain';
import { HEALTH_HEX, POLICY_ACTION_HEX } from '@/utils/palette';
import { compactNumber, formatDateTime } from '@/utils/format';
import { interceptPointKey, policyActionKey, quotaLevelKey, quotaRatio, quotaScopeKey } from '@/utils/labels';
import type { EChartsOption } from 'echarts';
import { RuntimeToolActivity } from './runtime/RuntimeToolActivity';
import { RuntimeQuotaPanel } from './runtime/RuntimeQuotaPanel';
import { McpEndpointUsage } from './mcp/McpEndpointUsage';

type BlacklistKind = 'command' | 'domain';

export default function RuntimePage() {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const chartTokens = useChartTokens();
  const canManageBlacklists = useSessionAccess().has('policies:write');
  const [paused, setPaused] = useState(false);
  const [pausedStream, setPausedStream] = useState<InterceptEvent[]>([]);
  const [blacklistKind, setBlacklistKind] = useState<BlacklistKind>('command');
  const [addOpen, setAddOpen] = useState(false);
  const [blacklistBusy, setBlacklistBusy] = useState(false);
  const blacklistPending = useRef(false);
  const [form] = Form.useForm<{ pattern: string; action: PolicyAction; scope: QuotaScope; note: string }>();

  const points = useApiQuery('intercept-points', () => api.interceptPoints(), { refetchInterval: 30_000 });
  const events = useApiQuery('intercept-events', () => api.interceptEvents(), {
    refetchInterval: paused ? false : 5_000,
  });
  const quotas = useApiQuery('runtime-quotas', () => api.quotas(), { refetchInterval: 30_000 });
  const blacklists = useApiQuery('blacklists', () => api.blacklists());

  // The API returns newest-first audit records. Freeze only when the user pauses.
  const stream = paused ? pausedStream : (events.data?.data ?? []).slice(0, 40);

  const quotaByScope = useMemo(() => {
    const list = quotas.data?.data ?? [];
    return {
      tenant: list.filter((usage) => usage.scope === 'tenant'),
      agent: list.filter((usage) => usage.scope === 'agent'),
      session: list.filter((usage) => usage.scope === 'session'),
    };
  }, [quotas.data]);

  const worstRatio = useMemo(
    () => summariseQuotas(quotas.data?.data ?? []),
    [quotas.data],
  );

  const throughputOption = useMemo<EChartsOption>(() => {
    const list = points.data?.data ?? [];
    return {
      grid: { left: 96, right: 26, top: 16, bottom: 22 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        backgroundColor: chartTokens.tooltipBg,
        borderColor: chartTokens.tooltipBorder,
        textStyle: { color: chartTokens.textStrong, fontSize: 12 },
      },
      xAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: chartTokens.grid, type: 'dashed' } },
        axisLabel: { color: chartTokens.text, fontSize: 11 },
      },
      yAxis: {
        type: 'category',
        data: list.map((point) => t(interceptPointKey(point.point))),
        axisLine: { lineStyle: { color: chartTokens.grid } },
        axisLabel: { color: chartTokens.text, fontSize: 12 },
      },
      series: [
        {
          type: 'bar',
          barWidth: 16,
          data: list.map((point) => ({
            value: point.throughputPerMin,
            itemStyle: { color: HEALTH_HEX[point.health] },
          })),
        },
      ],
    };
  }, [chartTokens, points.data, t]);

  const eventColumns: ColumnsType<InterceptEvent> = [
    {
      title: t('runtime.stream.column.time'),
      dataIndex: 'ts',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('runtime.stream.column.point'),
      dataIndex: 'point',
      width: 132,
      filters: (['mcp-proxy', 'ai-gateway', 'process-hook', 'egress-proxy'] as const).map((value) => ({
        text: t(interceptPointKey(value)),
        value,
      })),
      onFilter: (value, record) => record.point === value,
      render: (_value, record) => <Tag>{t(interceptPointKey(record.point))}</Tag>,
    },
    { title: t('runtime.stream.column.agent'), dataIndex: 'agentName', width: 190 },
    {
      title: t('runtime.stream.column.target'),
      key: 'target',
      width: 190,
      render: (_value, record) => {
        const target = [record.mcpName, record.toolName].filter(Boolean).join(' · ');
        return target ? (
          <span className="agf-mono" style={{ fontSize: 12 }}>
            {target}
          </span>
        ) : (
          <span className="agf-tertiary">—</span>
        );
      },
    },
    {
      title: t('runtime.stream.column.action'),
      dataIndex: 'action',
      width: 108,
      render: (_value, record) => <ActionTag action={record.action} />,
    },
    { title: t('runtime.stream.column.policy'), dataIndex: 'policyName', width: 220 },
    { title: t('runtime.stream.column.reason'), dataIndex: 'reason', width: 260 },
    {
      title: t('runtime.stream.column.latency'),
      dataIndex: 'latencyMs',
      width: 108,
      align: 'right',
      render: (value: number) => (
        <span className="agf-mono">{value > 0 && value < 0.1 ? '<0.1 ms' : `${value.toFixed(1)} ms`}</span>
      ),
    },
  ];

  const changeBlacklist = async (row: BlacklistEntry, enabled?: boolean) => {
    if (blacklistPending.current) return;
    blacklistPending.current = true;
    setBlacklistBusy(true);
    try {
      if (enabled === undefined) await api.deleteBlacklist(row.id, row.version);
      else await api.updateBlacklist(row.id, enabled, row.version);
    } catch (error) {
      message.error(error instanceof Error ? error.message : String(error));
    } finally {
      try { await blacklists.refetch(); }
      finally { blacklistPending.current = false; setBlacklistBusy(false); }
    }
  };
  const blacklistColumns: ColumnsType<BlacklistEntry> = [
    {
      title: t('runtime.blacklist.pattern'),
      dataIndex: 'pattern',
      width: 320,
      render: (value: string) => <span className="agf-mono">{value}</span>,
    },
    {
      title: t('runtime.blacklist.action'),
      dataIndex: 'action',
      width: 110,
      render: (_value, record) => <ActionTag action={record.action} />,
    },
    {
      title: t('runtime.blacklist.scope'),
      dataIndex: 'scope',
      width: 120,
      render: (value: QuotaScope) => <Tag>{t(quotaScopeKey(value))}</Tag>,
    },
    {
      title: t('common.enabled'),
      dataIndex: 'enabled',
      width: 96,
      render: (value: boolean, row: BlacklistEntry) => <Switch size="small" checked={value} disabled={!canManageBlacklists || blacklistBusy}
        onChange={(enabled) => { void changeBlacklist(row, enabled); }} />,
    },
    {
      title: t('runtime.blacklist.hits'),
      dataIndex: 'hits24h',
      width: 118,
      align: 'right',
      sorter: (a, b) => a.hits24h - b.hits24h,
      render: (value: number) => value.toLocaleString(),
    },
    { title: t('runtime.blacklist.note'), dataIndex: 'note', width: 240 },
    {
      title: t('common.updatedAt'),
      dataIndex: 'updatedAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('common.actions'),
      key: 'actions',
      width: 90,
      render: (_: unknown, row: BlacklistEntry) => canManageBlacklists ? (
        <Button size="small" type="link" danger disabled={blacklistBusy} onClick={() => { void changeBlacklist(row); }}>
          {t('common.delete')}
        </Button>
      ) : null,
    },
  ];

  const configuredPoints = points.data?.data ?? [];
  const anyDegraded = configuredPoints.some((point) => point.health !== 'healthy');

  return (
    <>
      <PageHeader
        title={t('runtime.title')}
        subtitle={t('runtime.subtitle')}
        actions={
          <Space>
            <Button
              icon={paused ? <PlayCircleOutlined /> : <PauseOutlined />}
              onClick={() => {
                if (!paused) setPausedStream(stream);
                setPaused(!paused);
              }}
            >
              {paused ? t('runtime.stream.resume') : t('runtime.stream.pause')}
            </Button>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                void points.refetch();
                void quotas.refetch();
                void events.refetch();
              }}
            >
              {t('common.refresh')}
            </Button>
          </Space>
        }
      />

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <RuntimeQuotaPanel />
        {anyDegraded ? (
          <Alert
            type="warning"
            showIcon
            message={t('runtime.intercepts')}
            description={configuredPoints
              .filter((point) => point.health !== 'healthy')
              .map((point) => `${t(interceptPointKey(point.point))}: ${point.lastError ?? t(`health.${point.health}`)}`)
              .join(' | ')}
          />
        ) : null}

        <Panel title={t('runtime.intercepts')}>
          <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))' }}>
            {configuredPoints.map((point) => (
              <div key={point.point} className="agf-panel agf-panel--pad" style={{ background: 'var(--agf-panel-strong)' }}>
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space size={8} wrap>
                    <Typography.Text strong>{t(interceptPointKey(point.point))}</Typography.Text>
                    <HealthTag health={point.health} />
                  </Space>
                  <Tag>{t(`runtime.intercept.mode.${point.mode}`)}</Tag>
                  <Space size={12} wrap className="agf-muted" style={{ fontSize: 12 }}>
                    <span>{t('runtime.intercept.throughput', { value: compactNumber(point.throughputPerMin) })}</span>
                    <span>{t('runtime.intercept.blocked', { value: point.blocked24h })}</span>
                    <span>{t('runtime.intercept.latency', { value: point.p95LatencyMs })}</span>
                  </Space>
                  <Space size={8}>
                    <Tag className="agf-mono">
                      {t('runtime.intercept.version', { value: point.version })}
                    </Tag>
                    <Tag>{t(point.enabled ? 'common.enabled' : 'common.disabled')}</Tag>
                  </Space>
                  {point.lastError ? (
                    <Tooltip title={point.lastError}>
                      <Typography.Text type="warning" style={{ fontSize: 12 }} ellipsis>
                        {t('runtime.intercept.lastError', { value: point.lastError })}
                      </Typography.Text>
                    </Tooltip>
                  ) : null}
                </Space>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12 }}>
            <MiniChart option={throughputOption} height={200} />
          </div>
        </Panel>

        <Panel
          title={t('runtime.stream.title')}
          extra={
            <Space size={8}>
              <span className="agf-severity-dot" style={{ background: paused ? 'var(--agf-text-tertiary)' : 'var(--agf-success)' }} />
              <span className="agf-muted">{paused ? t('runtime.stream.paused') : t('runtime.stream.live')}</span>
            </Space>
          }
        >
          <div className="agf-stream">
            <Table<InterceptEvent>
              rowKey="id"
              size="small"
              columns={eventColumns}
              dataSource={stream}
              pagination={false}
              scroll={{ x: 1580, y: 320 }}
            />
          </div>
        </Panel>

        <RuntimeToolActivity events={events.data?.data ?? []} />
        <McpEndpointUsage runtimeCheck zh={locale === 'zh-CN'} />

        <Row gutter={[14, 14]}>
          {(['tenant'] as QuotaScope[]).map((scope) => (
            <Col xs={24} xl={8} key={scope}>
              <Panel
                title={`${t('runtime.quota.title')} · ${t(quotaScopeKey(scope))}`}
                extra={
                  <Chip color={worstRatio[scope] >= 100 ? '#e5484d' : worstRatio[scope] >= 80 ? '#f0cc6a' : '#3dd68c'}>
                    {t('runtime.quota.ratio', { value: worstRatio[scope] })}
                  </Chip>
                }
              >
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  {quotaByScope[scope].length === 0 ? (
                    <Typography.Text className="agf-tertiary">{t('common.empty')}</Typography.Text>
                  ) : (
                    quotaByScope[scope].map((usage) => {
                      const ratio = quotaRatio(usage);
                      const color =
                        ratio.level === 'exceeded'
                          ? POLICY_ACTION_HEX.deny
                          : ratio.level === 'warning'
                            ? POLICY_ACTION_HEX.alert
                            : '#3dd68c';
                      return (
                        <Meter
                          key={usage.scopeId + usage.unit}
                          ratio={ratio.clampedRatio}
                          color={color}
                          label={
                            <Space size={6}>
                              <span>{usage.scopeName}</span>
                              {usage.throttled ? <Tag color="red">{t('runtime.quota.throttled')}</Tag> : null}
                            </Space>
                          }
                          valueText={t('runtime.quota.used', {
                            used: compactNumber(usage.used),
                            limit: compactNumber(usage.limit),
                          })}
                        />
                      );
                    })
                  )}
                  <Typography.Text className="agf-tertiary" style={{ fontSize: 12 }}>
                    {t(quotaLevelKey(worstRatio[scope] >= 100 ? 'exceeded' : worstRatio[scope] >= 80 ? 'warning' : 'normal'))}
                  </Typography.Text>
                </Space>
              </Panel>
            </Col>
          ))}
        </Row>

        <Panel
          title={t('runtime.blacklist.title')}
          extra={
            <Space size={10}>
              <Segmented<BlacklistKind>
                size="small"
                value={blacklistKind}
                onChange={(value) => setBlacklistKind(value)}
                options={[
                  { value: 'command', label: t('runtime.blacklist.command') },
                  { value: 'domain', label: t('runtime.blacklist.domain') },
                ]}
              />
              {canManageBlacklists && <Button size="small" type="primary" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>
                {t('runtime.blacklist.add')}
              </Button>}
            </Space>
          }
        >
          <DataState loading={blacklists.isLoading} error={blacklists.error}>
            <Table<BlacklistEntry>
              rowKey="id"
              size="small"
              columns={blacklistColumns}
              dataSource={(blacklists.data?.data ?? []).filter((entry) => entry.kind === blacklistKind)}
              pagination={false}
              scroll={{ x: 1440 }}
            />
          </DataState>
        </Panel>
      </Space>

      <Modal
        open={addOpen && canManageBlacklists}
        title={t('runtime.blacklist.add')}
        onCancel={() => setAddOpen(false)}
        onOk={() => {
          void (async () => {
            const values = await form.validateFields();
            await api.addBlacklist({ kind: blacklistKind, ...values });
            message.success(t('runtime.blacklist.added', { pattern: values.pattern }));
            setAddOpen(false);
            form.resetFields();
            void blacklists.refetch();
          })().catch((error: Error) => message.error(error.message));
        }}
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ action: 'deny', scope: 'tenant' }}
        >
          <Form.Item
            name="pattern"
            label={t('runtime.blacklist.pattern')}
            rules={[{ required: true, message: t('runtime.blacklist.pattern') }]}
          >
            <Input
              className="agf-mono"
              placeholder={
                blacklistKind === 'command' ? 're:rm\\s+-rf\\s+/(\\s|$)' : '*.attacker.example'
              }
            />
          </Form.Item>
          <Form.Item name="action" label={t('runtime.blacklist.action')}>
            <Select
              options={(['deny', 'allow', 'alert'] as PolicyAction[]).map((value) => ({
                value,
                label: t(policyActionKey(value)),
              }))}
            />
          </Form.Item>
          <Form.Item name="scope" label={t('runtime.blacklist.scope')}>
            <Select
              options={(['tenant'] as QuotaScope[]).map((value) => ({
                value,
                label: t(quotaScopeKey(value)),
              }))}
            />
          </Form.Item>
          <Form.Item name="note" label={t('runtime.blacklist.note')}>
            <Input />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

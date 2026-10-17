import { useSessionAccess } from '@/api/sessionAccess';
import { compareRiskScores } from '@/utils/measurements';
import { useMemo, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import type { EChartsOption } from 'echarts';
import { Button, Col, List, Progress, Row, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  AlertOutlined,
  ArrowDownOutlined,
  ArrowUpOutlined,
  DollarOutlined,
  DotChartOutlined,
  FileProtectOutlined,
  RocketOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { MiniChart, Sparkline, useChartTokens } from '@/components/MiniChart';
import { Panel } from '@/components/Panel';
import { HealthTag, SeverityTag } from '@/components/Tags';
import type { Asset, DashboardKpi, RecentAlert } from '@/types/domain';
import { CHART_PALETTE, DOMAIN_HEX, HEALTH_HEX } from '@/utils/palette';
import { compactNumber, formatPercent, formatShortDateTime, formatUsd } from '@/utils/format';
import { severityWeight } from '@/utils/severity';

const KPI_ICON: Record<DashboardKpi['key'], ReactNode> = {
  assets: <DotChartOutlined />,
  openAlerts: <AlertOutlined />,
  criticalFindings: <FileProtectOutlined />,
  redteamSuccessRate: <ThunderboltOutlined />,
  tokenSpend: <DollarOutlined />,
};

function formatKpiValue(kpi: DashboardKpi, unknown: string): string {
  if (kpi.value === null) return unknown;
  if (kpi.unit === 'common.unit.cny') {
    return new Intl.NumberFormat('zh-CN', { style: 'currency', currency: 'CNY', maximumFractionDigits: 4 }).format(kpi.value);
  }
  if (kpi.key === 'tokenSpend') {
    return formatUsd(kpi.value);
  }
  if (kpi.key === 'redteamSuccessRate') {
    return `${kpi.value}%`;
  }
  return compactNumber(kpi.value);
}

export default function OverviewPage() {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const tokens = useChartTokens();
  const access = useSessionAccess();
  const { data, isLoading, error, refetch } = useApiQuery('overview', () => api.overview(), {
    refetchInterval: 60_000,
  });

  const overview = data?.data;
  const can = (resource: string) => overview?.access?.[resource] ?? access.has(resource + ':read');
  const quick = (path: string, permission: string) => access.allows(path) && access.has(permission);

  const riskTrendOption = useMemo<EChartsOption>(() => {
    const points = overview?.riskTrend ?? [];
    return {
      grid: { left: 44, right: 18, top: 26, bottom: 28 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: tokens.tooltipBg,
        borderColor: tokens.tooltipBorder,
        textStyle: { color: tokens.textStrong, fontSize: 12 },
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: points.map((point) => formatShortDateTime(point.ts, locale)),
        axisLine: { lineStyle: { color: tokens.grid } },
        axisLabel: { color: tokens.text, fontSize: 11 },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: tokens.grid, type: 'dashed' } },
        axisLabel: { color: tokens.text, fontSize: 11 },
      },
      series: [
        {
          name: t('overview.riskTrend'),
          type: 'line',
          smooth: true,
          showSymbol: points.length === 1,
          data: points.map((point) => point.value),
          lineStyle: { width: 2, color: '#ff8b90' },
          areaStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: tokens.areaTop },
                { offset: 1, color: tokens.areaBottom },
              ],
            },
          },
        },
      ],
    };
  }, [overview, t, tokens, locale]);

  const domainOption = useMemo<EChartsOption>(() => {
    const rows = overview?.domainDistribution ?? [];
    return {
      grid: { left: 78, right: 26, top: 16, bottom: 22 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        backgroundColor: tokens.tooltipBg,
        borderColor: tokens.tooltipBorder,
        textStyle: { color: tokens.textStrong, fontSize: 12 },
      },
      xAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: tokens.grid, type: 'dashed' } },
        axisLabel: { color: tokens.text, fontSize: 11 },
      },
      yAxis: {
        type: 'category',
        data: rows.map((row) => t(`domain.${row.domain}`)),
        axisLine: { lineStyle: { color: tokens.grid } },
        axisLabel: { color: tokens.text, fontSize: 12 },
      },
      series: [
        {
          name: t('overview.domainDistribution.assets'),
          type: 'bar',
          stack: 'total',
          barWidth: 14,
          itemStyle: { color: '#3d8bfd' },
          data: rows.map((row) => row.assets),
        },
        {
          name: t('overview.domainDistribution.findings'),
          type: 'bar',
          stack: 'total',
          barWidth: 14,
          itemStyle: { color: '#d9a326' },
          data: rows.map((row) => row.findings),
        },
      ],
      legend: {
        bottom: 0,
        textStyle: { color: tokens.text, fontSize: 11 },
        icon: 'roundRect',
        itemWidth: 10,
        itemHeight: 10,
      },
    };
  }, [overview, t, tokens]);

  const topAssetColumns: ColumnsType<Asset> = [
    {
      title: t('assets.column.name'),
      dataIndex: 'name',
      render: (name: string, record) => (
        <Link to={"/assets/" + record.id}>
          {name}
        </Link>
      ),
    },
    {
      title: t('assets.column.kind'),
      dataIndex: 'kind',
      width: 110,
      render: (kind: string) => <Tag>{t(`assets.kind.${kind}`)}</Tag>,
    },
    {
      title: t('assets.column.risk'),
      dataIndex: 'riskScore',
      width: 140,
      sorter: compareRiskScores,
      defaultSortOrder: 'descend',
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
      title: t('assets.column.findings'),
      dataIndex: 'openFindings',
      render: (value: number | null) => value ?? t('common.unknown'),
      width: 110,
      align: 'right',
    },
  ];

  return (
    <>
      <PageHeader
        title={t('overview.title')}
        subtitle={t('overview.subtitle')}
        actions={
          <Space wrap>
            <Button icon={<RocketOutlined />} onClick={() => void refetch()}>
              {t('common.refresh')}
            </Button>
            {quick('/redteam', 'redteam:execute') && <Link to="/redteam">
              <Button type="primary" icon={<ThunderboltOutlined />}>{t('overview.quick.redteam')}</Button>
            </Link>}
          </Space>
        }
      />

      <DataState loading={isLoading} error={error} skeletonRows={6}>
        {overview ? (
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Typography.Text type="secondary">{t('overview.metricsHint')}</Typography.Text>
            <div className="agf-grid agf-grid--kpi">
              {overview.kpis.map((kpi) => (
                <Panel key={kpi.key} className="agf-kpi">
                  <div className="agf-kpi__label">
                    <span style={{ color: 'var(--agf-accent)' }}>{KPI_ICON[kpi.key]}</span>
                    <span>{t(`overview.kpi.${kpi.key}`)}</span>
                  </div>
                  <div className="agf-kpi__value">
                    {formatKpiValue(kpi, t('common.unknown'))}
                    {kpi.unit === 'unit.assets' || kpi.unit === 'unit.findings' ? (
                      <small>{t(kpi.unit)}</small>
                    ) : null}
                  </div>
                  <Space size={6} style={{ fontSize: 12 }}>
                    {kpi.delta === null ? <span className="agf-tertiary">{t('overview.noComparison')}</span> : kpi.delta >= 0 ? (
                      <span style={{ color: 'var(--agf-danger)' }}>
                        <ArrowUpOutlined /> {t('overview.kpi.deltaUp', { value: Math.abs(kpi.delta) })}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--agf-success)' }}>
                        <ArrowDownOutlined /> {t('overview.kpi.deltaDown', { value: Math.abs(kpi.delta) })}
                      </span>
                    )}
                  </Space>
                  <div className="agf-kpi__spark" aria-hidden>
                    <Sparkline data={kpi.sparkline} color={CHART_PALETTE[1] ?? '#12a594'} />
                  </div>
                </Panel>
              ))}
            </div>

            <Row gutter={[14, 14]}>
              <Col xs={24} xl={14}>
                <Panel
                  title={
                    <Space direction="vertical" size={0}>
                      <span>{t('overview.riskTrend')}</span>
                      <Typography.Text className="agf-tertiary" style={{ fontSize: 12, fontWeight: 400 }}>
                        {t('overview.riskTrend.tip')}
                      </Typography.Text>
                    </Space>
                  }
                >
                  {can('findings') ? <MiniChart option={riskTrendOption} height={268} /> : <Typography.Text>{t('overview.noAccess')}</Typography.Text>}
                </Panel>
              </Col>
              <Col xs={24} xl={10}>
                <Panel title={t('overview.domainDistribution')}>
                  <MiniChart option={domainOption} height={268} />
                </Panel>
              </Col>
            </Row>

            <Row gutter={[14, 14]}>
              <Col xs={24} xl={12}>
                <Panel
                  title={t('overview.topRiskAssets')}
                  extra={
                    <Link to="/assets">
                      <Button type="link" size="small">
                        {t('common.viewAll')}
                      </Button>
                    </Link>
                  }
                >
                  <Table<Asset>
                    rowKey="id"
                    size="small"
                    pagination={false}
                    columns={topAssetColumns}
                    dataSource={overview.topRiskAssets}
                    scroll={{ x: 480 }}
                  />
                </Panel>
              </Col>
              <Col xs={24} xl={12}>
                <Panel
                  title={t('overview.recentAlerts')}
                  extra={
                    can('alerts') ? <Link to="/alerts">
                      <Button type="link" size="small">{t('common.viewAll')}</Button>
                    </Link> : null
                  }
                >
                  {!can('alerts') && <Typography.Text>{t('overview.noAccess')}</Typography.Text>}
                  <List<RecentAlert>
                    size="small"
                    dataSource={[...overview.recentAlerts].sort(
                      (a, b) => severityWeight(b.severity) - severityWeight(a.severity),
                    )}
                    renderItem={(item) => (
                      <List.Item
                        actions={[
                          <span className="agf-tertiary" style={{ fontSize: 12 }} key="time">
                            {formatShortDateTime(item.occurredAt, locale)}
                          </span>,
                        ]}
                      >
                        <List.Item.Meta
                          avatar={<SeverityTag severity={item.severity} withLabel={false} />}
                          title={<Link style={{ fontSize: 13 }} to={"/alerts?alert=" + item.id}>{item.title}</Link>}
                          description={
                            <Space size={6} wrap>
                              <Tag color={DOMAIN_HEX[item.domain]} style={{ marginInlineEnd: 0 }}>
                                {t(`domain.${item.domain}`)}
                              </Tag>
                              <span className="agf-tertiary" style={{ fontSize: 12 }}>
                                {item.assetName}
                              </span>
                            </Space>
                          }
                        />
                      </List.Item>
                    )}
                  />
                </Panel>
              </Col>
            </Row>

            <Panel title={t('overview.adapterHealth')}>
              {!can('alicloud') && <Typography.Text>{t('overview.noAccess')}</Typography.Text>}
              <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
                {overview.adapterHealth.map((adapter) => (
                  <div
                    key={adapter.id}
                    className="agf-panel agf-panel--pad"
                    style={{ background: 'var(--agf-panel-strong)' }}
                  >
                    <Space direction="vertical" size={6} style={{ width: '100%' }}>
                      <Space size={6} wrap>
                        <Typography.Text strong style={{ fontSize: 13 }}>
                          {adapter.name}
                        </Typography.Text>
                        {adapter.mock ? <Tag color="gold">{t('common.mock')}</Tag> : null}
                      </Space>
                      <Space size={8} wrap>
                        <HealthTag health={adapter.health} />
                        <Tooltip
                          title={adapter.uptimePercent === null ? t('common.unknown') : t('overview.adapterHealth.uptime', {
                            value: adapter.uptimePercent.toFixed(2),
                          })}
                        >
                          <span className="agf-mono" style={{ color: HEALTH_HEX[adapter.health] }}>
                            {adapter.uptimePercent === null ? t('common.unknown') : formatPercent(adapter.uptimePercent / 100)}
                          </span>
                        </Tooltip>
                      </Space>
                      {adapter.uptimePercent !== null && <Progress
                        percent={adapter.uptimePercent}
                        showInfo={false}
                        size="small"
                        strokeColor={HEALTH_HEX[adapter.health]}
                      />}
                    </Space>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title={t('overview.quickActions')}>
              <Space wrap size={10}>
                {quick('/redteam', 'redteam:execute') && <Link to="/redteam">
                  <Button icon={<ThunderboltOutlined />}>{t('overview.quick.redteam')}</Button>
                </Link>}
                {quick('/policies', 'policies:write') && <Link to="/policies">
                  <Button icon={<SafetyOutlined />}>{t('overview.quick.policy')}</Button>
                </Link>}
                {quick('/ingest', 'sources:write') && <Link to="/ingest">
                  <Button icon={<DotChartOutlined />}>{t('overview.quick.ingest')}</Button>
                </Link>}
                {quick('/alicloud', 'alicloud:read') && <Link to="/alicloud">
                  <Button icon={<FileProtectOutlined />}>{t('overview.quick.selfcheck')}</Button>
                </Link>}
              </Space>
              <Typography.Paragraph className="agf-tertiary" style={{ fontSize: 12, marginTop: 10, marginBottom: 0 }}>
                {t('overview.generatedAt', { time: overview.generatedAt ? formatShortDateTime(overview.generatedAt, locale) : t('common.unknown') })}
              </Typography.Paragraph>
            </Panel>
          </Space>
        ) : null}
      </DataState>
    </>
  );
}

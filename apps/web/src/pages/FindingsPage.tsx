import { useState } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { useScopedOperation } from '@/components/useScopedOperation';
import { useDetailLink } from '@/components/useDetailLink';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import {
  Button,
  Descriptions,
  Drawer,
  Select,
  Space,
  Steps,
  Table,
  Tabs,
  Tag,
  Timeline,
  Tooltip,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Chip, SeverityTag } from '@/components/Tags';
import type { Finding, FindingStatus, ListQuery, RiskDomain, Severity } from '@/types/domain';
import { DOMAIN_HEX } from '@/utils/palette';
import { formatDateTime, formatPercent } from '@/utils/format';
import { FindingAsset } from './findings/FindingAsset';
import { FindingEvidence } from './findings/FindingEvidence';
import { CorrelationEvidence } from './findings/CorrelationEvidence';
import { ExportFindingsButton } from './findings/ExportFindingsButton';
import { ScanJobsButton } from './findings/ScanJobsButton';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const DOMAINS: RiskDomain[] = ['data', 'identity', 'runtime'];
const STATUSES: FindingStatus[] = ['pending', 'code-reviewed', 'verified', 'false-positive', 'fixed'];

const LLM_COLOR: Record<string, string> = {
  'true-positive': '#3dd68c',
  'false-positive': '#6f7683',
  inconclusive: '#f0cc6a',
};

export default function FindingsPage() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const session = useAuthStore(state => state.sessionGeneration);
  return <FindingConsole key={`${tenant}:${session}`} />;
}

function FindingConsole() {
  const { t, i18n } = useTranslation();
  const readOnlyHint = i18n.language.startsWith('zh') ? '当前账号没有发现状态修改权限' : 'This account cannot change finding states';
  const locale = useAppLocale();
  const [severity, setSeverity] = useState<Severity[]>([]);
  const [domain, setDomain] = useState<RiskDomain[]>([]);
  const [status, setStatus] = useState<FindingStatus[]>([]);
  const [query, setQuery] = useState<ListQuery>({ page: 1, pageSize: 10 });
  const linked = useDetailLink<Finding>('finding', '/api/v1/findings');
  const selected = linked.value;
  const operation = useScopedOperation();

  const findings = useApiQuery(
    'findings',
    () => api.findings({ severity, domain, status }, query),
    { key: [severity, domain, status, query] },
  );
  const canWrite = findings.data?.data.canWrite === true && !findings.error;

  const changeStatus = async (finding: Finding, next: FindingStatus): Promise<void> => {
    if (!canWrite || next === finding.status) return;
    await operation.run(async current => {
      try {
        const response = await api.updateFindingStatus(finding.id, next);
        if (!current()) return;
        if (response.data && linked.id === finding.id) await linked.detail.refetch();
        if (current()) await findings.refetch();
      } catch (reason) {
        if (current()) void message.error(reason instanceof Error ? reason.message : String(reason));
      }
    });
  };

  const columns: ColumnsType<Finding> = [
      {
        title: t('findings.column.title'),
        dataIndex: 'title',
        width: 330,
        render: (title: string, record) => (
          <Space direction="vertical" size={2}>
            <Typography.Link onClick={() => linked.select(record.id)}>{title}</Typography.Link>
            <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
              {record.id}
            </span>
          </Space>
        ),
      },
      {
        title: t('findings.column.severity'),
        dataIndex: 'severity',
        width: 112,
        sorter: true,
        sortOrder: query.sortBy === 'severity' ? (query.sortOrder === 'asc' ? 'ascend' : 'descend') : null,
        render: (_value, record) => <SeverityTag severity={record.severity} />,
      },
      {
        title: t('findings.column.domain'),
        dataIndex: 'domain',
        width: 116,
        render: (value: RiskDomain) => <Chip color={DOMAIN_HEX[value]}>{t(`domain.${value}`)}</Chip>,
      },
      {
        title: t('findings.column.asset'),
        dataIndex: 'assetName',
        width: 200,
        render: (_value: string, record) => (
          <Tooltip title={record.assetId}>
            <FindingAsset finding={record} />
          </Tooltip>
        ),
      },
      {
        title: t('findings.column.rule'),
        dataIndex: 'ruleName',
        width: 250,
        render: (value: string, record) => (
          <Space direction="vertical" size={2}>
            <span style={{ fontSize: 13 }}>{value}</span>
            <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
              {record.ruleId}
            </span>
          </Space>
        ),
      },
      {
        title: t('findings.column.status'),
        dataIndex: 'status',
        width: 168,
        render: (_value, record) => (
          <Select<FindingStatus>
            size="small"
            aria-label={`${t('findings.column.status')}: ${record.title}`}
            disabled={!canWrite || operation.busy}
            title={!canWrite ? readOnlyHint : undefined}
            value={record.status}
            style={{ width: 140 }}
            onChange={(next) => void changeStatus(record, next)}
            options={STATUSES.map((value) => ({ value, label: t(`status.${value}`) }))}
          />
        ),
      },
      {
        title: t('findings.column.detectedAt'),
        dataIndex: 'detectedAt',
        width: 168,
        sorter: true,
        sortOrder: query.sortBy === 'firstSeenAt' ? (query.sortOrder === 'asc' ? 'ascend' : 'descend') : null,
        render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
      },
      { title: t('findings.column.assignee'), dataIndex: 'assignee', width: 106,
        render: (value: string | null) => value ?? <span className="agf-tertiary">—</span> },
      {
        title: t('findings.drawer.llm'),
        key: 'llm',
        width: 148,
        render: (_value, record) => (
          <Space direction="vertical" size={0}>
            <Chip color={LLM_COLOR[record.llmVerdict?.verdict ?? ''] ?? '#6f7683'}>
              {record.llmVerdict ? t(`findings.llm.${record.llmVerdict.verdict}`) : t('common.noData')}
            </Chip>
            <span className="agf-tertiary" style={{ fontSize: 11 }}>
              {formatPercent(record.llmVerdict?.confidence)}
            </span>
          </Space>
        ),
      },
      {
        title: t('common.actions'),
        key: 'actions',
        fixed: 'right',
        width: 92,
        render: (_value, record) => (
          <Button size="small" type="link" onClick={() => linked.select(record.id)}>
            {t('common.detail')}
          </Button>
        ),
      },
    ];

  return (
    <>
      <PageHeader
        title={t('findings.title')}
        subtitle={t('findings.subtitle')}
        actions={
          <Space>
            <ScanJobsButton onResults={() => void findings.refetch()} />
            <ExportFindingsButton filter={{ severity, domain, status }} />
            <Button icon={<ReloadOutlined />} onClick={() => void findings.refetch()}>
              {t('common.refresh')}
            </Button>
          </Space>
        }
      />

      <div className="agf-toolbar">
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 190 }}
          placeholder={t('findings.filter.severity')}
          value={severity}
          onChange={value => { setSeverity(value); setQuery(current => ({ ...current, page: 1 })); }}
          options={SEVERITIES.map((value) => ({ value, label: t(`severity.${value}`) }))}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 190 }}
          placeholder={t('findings.filter.domain')}
          value={domain}
          onChange={value => { setDomain(value); setQuery(current => ({ ...current, page: 1 })); }}
          options={DOMAINS.map((value) => ({ value, label: t(`domain.${value}`) }))}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 190 }}
          placeholder={t('findings.filter.status')}
          value={status}
          onChange={value => { setStatus(value); setQuery(current => ({ ...current, page: 1 })); }}
          options={STATUSES.map((value) => ({ value, label: t(`status.${value}`) }))}
        />
        <Button
          onClick={() => {
            setSeverity([]);
            setDomain([]);
            setStatus([]);
            setQuery(current => ({ ...current, page: 1 }));
          }}
        >
          {t('common.reset')}
        </Button>
        <span className="agf-header__spacer" />
        <span className="agf-muted">{t('common.total', { count: findings.data?.data.total ?? 0 })}</span>
      </div>

      <DataState loading={findings.isLoading} error={findings.error} skeletonRows={6}>
        <Table<Finding>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={findings.data?.data.items ?? []}
          scroll={{ x: 1880 }}
          onChange={(pagination, _filters, sort) => {
            const selectedSort = Array.isArray(sort) ? sort[0] : sort;
            setQuery({ page: pagination.current ?? 1, pageSize: pagination.pageSize ?? 10,
              sortBy: selectedSort.order ? (selectedSort.field === 'severity' ? 'severity' : 'firstSeenAt') : undefined,
              sortOrder: selectedSort.order === 'ascend' ? 'asc' : 'desc' });
          }}
          pagination={{
            current: findings.data?.data.page ?? 1,
            pageSize: findings.data?.data.pageSize ?? 10,
            total: findings.data?.data.total ?? 0,
            showSizeChanger: true,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>

      <Drawer
        width={760}
        open={Boolean(linked.id)}
        onClose={() => linked.select(null)}
        title={t('findings.drawer.title', { id: linked.id })}
        destroyOnClose
      >
        <DataState loading={linked.detail.isLoading} error={linked.detail.error} onRetry={() => void linked.detail.refetch()}>
        {selected ? (
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Space size={8} wrap>
              <SeverityTag severity={selected.severity} />
              <Chip color={DOMAIN_HEX[selected.domain]}>{t(`domain.${selected.domain}`)}</Chip>
              <Tag>{t(`status.${selected.status}`)}</Tag>
              <Chip color={LLM_COLOR[selected.llmVerdict?.verdict ?? ''] ?? '#6f7683'}>
                {selected.llmVerdict ? t(`findings.llm.${selected.llmVerdict.verdict}`) : t('common.noData')}
              </Chip>
            </Space>

            <Link to={`/cases?finding=${encodeURIComponent(selected.id)}`}>
              <Button type="primary">{i18n.language.startsWith('zh') ? '核对证据后关联新案件' : 'Create a case from this finding'}</Button>
            </Link>

            <div>
              <div className="agf-drawer-section__title">{t('findings.drawer.summary')}</div>
              <Typography.Paragraph style={{ marginBottom: 6 }}>{selected.summary}</Typography.Paragraph>
              <Typography.Paragraph type="secondary" style={{ fontSize: 13 }}>
                {selected.description}
              </Typography.Paragraph>
            </div>

            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label={t('findings.column.asset')}><FindingAsset finding={selected} /></Descriptions.Item>
              <Descriptions.Item label={t('findings.column.rule')}>{selected.ruleName}</Descriptions.Item>
              <Descriptions.Item label={t('findings.drawer.cvss')}>{selected.cvss}</Descriptions.Item>
              <Descriptions.Item label={t('findings.drawer.cwe')}>{selected.cwe ?? '—'}</Descriptions.Item>
              <Descriptions.Item label={t('findings.column.detectedAt')}>
                {formatDateTime(selected.detectedAt, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('common.updatedAt')}>
                {formatDateTime(selected.updatedAt, locale)}
              </Descriptions.Item>
            </Descriptions>

            <Tabs
              size="small"
              items={[
                {
                  key: 'evidence',
                  label: t('findings.drawer.evidence'),
                  children: (
                    <FindingEvidence items={selected.evidence} />
                  ),
                },
                {
                  key: 'triple',
                  label: t('findings.drawer.triple'),
                  children: (
                    <Space direction="vertical" size={10} style={{ width: '100%' }}>
                      {(
                        [
                          ['baseline', selected.triple.baseline],
                          ['diff', selected.triple.diff],
                          ['marker', selected.triple.markerEcho],
                        ] as const
                      ).map(([key, value]) => (
                        <div key={key}>
                          <div className="agf-drawer-section__title">{t(`findings.drawer.${key}`)}</div>
                          <pre className="agf-code agf-code--compact">{value}</pre>
                        </div>
                      ))}
                    </Space>
                  ),
                },
                {
                  key: 'chain',
                  label: t('findings.drawer.callChain'),
                  children: selected.correlationAnalysis ? <CorrelationEvidence analysis={selected.correlationAnalysis} /> : (
                    <Steps
                      direction="vertical"
                      size="small"
                      current={selected.callChain.length}
                      items={selected.callChain.map((step) => ({ title: step }))}
                    />
                  ),
                },
                {
                  key: 'remediation',
                  label: t('findings.drawer.remediation'),
                  children: <Typography.Paragraph>{selected.remediation}</Typography.Paragraph>,
                },
                {
                  key: 'llm',
                  label: t('findings.drawer.llm'),
                  children: selected.llmVerdict ? (
                    <Space direction="vertical" size={8} style={{ width: '100%' }}>
                      <Space size={8} wrap>
                        <Chip color={LLM_COLOR[selected.llmVerdict.verdict] ?? '#6f7683'}>
                          {t(`findings.llm.${selected.llmVerdict.verdict}`)}
                        </Chip>
                        <span className="agf-muted">
                          {t('findings.drawer.confidence', {
                            value: Math.round(selected.llmVerdict.confidence * 100),
                          })}
                        </span>
                        <Tag className="agf-mono">{selected.llmVerdict.model}</Tag>
                      </Space>
                      <Typography.Paragraph style={{ marginBottom: 0 }}>
                        {selected.llmVerdict.reasoning}
                      </Typography.Paragraph>
                      <Timeline
                        items={[
                          {
                            children: `${t('findings.drawer.llm')} · ${formatDateTime(
                              selected.llmVerdict.reviewedAt,
                              locale,
                            )}`,
                          },
                        ]}
                      />
                    </Space>
                  ) : <Typography.Text type="secondary">{t('common.noData')}</Typography.Text>,
                },
              ]}
            />
          </Space>
        ) : null}
        </DataState>
      </Drawer>
    </>
  );
}

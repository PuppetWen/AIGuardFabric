import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { callApi } from '@/api/transport';
import { casesApi } from '@/api/cases';

import {
  Alert,
  Badge,
  Button,
  Collapse,
  Descriptions,
  Drawer,
  Pagination,
  Input,
  Space,
  Steps,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined } from '@ant-design/icons';
import CaseActions from './cases/CaseActions';
import CaseAutomations from './cases/CaseAutomations';
import { CaseResponseGuide } from './cases/CaseResponseGuide';
import { CreateCase, CaseLifecycle } from './cases/CaseLifecycle';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { SecurityAnalysisPanel } from '@/components/SecurityAnalysisPanel';
import { DataState, PageHeader } from '@/components/DataState';
import { Chip, SeverityTag } from '@/components/Tags';
import type { Case, CaseState, Finding, SoarRun } from '@/types/domain';
import { CASE_STATE_HEX, CASE_STATE_ORDER } from '@/utils/palette';
import { formatDateTime } from '@/utils/format';
import { caseStateKey, soarStatusKey } from '@/utils/labels';

export default function CasesPage() {
  const { t, i18n } = useTranslation();
  const locale = useAppLocale();
  const { id } = useParams<{id: string}>();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const findingId = searchParams.get('finding') ?? '';
  const linkedFinding = useApiQuery('case-create-finding', () => callApi<Finding>(
    `/api/v1/findings/${encodeURIComponent(findingId)}`,
    () => { throw new Error('Finding detail unavailable'); }, { noFallback: true },
  ), { key: [findingId], enabled: Boolean(findingId) });
  const clearFinding = () => setSearchParams(previous => {
    const next = new URLSearchParams(previous);
    next.delete('finding');
    return next;
  }, { replace: true });
  const detail = useApiQuery('case-detail', () => casesApi.get(id ?? ''), { key: [id], enabled: Boolean(id) });
  const selected = detail.data?.data.case ?? null;
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState('');

  const cases = useApiQuery('cases', () => api.cases({ page, pageSize: 30, keyword }), { key: [page, keyword], refetchInterval: 60_000 });
  const timeline = useApiQuery('case-timeline', () => api.caseTimeline(selected?.id ?? ''), {
    key: [selected?.id],
    enabled: Boolean(selected),
    refetchInterval: 5000,
  });
  const soar = useApiQuery('case-soar', () => api.soarRuns(selected?.id ?? ''), {
    key: [selected?.id],
    enabled: Boolean(selected),
    refetchInterval: 5000,
  });

  const byState = useMemo(() => {
    const items = cases.data?.data?.items ?? [];
    return CASE_STATE_ORDER.reduce<Record<CaseState, Case[]>>(
      (acc, state) => {
        acc[state] = items.filter((item) => item.state === state);
        return acc;
      },
      {
        new: [],
        triaged: [],
        containing: [],
        recovered: [],
        closed: [],
      },
    );
  }, [cases.data]);

  const refreshCase = () => {
    void timeline.refetch(); void soar.refetch();
    void cases.refetch(); void detail.refetch();
  };

  const soarColumns: ColumnsType<SoarRun> = [
    {
      title: t('cases.soar.playbook'),
      dataIndex: 'playbook',
      width: 230,
      render: (value: string, row) => <Space direction="vertical"><span className="agf-mono">{value}</span>
        {row.dryRun && <Tag>{i18n.language?.startsWith('zh') ? '演练' : 'Dry run'}</Tag>}</Space>,
    },
    {
      title: t('common.status'),
      dataIndex: 'status',
      width: 118,
      render: (value: SoarRun['status']) => (
        <Chip
          color={
            value === 'succeeded'
              ? '#3dd68c'
              : value === 'running'
                ? '#3d8bfd'
                : value === 'failed'
                  ? '#ff8b90'
                  : '#8b93a1'
          }
        >
          {t(soarStatusKey(value))}
        </Chip>
      ),
    },
    {
      title: t('cases.soar.startedAt'),
      dataIndex: 'startedAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('cases.soar.duration'),
      key: 'duration',
      width: 110,
      align: 'right',
      render: (_value, record) => {
        const duration = record.steps.reduce((sum, step) => sum + step.durationMs, 0);
        return <span className="agf-mono">{duration > 0 ? (duration / 1000).toFixed(1) + 's' : '—'}</span>;
      },
    },
    {
      title: t('cases.soar.step'),
      key: 'steps',
      render: (_value, record) => (
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          {record.steps.map((step) => (
            <Space key={step.name} size={6} align="baseline">
              <Chip
                color={
                  step.status === 'done'
                    ? '#3dd68c'
                    : step.status === 'running'
                      ? '#3d8bfd'
                      : step.status === 'failed'
                        ? '#ff8b90'
                        : '#8b93a1'
                }
              >
                {step.status}
              </Chip>
              <span style={{ fontSize: 12 }}>{step.name}</span>
              {step.output ? (
                <Tooltip title={step.output}>
                  <span className="agf-tertiary" style={{ fontSize: 11 }}>
                    {t('cases.soar.output')}
                  </span>
                </Tooltip>
              ) : null}
            </Space>
          ))}
        </Space>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t('cases.title')}
        subtitle={t('cases.subtitle')}
        actions={
          <Space><CreateCase canWrite={cases.data?.data.canWrite === true} onChange={() => void cases.refetch()}
            prefillFinding={findingId ? linkedFinding.data?.data : undefined} onClearPrefill={findingId ? clearFinding : undefined}
            onCreated={caseId => navigate(`/cases/${encodeURIComponent(caseId)}`)} /><Button icon={<ReloadOutlined />} onClick={() => void cases.refetch()}>
            {t('common.refresh')}
          </Button></Space>
        }
      />

      {findingId && linkedFinding.error && <Alert type="error" showIcon style={{ marginBottom: 16 }}
        message={i18n.language?.startsWith('zh') ? '关联发现无法读取' : 'Cannot load linked finding'}
        description={String(linkedFinding.error)} closable onClose={clearFinding} />}
      {findingId && cases.data?.data.canWrite === false && <Alert type="warning" showIcon style={{ marginBottom: 16 }}
        message={i18n.language?.startsWith('zh') ? '当前账号没有新建案件权限' : 'This account cannot create cases'}
        closable onClose={clearFinding} />}

      <Input.Search style={{ maxWidth: 400, marginBottom: 16 }} placeholder={t('common.search')} allowClear
        onSearch={(value) => { setKeyword(value); setPage(1); }} />
      <Collapse style={{ marginBottom: 16 }} items={[
        { key: 'automations', label: i18n.language?.startsWith('zh') ? '告警自动响应：模板、启停和触发记录' : 'Automatic alert response: templates, enablement and records', children: <CaseAutomations /> },
        { key: 'guide', label: i18n.language?.startsWith('zh') ? '操作指南：案件、审批与恢复' : 'Guide: cases, approvals and recovery', children: <CaseResponseGuide /> },
      ]} />
      <DataState loading={cases.isLoading} error={cases.error} skeletonRows={5}>
        <div className="agf-kanban">
          {CASE_STATE_ORDER.map((state) => (
            <div className="agf-kanban__col" key={state}>
              <div className="agf-kanban__head">
                <Space size={8}>
                  <span className="agf-severity-dot" style={{ background: CASE_STATE_HEX[state] }} />
                  <span>{t(caseStateKey(state))}</span>
                </Space>
                <Badge
                  count={byState[state].length}
                  overflowCount={99}
                  style={{ backgroundColor: CASE_STATE_HEX[state], color: '#0b0f16' }}
                />
              </div>
              <div className="agf-kanban__body">
                {byState[state].length === 0 ? (
                  <Typography.Text className="agf-tertiary" style={{ fontSize: 12 }}>
                    {t('cases.column.count', { count: 0 })}
                  </Typography.Text>
                ) : (
                  byState[state].map((item) => (
                    <div
                      key={item.id}
                      role="button"
                      tabIndex={0}
                      className={`agf-kanban__card${selected?.id === item.id ? ' agf-kanban__card--active' : ''}`}
                      onClick={() => navigate(`/cases/${encodeURIComponent(item.id)}`)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          navigate(`/cases/${encodeURIComponent(item.id)}`);
                        }
                      }}
                    >
                      <Space direction="vertical" size={6} style={{ width: '100%' }}>
                        <Space size={6} wrap>
                          <SeverityTag severity={item.severity} withLabel={false} />
                          <Typography.Text strong style={{ fontSize: 13 }}>
                            {item.title}
                          </Typography.Text>
                        </Space>
                        <div className="agf-inline-list">
                          {item.assetNames.slice(0, 2).map((name) => (
                            <Tag key={name} style={{ marginInlineEnd: 0, fontSize: 11 }}>
                              {name}
                            </Tag>
                          ))}
                        </div>
                        <Space size={8} className="agf-tertiary" style={{ fontSize: 11 }}>
                          <span className="agf-mono">{item.id}</span>
                          <span>{item.owner}</span>
                        </Space>
                      </Space>
                    </div>
                  ))
                )}
              </div>
            </div>
          ))}
        </div>
      </DataState>
      <Pagination current={page} pageSize={30} total={cases.data?.data.total ?? 0} showSizeChanger={false} onChange={setPage} />

      <Drawer
        width={880}
        open={Boolean(id)}
        onClose={() => navigate('/cases')}
        title={t('cases.detail.title', { id: selected?.id ?? '' })}
        destroyOnClose
      >
        <DataState loading={detail.isLoading} error={detail.error} skeletonRows={3} onRetry={() => void detail.refetch()}>
        {selected ? (
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label={t('common.name')} span={2}>
                {selected.title}
              </Descriptions.Item>
              <Descriptions.Item label={t('common.status')}>
                <Chip color={CASE_STATE_HEX[selected.state]}>{t(caseStateKey(selected.state))}</Chip>
              </Descriptions.Item>
              <Descriptions.Item label={t('common.severity')}>
                <SeverityTag severity={selected.severity} />
              </Descriptions.Item>
              <Descriptions.Item label={t('cases.owner')}>{selected.owner}</Descriptions.Item>
              <Descriptions.Item label={t('cases.dueAt')}>
                {formatDateTime(selected.dueAt, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('common.createdAt')}>
                {formatDateTime(selected.createdAt, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('common.updatedAt')}>
                {formatDateTime(selected.updatedAt, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('alerts.title')} span={2}>
                <span className="agf-inline-list">
                  {selected.alertIds.map((id) => (
                    <Tag key={id} className="agf-mono" style={{ marginInlineEnd: 0, fontSize: 11 }}>
                      {id}
                    </Tag>
                  ))}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label={t('findings.title')} span={2}>
                <span className="agf-inline-list">
                  {(selected.findingIds ?? []).map(finding => <Link key={finding}
                    to={`/findings?finding=${encodeURIComponent(finding)}`} className="agf-mono">{finding}</Link>)}
                </span>
              </Descriptions.Item>
            </Descriptions>

            <div>
              <div className="agf-drawer-section__title">{t('findings.drawer.summary')}</div>
              <Typography.Paragraph>{selected.summary}</Typography.Paragraph>
            </div>

            <CaseLifecycle key={'state-' + selected.id} canWrite={detail.data?.data.canWrite === true} item={selected} onChange={refreshCase} />
            <CaseActions key={selected.id} item={selected} onChange={refreshCase} />
            <SecurityAnalysisPanel key={'analysis-' + selected.id} resource="cases" id={selected.id} />

            <div>
              <div className="agf-drawer-section__title">{t('cases.timeline.title')}</div>
              {timeline.data?.data && timeline.data.data.length > 0 ? (
                <div className="agf-timeline">
                  {[...timeline.data.data].reverse().map((entry) => (
                    <div className="agf-timeline__item" key={entry.id}>
                      <div className="agf-timeline__time">{formatDateTime(entry.at, locale)}</div>
                      <div className="agf-timeline__rail">
                        <span className="agf-timeline__dot" />
                      </div>
                      <div className="agf-timeline__body">
                        <div className="agf-timeline__meta">
                          {entry.actor} · {t(`cases.timeline.kind.${entry.kind}`)}
                        </div>
                        <div className="agf-timeline__title">{entry.title}</div>
                        <div className="agf-muted" style={{ fontSize: 13 }}>
                          {entry.detail}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <Typography.Text className="agf-tertiary">{t('cases.timeline.empty')}</Typography.Text>
              )}
            </div>

            <div>
              <div className="agf-drawer-section__title">{t('cases.soar.title')}</div>
              {(soar.data?.data ?? []).length === 0 ? (
                <Typography.Text className="agf-tertiary">{t('cases.soar.empty')}</Typography.Text>
              ) : (
                <Table<SoarRun>
                  rowKey="id"
                  size="small"
                  columns={soarColumns}
                  dataSource={soar.data?.data ?? []}
                  pagination={false}
                  scroll={{ x: 940 }}
                />
              )}
            </div>

            <Steps
              size="small"
              current={CASE_STATE_ORDER.indexOf(selected.state)}
              items={CASE_STATE_ORDER.map((state) => ({ title: t(caseStateKey(state)) }))}
            />
          </Space>
        ) : null}
        </DataState>
      </Drawer>


    </>
  );
}

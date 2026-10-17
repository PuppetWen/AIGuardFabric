import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Input,
  Segmented,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { CheckCircleOutlined, CloseCircleOutlined, SafetyOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { AuditEntry, ChainCheckResult } from '@/types/domain';
import { formatDateTime, truncate } from '@/utils/format';
import { AuditExportButton } from './audit/AuditExportButton';

type ResultFilter = 'all' | AuditEntry['result'];

const RESULT_COLOR: Record<AuditEntry['result'], string> = {
  success: '#3dd68c',
  failure: '#f0cc6a',
  denied: '#ff8b90',
};

export default function AuditPage() {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const [sensitiveOnly, setSensitiveOnly] = useState(false);
  const [actor, setActor] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [resultFilter, setResultFilter] = useState<ResultFilter>('all');
  const [query, setQuery] = useState({ page: 1, pageSize: 15 });
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const [check, setCheck] = useState<ChainCheckResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const filters = {
    keyword: actionFilter.trim() || undefined,
    actor: actor.trim() || undefined,
    outcome: resultFilter === 'all' ? undefined : resultFilter,
    sensitive_only: sensitiveOnly || undefined,
  };
  const audit = useApiQuery('audit', () => api.auditEntries({ ...query, ...filters }), {
    key: [query.page, query.pageSize, filters.keyword, filters.actor, filters.outcome, filters.sensitive_only],
  });
  const rows = audit.data?.data.items ?? [];
  const total = audit.data?.data.total ?? 0;

  const runVerify = async (): Promise<void> => {
    setVerifying(true);
    try {
      const response = await api.verifyChain();
      setCheck(response.data);
      if (response.data.verdict === 'valid') {
        message.success(t('audit.verify.valid'));
      } else {
        message.warning(t(`audit.verify.${response.data.verdict}`));
      }
    } finally {
      setVerifying(false);
    }
  };

  const columns: ColumnsType<AuditEntry> = [
    {
      title: t('audit.column.time'),
      dataIndex: 'ts',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('audit.column.actor'),
      dataIndex: 'actor',
      width: 152,
      render: (value: string, record) => (
        <Space direction="vertical" size={0}>
          <span>{value}</span>
          <span className="agf-tertiary" style={{ fontSize: 11 }}>
            {t(`settings.users.role.${record.actorRole}`)}
          </span>
        </Space>
      ),
    },
    {
      title: t('audit.column.action'),
      dataIndex: 'action',
      width: 200,
      render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
    },
    {
      title: t('audit.column.resource'),
      dataIndex: 'resourceName',
      width: 250,
      render: (value: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Link onClick={() => setSelected(record)}>{value}</Typography.Link>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.resourceKind} · {record.resourceId}
          </span>
        </Space>
      ),
    },
    {
      title: t('audit.column.result'),
      dataIndex: 'result',
      width: 110,
      render: (value: AuditEntry['result']) => (
        <Chip color={RESULT_COLOR[value]}>{t(`audit.result.${value}`)}</Chip>
      ),
    },
    {
      title: t('audit.column.sensitive'),
      dataIndex: 'sensitive',
      width: 110,
      render: (value: boolean) =>
        value ? (
          <Tag color="red" style={{ marginInlineEnd: 0 }}>
            {t('audit.sensitive.yes')}
          </Tag>
        ) : (
          <Tag style={{ marginInlineEnd: 0 }}>{t('audit.sensitive.no')}</Tag>
        ),
    },
    {
      title: t('audit.column.ip'),
      dataIndex: 'ip',
      width: 140,
      render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
    },
    {
      title: t('audit.column.hash'),
      dataIndex: 'hash',
      width: 200,
      render: (value: string, record) => {
        const broken = check?.issues.some((issue) => issue.entryId === record.id);
        return (
          <Tooltip title={value}>
            <Space size={4}>
              {broken ? (
                <CloseCircleOutlined style={{ color: 'var(--agf-danger)' }} />
              ) : (
                <CheckCircleOutlined style={{ color: 'var(--agf-success)', opacity: 0.6 }} />
              )}
              <span className="agf-mono" style={{ fontSize: 11 }}>
                {truncate(value, 22)}
              </span>
            </Space>
          </Tooltip>
        );
      },
    },
  ];

  return (
    <>
      <PageHeader
        title={t('audit.title')}
        subtitle={t('audit.subtitle')}
        actions={
          <Space>
            <Segmented<ResultFilter>
              value={resultFilter}
              onChange={(value) => { setResultFilter(value); setQuery((current) => ({ ...current, page: 1 })); }}
              options={[
                { value: 'all', label: t('common.all') },
                { value: 'success', label: t('audit.result.success') },
                { value: 'failure', label: t('audit.result.failure') },
                { value: 'denied', label: t('audit.result.denied') },
              ]}
            />
            <Button
              type="primary"
              icon={<SafetyOutlined />}
              loading={verifying}
              onClick={() => void runVerify()}
            >
              {verifying ? t('audit.verify.running') : t('audit.verify.button')}
            </Button>
            <AuditExportButton filters={filters} />
          </Space>
        }
      />

      {check ? (
        <Alert
          style={{ marginBottom: 14 }}
          type={check.verdict === 'valid' ? 'success' : check.verdict === 'partial' ? 'warning' : 'error'}
          showIcon
          message={
            <Space size={10} wrap>
              <span>
                {t('audit.verify.title')}: <strong>{t(`audit.verify.${check.verdict}`)}</strong>
              </span>
              <Tag>{t('audit.verify.checked', { count: check.checkedEntries })}</Tag>
              <Tag className="agf-mono">
                {typeof check.firstSequence === 'number' && typeof check.lastSequence === 'number'
                  ? t('audit.verify.sequenceRange', { from: check.firstSequence, to: check.lastSequence })
                  : t('audit.verify.range', {
                    from: check.from ? formatDateTime(check.from, locale) : '—',
                    to: check.to ? formatDateTime(check.to, locale) : '—',
                  })}
              </Tag>
              <Tag className="agf-mono">{t('audit.verify.checkedAt', { time: formatDateTime(check.checkedAt, locale) })}</Tag>
            </Space>
          }
          description={
            check.issues.length === 0 ? (
              t('audit.verify.noIssue')
            ) : (
              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                <span>
                  {t('audit.verify.issues')} ({check.issues.length})
                </span>
                {check.issues.map((issue) => (
                  <span key={issue.entryId} className="agf-mono" style={{ fontSize: 12 }}>
                    {issue.entryId} · {issue.reason} · {t('audit.verify.expected')}={truncate(issue.expectedHash, 26)} ·{' '}
                    {t('audit.verify.actual')}={truncate(issue.actualHash, 26)}
                  </span>
                ))}
              </Space>
            )
          }
        />
      ) : null}

      <div className="agf-toolbar">
        <Input
          allowClear
          style={{ width: 180 }}
          placeholder={t('audit.filter.actor')}
          value={actor}
          onChange={(event) => { setActor(event.target.value); setQuery((current) => ({ ...current, page: 1 })); }}
        />
        <Input
          allowClear
          style={{ width: 220 }}
          placeholder={t('audit.filter.action')}
          value={actionFilter}
          onChange={(event) => { setActionFilter(event.target.value); setQuery((current) => ({ ...current, page: 1 })); }}
          aria-label={t('audit.filter.action')}
        />
        <Space size={8}>
          <span className="agf-muted">{t('audit.filter.sensitiveOnly')}</span>
          <Switch checked={sensitiveOnly} onChange={(value) => {
            setSensitiveOnly(value);
            setQuery((current) => ({ ...current, page: 1 }));
          }} size="small" />
        </Space>
        <span className="agf-header__spacer" />
        <Space size={18}>
          <Statistic title={t('common.total', { count: total })} value={total} valueStyle={{ fontSize: 15 }} />
          <Statistic
            title={t('audit.pageSensitive')}
            value={rows.filter((entry) => entry.sensitive).length}
            valueStyle={{ fontSize: 15, color: 'var(--agf-warning)' }}
          />
          <Statistic
            title={t('audit.pageDenied')}
            value={rows.filter((entry) => entry.result === 'denied').length}
            valueStyle={{ fontSize: 15, color: 'var(--agf-danger)' }}
          />
        </Space>
      </div>

      <DataState loading={audit.isLoading} error={audit.error} skeletonRows={6}>
        <Table<AuditEntry>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={rows}
          scroll={{ x: 1700 }}
          onChange={(pagination) =>
            setQuery({ page: pagination.current ?? 1, pageSize: pagination.pageSize ?? 15 })
          }
          pagination={{
            current: query.page,
            pageSize: query.pageSize,
            total,
            showSizeChanger: true,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>

      <Drawer
        width={620}
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={t('audit.detail.title', { id: selected?.id ?? '' })}
        destroyOnClose
      >
        {selected ? (
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label={t('audit.column.time')}>
                {formatDateTime(selected.ts, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.column.actor')}>
                {selected.actor} · {t(`settings.users.role.${selected.actorRole}`)}
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.column.action')}>
                <span className="agf-mono">{selected.action}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.column.resource')}>
                {selected.resourceKind} · {selected.resourceName} ({selected.resourceId})
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.column.result')}>
                <Chip color={RESULT_COLOR[selected.result]}>{t(`audit.result.${selected.result}`)}</Chip>
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.column.ip')}>
                <span className="agf-mono">{selected.ip}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.detail.userAgent')}>
                <span className="agf-mono" style={{ fontSize: 11 }}>
                  {selected.userAgent}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label={t('audit.detail.detail')}>{selected.detail}</Descriptions.Item>
            </Descriptions>

            <Panel title={t('audit.verify.title')}>
              <Space direction="vertical" size={6} style={{ width: '100%' }}>
                <span className="agf-mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                  hash: {selected.hash}
                </span>
                <span className="agf-mono agf-tertiary" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                  prevHash: {selected.prevHash}
                </span>
                {check?.issues.some((issue) => issue.entryId === selected.id) ? (
                  <Alert
                    type="error"
                    showIcon
                    message={t('audit.verify.issues')}
                    description={
                      check.issues.find((issue) => issue.entryId === selected.id)?.reason ?? ''
                    }
                  />
                ) : (
                  <Typography.Text type="success">{t('audit.verify.noIssue')}</Typography.Text>
                )}
              </Space>
            </Panel>
          </Space>
        ) : null}
      </Drawer>
    </>
  );
}

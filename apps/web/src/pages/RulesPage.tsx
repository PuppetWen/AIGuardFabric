import { DefinitionDetail } from '@/components/DefinitionDetail';
import { useState } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { useScopedOperation } from '@/components/useScopedOperation';
import { useTranslation } from 'react-i18next';

import {
  Alert,
  Button,
  Drawer,
  Input,
  Progress,
  Slider,
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
import { ExperimentOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { RuleEditor } from './rules/RuleEditor';
import { CorrelationConsole } from './rules/CorrelationConsole';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Chip, SeverityTag } from '@/components/Tags';
import type { RiskDomain, Rule, RuleSample } from '@/types/domain';
import { DOMAIN_HEX } from '@/utils/palette';
import { formatDateTime, formatNumber, formatPercent } from '@/utils/format';

export default function RulesPage() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const session = useAuthStore(state => state.sessionGeneration);
  return <RuleConsole key={`${tenant}:${session}`} />;
}

function RuleConsole() {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const readOnlyHint = zh ? '当前账号没有规则修改权限' : 'This account cannot modify rules';
  const locale = useAppLocale();
  const [testRule, setTestRule] = useState<Rule | null>(null);
  const [rollout, setRollout] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState<string>();
  const [error, setError] = useState('');
  const operation = useScopedOperation();
  const [editing, setEditing] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [keyword, setKeyword] = useState('');
  const [domain, setDomain] = useState<string>();

  const rules = useApiQuery('rules', () => api.rules({ page, pageSize, keyword, domain }), { key: [page, pageSize, keyword, domain] });
  const canWrite = rules.data?.data.canWrite === true && !rules.error;
  const testResult = useApiQuery('rule-test', () => api.ruleTest(testRule?.id ?? ''), {
    key: [testRule?.id],
    enabled: Boolean(testRule) && canWrite,
    staleTime: 0,
  });

  const update = async (rule: Rule, patch: { enabled?: boolean; rolloutPercent?: number }) => {
    if (!canWrite || rule.readOnly) return;
    await operation.run(async current => {
      setSaving(rule.id); setError('');
      try {
        await api.updateRule(rule.id, { ...patch, expectedVersion: Number(rule.version) });
        if (!current()) return;
        setRollout(prev => { const next = { ...prev }; delete next[rule.id]; return next; });
        await rules.refetch();
        if (current()) void message.success(zh ? '规则新版本已保存' : 'New rule revision saved');
      } catch (reason) {
        if (!current()) return;
        setRollout(prev => { const next = { ...prev }; delete next[rule.id]; return next; });
        setError(String(reason)); await rules.refetch();
      } finally { if (current()) setSaving(undefined); }
    });
  };

  const columns: ColumnsType<Rule> = [
    {
      title: t('rules.column.name'),
      dataIndex: 'name',
      width: 320,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            {name}
          </Typography.Text>
          <span className="agf-tertiary" style={{ fontSize: 12 }}>
            {record.description}
          </span>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id}
          </span>
        </Space>
      ),
    },
    {
      title: t('rules.column.domain'),
      dataIndex: 'domain',
      width: 116,
      filterMultiple: false,
      filteredValue: domain ? [domain] : null,
      filters: [
        { text: zh ? '提示词攻击' : 'Prompt attacks', value: 'prompt-attack' }, { text: zh ? '凭据泄露' : 'Credential leaks', value: 'credential-leak' },
        { text: zh ? 'RAG 投毒' : 'RAG poisoning', value: 'rag-poison' }, { text: zh ? '工具滥用' : 'Tool abuse', value: 'tool-abuse' },
        { text: zh ? '模型与数据' : 'Models and data', value: 'model-data' },
      ],
      render: (value: RiskDomain) => <Chip color={DOMAIN_HEX[value]}>{t(`domain.${value}`)}</Chip>,
    },
    {
      title: t('rules.column.severity'),
      dataIndex: 'severity',
      width: 108,
      render: (_value, record) => <SeverityTag severity={record.severity} />,
    },
    {
      title: t('rules.column.rollout'),
      key: 'rollout',
      width: 224,
      render: (_value, record) => (
        <div className="agf-rule-slider" title={record.readOnly ? readOnlyHint : undefined}>
          <Slider
            style={{ flex: 1, minWidth: 120 }}
            min={0}
            max={100}
            step={5}
            value={rollout[record.id] ?? record.rolloutPercent}
            disabled={!canWrite || record.readOnly || !record.enabled || operation.busy}
            onChange={(value) => setRollout((prev) => ({ ...prev, [record.id]: value }))}
            onChangeComplete={(value) => void update(record, { rolloutPercent: value })}
            tooltip={{ formatter: (value) => `${value}%` }}
          />
          <span className="agf-mono" style={{ width: 42, textAlign: 'right' }}>
            {rollout[record.id] ?? record.rolloutPercent}%
          </span>
        </div>
      ),
    },
    {
      title: t('rules.column.version'),
      dataIndex: 'version',
      width: 148,
      render: (version: string, record) => (
        <Space size={6}>
          <span className="agf-mono" style={{ fontSize: 12 }}>
            {version}
          </span>
          <Chip
            color={
              record.lifecycle === 'ga'
                ? '#3dd68c'
                : record.lifecycle === 'gray'
                  ? '#f0cc6a'
                  : record.lifecycle === 'draft'
                    ? '#8b93a1'
                    : '#6f7683'
            }
          >
            {t(`status.${record.lifecycle}`)}
          </Chip>
        </Space>
      ),
    },
    {
      title: t('rules.column.enabled'),
      dataIndex: 'enabled',
      width: 96,
      render: (value: boolean, record) => (
        <Switch
          size="small"
          checked={value}
          loading={saving === record.id}
          disabled={!canWrite || record.readOnly || operation.busy}
          title={record.readOnly ? readOnlyHint : undefined}
          onChange={(next) => void update(record, { enabled: next })}
        />
      ),
    },
    {
      title: t('rules.column.hits'),
      dataIndex: 'hitCount24h',
      width: 118,
      align: 'right',
      render: (value: number) => formatNumber(value),
    },
    {
      title: t('rules.column.fpr'),
      dataIndex: 'falsePositiveRate',
      width: 132,
      align: 'right',
      render: (value: number) => (
        <span style={{ color: value > 0.2 ? 'var(--agf-danger)' : undefined }}>{formatPercent(value)}</span>
      ),
    },
    { title: t('rules.column.author'), dataIndex: 'author', width: 96 },
    {
      title: t('rules.column.updatedAt'),
      dataIndex: 'updatedAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('common.actions'),
      key: 'actions',
      fixed: 'right',
      width: 220,
      render: (_value, record) => <Space>
        <Button size="small" onClick={() => setEditing(record.id)}>{canWrite && !record.readOnly ? (zh ? '编辑 / 版本' : 'Edit / revisions') : (zh ? '查看 / 版本' : 'View / revisions')}</Button>
        <Button size="small" disabled={!canWrite || record.readOnly} title={!canWrite ? readOnlyHint : undefined}
          icon={<ExperimentOutlined />} onClick={() => setTestRule(record)}>{t('rules.test.button')}</Button>
      </Space>,
    },
  ];

  const sampleColumns: ColumnsType<RuleSample> = [
    {
      title: t('rules.test.column.label'),
      dataIndex: 'label',
      width: 110,
      render: (value: RuleSample['label']) => (
        <Tag color={value === 'positive' ? 'red' : 'green'}>
          {t(`rules.test.${value}`)}
        </Tag>
      ),
    },
    {
      title: t('rules.test.column.payload'),
      dataIndex: 'payload',
      width: 400,
      render: (value: string) => (
        <Tooltip title={value}>
          <span
            className="agf-mono"
            style={{
              fontSize: 11,
              display: 'inline-block',
              maxWidth: 390,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              verticalAlign: 'middle',
            }}
          >
            {value}
          </span>
        </Tooltip>
      ),
    },
    {
      title: t('rules.test.column.matched'),
      dataIndex: 'matched',
      width: 108,
      render: (value: boolean) =>
        value ? (
          <Tag color="red" style={{ marginInlineEnd: 0 }}>
            {t('rules.test.matched')}
          </Tag>
        ) : (
          <Tag style={{ marginInlineEnd: 0 }}>{t('rules.test.missed')}</Tag>
        ),
    },
    {
      title: t('rules.test.column.latency'),
      dataIndex: 'latencyMs',
      width: 104,
      align: 'right',
      render: (value: number) => <span className="agf-mono">{value.toFixed(1)} ms</span>,
    },
    { title: t('rules.test.column.note'), dataIndex: 'note', width: 230 },
  ];

  const result = testResult.data?.data;

  return (
    <>
      <DefinitionDetail kind="rule" />
      {editing !== null && <RuleEditor key={editing} ruleKey={editing} canWrite={canWrite} onClose={() => setEditing(null)} onSaved={() => void rules.refetch()} />}
      <PageHeader
        title={t('rules.title')}
        subtitle={t('rules.subtitle')}
        actions={
          <Space><CorrelationConsole /><Button disabled={!canWrite} title={!canWrite ? readOnlyHint : undefined}
            onClick={() => setEditing('')}>{zh ? '新建规则' : 'New rule'}</Button><Button icon={<ReloadOutlined />} onClick={() => void rules.refetch()}>
            {t('common.refresh')}
          </Button>
          </Space>
        }
      />

      {rules.data && !canWrite && <Alert style={{ marginBottom: 16 }} type="info" showIcon message={readOnlyHint} />}
      {error && <Alert style={{ marginBottom: 16 }} type="error" showIcon message={error} closable onClose={() => setError('')} />}
      <DataState loading={rules.isLoading} error={rules.error} onRetry={() => void rules.refetch()} skeletonRows={6}>
        <Input.Search aria-label={zh ? '搜索全部规则' : 'Search all rules'} placeholder={zh ? '搜索全部规则：名称、标识或描述' : 'Search all rules: name, key or description'} allowClear
          style={{ maxWidth: 480, marginBottom: 12 }} onSearch={(value) => { setKeyword(value); setPage(1); }} />
        <Table<Rule>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={rules.data?.data.items ?? []}
          scroll={{ x: 1980 }}
          onChange={(_, filters, __, extra) => { if (extra.action === 'filter') {
            setDomain(filters.domain?.[0]?.toString()); setPage(1);
          } }}
          pagination={{
            current: page, pageSize, total: rules.data?.data.total ?? 0,
            onChange: (next, size) => { setPage(size === pageSize ? next : 1); setPageSize(size); },
            showSizeChanger: true,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>

      <Drawer
        width={920}
        open={Boolean(testRule)}
        onClose={() => setTestRule(null)}
        title={t('rules.test.title', { name: testRule?.name ?? '' })}
        destroyOnClose
        extra={
          <Button
            type="primary"
            icon={<ExperimentOutlined />}
            loading={testResult.isFetching}
            disabled={!canWrite || testResult.isFetching}
            onClick={() => void testResult.refetch()}
          >
            {t('rules.test.run')}
          </Button>
        }
      >
        <DataState loading={testResult.isLoading} error={testResult.error}>
        {testRule ? (
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
              <Statistic
                title={t('rules.test.truePositive')}
                value={result?.truePositive ?? 0}
                valueStyle={{ color: 'var(--agf-danger)', fontSize: 20 }}
              />
              <Statistic
                title={t('rules.test.falseNegative')}
                value={result?.falseNegative ?? 0}
                valueStyle={{ color: 'var(--agf-warning)', fontSize: 20 }}
              />
              <Statistic
                title={t('rules.test.trueNegative')}
                value={result?.trueNegative ?? 0}
                valueStyle={{ color: 'var(--agf-success)', fontSize: 20 }}
              />
              <Statistic
                title={t('rules.test.falsePositive')}
                value={result?.falsePositive ?? 0}
                valueStyle={{ color: 'var(--agf-warning)', fontSize: 20 }}
              />
            </div>

            <Space size={8} wrap>
              <Tag className="agf-mono">{testRule.version}</Tag>
              <Chip color="#3d8bfd">{t(`domain.${testRule.domain}`)}</Chip>
              <span className="agf-muted">
                {result
                  ? t('rules.test.ranAt', { time: formatDateTime(result.ranAt, locale) })
                  : t('rules.test.running')}
              </span>
            </Space>

            <div>
              <div className="agf-drawer-section__title">{t('rules.rollout.slider')}</div>
              <Progress
                percent={rollout[testRule.id] ?? testRule.rolloutPercent}
                strokeColor="#3d8bfd"
                format={(value) => `${value}%`}
              />
              <Typography.Paragraph className="agf-tertiary" style={{ fontSize: 12 }}>
                {t('rules.rollout.hint')}
              </Typography.Paragraph>
            </div>

            <Table<RuleSample>
              rowKey="id"
              size="small"
              loading={testResult.isLoading}
              columns={sampleColumns}
              dataSource={result?.samples ?? []}
              pagination={false}
              scroll={{ x: 960 }}
            />
          </Space>
        ) : null}
        </DataState>
      </Drawer>
    </>
  );
}

import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Button,
  Checkbox,
  Col,
  Descriptions,
  Drawer,
  Form,
  InputNumber,
  Row,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { DownloadOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { ReportFormat, ReportJob, ReportSchedule } from '@/types/domain';
import { renderMarkdown } from '@/utils/markdown';
import { formatDateTime } from '@/utils/format';
import { downloadText } from '@/utils/download';
import { downloadArtifact } from '@/api/transport';
import { ReportSchedules } from './reports/ReportSchedules';
import { reportScheduleKey, reportTypeKey } from '@/utils/labels';
import { useAuthStore } from '@/stores/authStore';
import { callApi } from '@/api/transport';
import { useSessionAccess } from '@/api/sessionAccess';

const TYPES: ReportJob['type'][] = ['executive', 'compliance', 'asset-inventory', 'redteam', 'incident'];
const FORMATS: ReportFormat[] = ['pdf', 'markdown', 'html', 'csv', 'json'];
const SCHEDULES: ReportSchedule[] = ['manual'];

const STATUS_COLOR: Record<ReportJob['status'], string> = {
  ready: '#3dd68c',
  generating: '#3d8bfd',
  scheduled: '#f0cc6a',
  failed: '#ff8b90',
};

interface WizardValues {
  type: ReportJob['type'];
  windowDays: number;
  format: ReportFormat;
  schedule: ReportSchedule;
  recipients: string;
  modelAssisted?: boolean;
}

export default function ReportsPage() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <ReportsPanel key={`${tenant}:${generation}`} />;
}

function ReportsPanel() {
  const { t, i18n } = useTranslation();
  const scheduledLabel = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh') ? '定时计划' : 'Scheduled plan';
  const locale = useAppLocale();
  const access = useSessionAccess();
  const canAssist = access.has('models:write') && access.has('reports:read') && access.has('reports:write')
    && access.has('findings:read') && access.has('alerts:read');
  const [wizardOpen, setWizardOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [selected, setSelected] = useState<ReportJob | null>(null);
  const [generating, setGenerating] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [kind, setKind] = useState<string>();
  const [form] = Form.useForm<WizardValues>();

  const reports = useApiQuery('reports', () => api.reports({ page, pageSize, kind }), { key: [page, pageSize, kind] });

  const columns: ColumnsType<ReportJob> = [
    {
      title: t('reports.column.name'),
      dataIndex: 'name',
      width: 340,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Link onClick={() => setSelected(record)}>{name}</Typography.Link>
          {record.recipients.length > 0 && <span className="agf-tertiary" style={{ fontSize: 12 }}>
            {record.recipients.join(', ')}
          </span>}
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id}
          </span>
        </Space>
      ),
    },
    {
      title: t('reports.column.type'),
      dataIndex: 'type',
      width: 190,
      filterMultiple: false,
      filteredValue: kind ? [kind] : null,
      filters: TYPES.map((value) => ({ text: t(reportTypeKey(value)), value: value === 'executive' ? 'posture' : value })),
      render: (value: ReportJob['type']) => <Tag color="blue">{t(reportTypeKey(value))}</Tag>,
    },
    {
      title: t('reports.column.format'),
      dataIndex: 'format',
      width: 110,
      render: (value: ReportFormat) => <Tag className="agf-mono">{value.toUpperCase()}</Tag>,
    },
    {
      title: t('reports.column.schedule'),
      dataIndex: 'schedule',
      width: 150,
      render: (value: ReportSchedule, record) => (
        <Space direction="vertical" size={0}>
          <span>{record.scheduleId ? scheduledLabel : t(reportScheduleKey(value))}</span>
          <span className="agf-tertiary" style={{ fontSize: 11 }}>
            {t('reports.wizard.window')}: {record.windowDays}
          </span>
        </Space>
      ),
    },
    {
      title: t('reports.column.status'),
      dataIndex: 'status',
      width: 124,
      render: (value: ReportJob['status']) => (
        <Chip color={STATUS_COLOR[value]}>{t(`status.${value === 'ready' ? 'ready' : value}`)}</Chip>
      ),
    },
    {
      title: t('reports.column.size'),
      dataIndex: 'sizeKb',
      width: 112,
      align: 'right',
      render: (value: number) => (value > 0 ? `${value.toLocaleString()} KB` : '—'),
    },
    { title: t('reports.column.createdBy'), dataIndex: 'createdBy', width: 110 },
    {
      title: t('reports.column.createdAt'),
      dataIndex: 'createdAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('common.actions'),
      key: 'actions',
      fixed: 'right',
      width: 180,
      render: (_value, record) => (
        <Space size={4}>
          <Button size="small" type="link" onClick={() => setSelected(record)}>
            {t('common.preview')}
          </Button>
          <Button
            size="small"
            type="link"
            icon={<DownloadOutlined />}
            onClick={() => {
              const filename = `${record.name}.${record.format === 'markdown' ? 'md' : record.format}`;
              if (reports.data?.meta.source === 'demo') downloadText(filename, record.preview);
              else void downloadArtifact(`/api/v1/reports/${record.id}/download`, filename).catch(error => message.error(String(error)));
            }}
          >
            {t('common.download')}
          </Button>
        </Space>
      ),
    },
  ];


  return (
    <>
      <PageHeader
        title={t('reports.title')}
        subtitle={t('reports.subtitle')}
        actions={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => void reports.refetch()}>
              {t('common.refresh')}
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                setWizardOpen(true);
                setStep(0);
              }}
            >
              {t('reports.wizard.button')}
            </Button>
          </Space>
        }
      />

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <DataState loading={reports.isLoading} error={reports.error} skeletonRows={6}>
          <Table<ReportJob>
            rowKey="id"
            size="middle"
            columns={columns}
            dataSource={reports.data?.data?.items ?? []}
            scroll={{ x: 1620 }}
            onChange={(_, filters, __, extra) => { if (extra.action === 'filter') {
              setKind(filters.type?.[0]?.toString()); setPage(1);
            } }}
            pagination={{
              current: page, pageSize, total: reports.data?.data.total ?? 0,
              onChange: (next, size) => { setPage(size === pageSize ? next : 1); setPageSize(size); },
              showSizeChanger: true,
              showTotal: (total) => t('common.total', { count: total }),
            }}
          />
        </DataState>

        <Row gutter={[14, 14]}>
          <Col xs={24} xl={14}>
            <Panel
              title={t('reports.preview.title')}
              extra={
                selected ? (
                  <Tag className="agf-mono">{selected.format.toUpperCase()}</Tag>
                ) : null
              }
            >
              {selected ? (
                <div
                  className="agf-report"
                  // The renderer escapes all HTML before emitting markup.
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(selected.preview) }}
                />
              ) : (
                <Typography.Text className="agf-tertiary">{t('reports.preview.empty')}</Typography.Text>
              )}
            </Panel>
          </Col>
          <Col xs={24} xl={10}>
            <Panel title={t('reports.schedule.title')}>
              <ReportSchedules onGenerated={() => void reports.refetch()} />
            </Panel>
          </Col>
        </Row>
      </Space>

      <Drawer
        width={560}
        open={wizardOpen}
        onClose={() => setWizardOpen(false)}
        title={t('reports.wizard.title')}
        destroyOnClose
        extra={
          step === 3 ? (
            <Button
              type="primary"
              loading={generating}
              onClick={() => {
                void (async () => {
                  await form.validateFields();
                  // Earlier wizard steps are unmounted; include their preserved values.
                  const values = form.getFieldsValue(true) as WizardValues;
                  if (values.modelAssisted && !canAssist) {
                    message.error(i18n.language.startsWith('zh') ? '模型摘要需要模型和报表写入权限' : 'Model summaries require model and report write permission');
                    return;
                  }
                  const startedFor = useAuthStore.getState();
                  const current = () => useAuthStore.getState().tenant?.id === startedFor.tenant?.id
                    && useAuthStore.getState().sessionGeneration === startedFor.sessionGeneration;
                  setGenerating(true);
                  try {
                    if (values.modelAssisted) {
                      await callApi('/api/v1/reports', () => null as never, { noFallback: true, method: 'POST', timeoutMs: 45_000, body: {
                        kind: values.type === 'executive' ? 'posture' : values.type,
                        window_secs: values.windowDays * 86400, format: values.format, model_assisted: true,
                      } });
                    } else {
                      await api.generateReport({ type: values.type, windowDays: values.windowDays, format: values.format });
                    }
                    if (!current()) return;
                    message.success(t('reports.wizard.generated', { name: t(reportTypeKey(values.type)) }));
                    setWizardOpen(false);
                    setStep(0);
                    form.resetFields();
                    void reports.refetch();
                  } catch (error) {
                    if (current()) message.error(error instanceof Error ? error.message : t('common.error'));
                  } finally {
                    if (current()) setGenerating(false);
                  }
                })();
              }}
            >
              {t('common.generate')}
            </Button>
          ) : null
        }
      >
        <Steps
          size="small"
          current={step}
          style={{ marginBottom: 18 }}
          items={[
            { title: t('reports.wizard.step.type') },
            { title: t('reports.wizard.step.window') },
            { title: t('reports.wizard.step.format') },
            { title: t('reports.wizard.step.schedule') },
          ]}
        />
        <Form<WizardValues>
          form={form}
          layout="vertical"
          initialValues={{ type: 'executive', windowDays: 30, format: 'markdown', schedule: 'manual', modelAssisted: false }}
        >
          {step === 0 ? (
            <Form.Item name="type" label={t('reports.wizard.type')}>
              <Select options={TYPES.map((value) => ({ value, label: t(reportTypeKey(value)) }))} />
            </Form.Item>
          ) : null}
          {step === 1 ? (
            <Form.Item name="windowDays" label={t('reports.wizard.window')}>
              <InputNumber min={1} max={90} style={{ width: '100%' }} />
            </Form.Item>
          ) : null}
          {step === 2 ? (
            <>
              <Form.Item name="format" label={t('reports.wizard.format')}>
                <Select options={FORMATS.map((value) => ({ value, label: value.toUpperCase() }))} />
              </Form.Item>
              <Form.Item name="modelAssisted" valuePropName="checked">
                <Checkbox disabled={!canAssist}>
                  {i18n.language.startsWith('zh') ? '添加模型证据摘要（实际用量计费，Mock 会明确标注）' : 'Add a model evidence summary (metered usage; Mock is labelled)'}
                </Checkbox>
              </Form.Item>
              <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>{i18n.language.startsWith('zh')
                  ? '仅抽样审阅窗口内发现和告警的元数据；原始日志、提示词和载荷不发送给模型，不能独立验证攻击。'
                  : 'Samples finding and alert metadata in the window. Raw logs, prompts and payloads are excluded; this review cannot independently validate attacks.'}</Typography.Paragraph>
            </>
          ) : null}
          {step === 3 ? (
            <Space direction="vertical" size={10} style={{ width: '100%' }}>
              <Form.Item name="schedule" label={t('reports.wizard.schedule')}>
                <Select options={SCHEDULES.map((value) => ({ value, label: t(reportScheduleKey(value)) }))} />
              </Form.Item>
              <Typography.Text>周期执行请在下方“定时报表计划”面板创建，时间统一为 UTC。</Typography.Text>
              <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label={t('reports.wizard.type')}>
                  {t(reportTypeKey(form.getFieldValue('type') as ReportJob['type']))}
                </Descriptions.Item>
                <Descriptions.Item label={t('reports.wizard.window')}>
                  {String(form.getFieldValue('windowDays'))}
                </Descriptions.Item>
                <Descriptions.Item label={t('reports.wizard.format')}>
                  {String(form.getFieldValue('format')).toUpperCase()}
                </Descriptions.Item>
                <Descriptions.Item label={i18n.language.startsWith('zh') ? '模型证据摘要' : 'Model evidence summary'}>
                  {form.getFieldValue('modelAssisted') === true
                    ? (i18n.language.startsWith('zh') ? '已启用：实际用量计费，Mock 会明确标注' : 'Enabled: metered usage; Mock is labelled')
                    : (i18n.language.startsWith('zh') ? '未启用' : 'Disabled')}
                </Descriptions.Item>
              </Descriptions>
            </Space>
          ) : null}

          <Space style={{ marginTop: 12 }}>
            <Button disabled={step === 0} onClick={() => setStep((prev) => prev - 1)}>
              {t('common.prev')}
            </Button>
            {step < 3 ? (
              <Button
                type="primary"
                onClick={() => {
                  void form
                    .validateFields(step === 0 ? ['type'] : step === 1 ? ['windowDays'] : ['format'])
                    .then(() => setStep((prev) => prev + 1));
                }}
              >
                {t('common.next')}
              </Button>
            ) : null}
          </Space>
        </Form>
      </Drawer>
    </>
  );
}

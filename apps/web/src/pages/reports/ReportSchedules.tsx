import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, message } from 'antd';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { formatDateTime } from '@/utils/format';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { useAuthStore } from '@/stores/authStore';

interface Schedule {
  id: string; name: string; kind: string; format: string; cron: string; enabled: boolean;
  version: number; windowSecs: number; channelIds: string[];
  lastGeneratedAt?: string; lastReportId?: string; lastError?: string;
}
interface Values { name: string; kind: string; format: string; cron: string; windowDays: number; channelIds: string[] }
interface Channel { id: string; channel: string; enabled: boolean }
const empty = <T,>(): { items: T[] } => ({ items: [] });
const path = (row: Schedule) => '/api/v1/reports/schedules/' + row.id;

export function ReportSchedules(props: { onGenerated: () => void }) {
  const tenant = useAuthStore(state => state.tenant?.id);
  return <SchedulePanel key={tenant} {...props} />;
}

function SchedulePanel({ onGenerated }: { onGenerated: () => void }) {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Schedule>();
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState<string>();
  const [form] = Form.useForm<Values>();
  const locale = useAppLocale();
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const query = useApiQuery('report-schedules', () => callApi<{ items: Schedule[] }>(
    '/api/v1/reports/schedules', empty<Schedule>, { noFallback: true },
  ));
  const channels = useApiQuery('report-channels', () => callApi<{ items: Channel[] }>(
    '/api/v1/reports/channels', empty<Channel>, { noFallback: true },
  ));
  const names: Record<string, string> = { email: text('邮件', 'Email'), dingtalk: text('钉钉', 'DingTalk'),
    feishu: text('飞书', 'Feishu'), wecom: text('企业微信', 'WeCom'), sms: text('短信', 'SMS'),
    'in-app': text('站内消息', 'In-app'), webhook: 'Webhook', pagerduty: 'PagerDuty' };
  const channelLabel = (id: string) => {
    const row = channels.data?.data.items.find(channel => channel.id === id);
    return row ? names[row.channel] ?? row.channel : text('渠道不可用', 'Unavailable channel');
  };
  const perform = async (action: () => Promise<unknown>) => {
    setBusy(true); setOperationError(undefined);
    try { await action(); await query.refetch(); onGenerated(); }
    catch (error) { setOperationError(String(error)); }
    finally { setBusy(false); }
  };
  const begin = (row?: Schedule) => {
    setEditing(row); setOperationError(undefined); form.resetFields();
    form.setFieldsValue(row ? { name: row.name, kind: row.kind, format: row.format,
      cron: row.cron, windowDays: row.windowSecs / 86400, channelIds: row.channelIds ?? [] }
      : { name: '', kind: 'posture', format: 'pdf', cron: '0 0 * * *', windowDays: 1, channelIds: [] });
    setOpen(true); void channels.refetch();
  };
  const save = async () => {
    let values: Values;
    try { values = await form.validateFields(); } catch { return; }
    await perform(async () => {
      await callApi(editing ? path(editing) : '/api/v1/reports/schedules', () => null, {
        method: editing ? 'PATCH' : 'POST', noFallback: true, body: {
          name: values.name, kind: values.kind, format: values.format, cron: values.cron,
          window_secs: Math.round(values.windowDays * 86400), channel_ids: values.channelIds,
          ...(editing ? { expected_version: editing.version } : {}),
        },
      });
      setOpen(false); form.resetFields();
      message.success(text('计划已保存，按 UTC 时间自动生成报表', 'Schedule saved; reports run in UTC'));
    });
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('计划使用 UTC 时间。主服务每 15 秒检查一次；停机期间的周期不补跑。',
      'Schedules use UTC. The server checks every 15 seconds; missed periods during downtime are not replayed.')}
      description={text('可立即生成验证内容。暂停和编辑保留历史报表。通知发送下载提示，文件需登录后下载。',
        'Run now to verify content. Editing or pausing preserves past reports. Notifications announce availability; downloads require sign-in.')} />
    {query.error && <Alert type="error" message={String(query.error)} />}
    {!open && operationError && <Alert type="error" message={operationError} />}
    <Space>
      <Button onClick={() => begin()} disabled={busy}>{text('新建定时计划', 'New schedule')}</Button>
      <Button onClick={() => void query.refetch()} loading={query.isFetching} disabled={busy}>{text('刷新计划', 'Refresh plans')}</Button>
    </Space>
    <Table<Schedule> rowKey="id" size="small" loading={busy || query.isLoading} dataSource={query.data?.data.items ?? []}
      scroll={{ x: 1050 }} columns={[
        { title: text('名称', 'Name'), dataIndex: 'name' },
        { title: text('UTC 时间规则', 'UTC cron'), dataIndex: 'cron' },
        { title: text('格式', 'Format'), dataIndex: 'format' },
        { title: text('通知渠道', 'Notifications'), render: (_, row) => (row.channelIds ?? []).map(channelLabel).join(', ') || text('仅保存报表', 'Save only') },
        { title: text('最近生成', 'Last generated'), render: (_, row) => row.lastGeneratedAt ? formatDateTime(row.lastGeneratedAt, locale) : text('尚未执行', 'Not run') },
        { title: text('状态', 'Status'), render: (_, row) => <Space direction="vertical">
          <Switch aria-label={text('启用计划 ', 'Enable schedule ') + row.name} checked={row.enabled} disabled={busy}
            onChange={(enabled) => void perform(() => callApi(path(row), () => null, {
              method: 'PATCH', noFallback: true, body: { enabled, expected_version: row.version },
            }))} />{row.lastError && <span role="alert">{row.lastError}</span>}</Space> },
        { title: text('操作', 'Actions'), render: (_, row) => <Space>
          <Button size="small" disabled={busy} onClick={() => begin(row)}>{text('编辑', 'Edit')}</Button>
          <Button size="small" disabled={busy} onClick={() => void perform(async () => {
            await callApi(path(row) + '/run', () => null, { method: 'POST', noFallback: true });
            message.success(text('报表已生成，可在列表下载', 'Report generated; download it from the list'));
          })}>{text('立即生成', 'Run now')}</Button>
          <Popconfirm title={text('删除此计划？已生成的报表会保留。', 'Delete this schedule? Past reports are retained.')}
            onConfirm={() => perform(() => callApi(path(row), () => null, {
              method: 'DELETE', noFallback: true, query: { expected_version: row.version },
            }))}>
            <Button size="small" danger disabled={busy}>{text('删除', 'Delete')}</Button>
          </Popconfirm>
        </Space> },
      ]} />
    <Modal title={editing ? text('编辑定时报表', 'Edit report schedule') : text('新建定时报表', 'New report schedule')}
      open={open} onCancel={() => { if (!busy) setOpen(false); }} onOk={() => void save()}
      okText={text('保存', 'Save')} cancelText={text('取消', 'Cancel')} confirmLoading={busy}>
      <Form form={form} layout="vertical">
        {operationError && <Alert type="error" showIcon message={operationError} />}
        <Form.Item name="name" label={text('计划名称', 'Schedule name')} rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
        <Form.Item name="kind" label={text('内容', 'Content')} rules={[{ required: true }]}><Select options={[
          { value: 'posture', label: text('安全态势', 'Security posture') }, { value: 'findings', label: text('风险发现', 'Findings') },
          { value: 'asset-inventory', label: text('资产盘点', 'Asset inventory') }, { value: 'incident', label: text('告警与案件', 'Alerts and cases') },
          { value: 'compliance', label: text('合规', 'Compliance') }, { value: 'redteam', label: text('红队', 'Red team') },
          { value: 'drift', label: text('变更漂移', 'Drift') }, { value: 'billing', label: text('成本', 'Billing') },
          { value: 'custom', label: text('自定义', 'Custom') },
        ]} /></Form.Item>
        <Form.Item name="format" label={text('格式', 'Format')} rules={[{ required: true }]}><Select options={['pdf', 'markdown', 'html', 'csv', 'json'].map(value => ({ value, label: value.toUpperCase() }))} /></Form.Item>
        <Form.Item name="windowDays" label={text('统计窗口（天）', 'Window (days)')} rules={[{ required: true }]}><InputNumber min={1 / 1440} max={90} /></Form.Item>
        <Form.Item name="cron" label={text('UTC cron（分 时 日 月 周）', 'UTC cron (minute hour day month weekday)')} rules={[{ required: true }]}
          extra={text('0 0 * * *：每日 UTC 00:00（北京时间 08:00）；0 0 * * MON：每周一。', '0 0 * * *: daily at 00:00 UTC; 0 0 * * MON: every Monday.')}><Input /></Form.Item>
        {channels.error && <Alert type="error" message={text('渠道加载失败，请重试或只保存报表', 'Channels could not load; retry or save without notifications')} />}
        <Form.Item name="channelIds" label={text('通知渠道（可选）', 'Notification channels (optional)')}
          extra={text('先在设置 → 通知渠道配置并测试收件人。留空仅保存报表。', 'Configure and test recipients in Settings → Notifications first. Leave empty to save reports only.')}>
          <Select mode="multiple" allowClear loading={channels.isLoading} options={(channels.data?.data.items ?? []).map(channel => ({
            value: channel.id, disabled: !channel.enabled,
            label: (names[channel.channel] ?? channel.channel) + (channel.enabled ? '' : text('（已停用）', ' (disabled)')),
          }))} />
        </Form.Item>
        {editing && <Alert type="info" message={text('若其他人已修改计划，保存会提示冲突。关闭后刷新列表再编辑。',
          'Concurrent edits are rejected. Close this form, refresh the list, and reopen it if a conflict occurs.')} />}
      </Form>
    </Modal>
  </Space>;
}

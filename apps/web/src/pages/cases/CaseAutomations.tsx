import { useState } from 'react';
import { Alert, Button, Collapse, Drawer, Input, Space, Table, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { automationsApi, type Automation, type TriggerDelivery } from '@/api/soarAutomations';
import { useAuthStore } from '@/stores/authStore';
import AutomationEditor from './AutomationEditor';

export default function CaseAutomations() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <AutomationPanel key={`${tenant ?? 'none'}:${generation}`} />;
}

function AutomationPanel() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState('');
  const [editor, setEditor] = useState<{item?: Automation}>();
  const [selected, setSelected] = useState<Automation>();
  const [deliveryPage, setDeliveryPage] = useState(1);
  const [deliveryKeyword, setDeliveryKeyword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const list = useApiQuery('soar-automations', () => automationsApi.list(page, keyword), { key: [page, keyword], refetchInterval: 10_000 });
  const records = useApiQuery('soar-trigger-records', () => automationsApi.deliveries(selected?.id ?? '', deliveryPage, deliveryKeyword),
    { key: [selected?.id, deliveryPage, deliveryKeyword], enabled: Boolean(selected), refetchInterval: 5000 });
  const data = list.data?.data;
  const detail = useApiQuery('soar-automation-history', () => automationsApi.get(selected?.id ?? ''), {key: [selected?.id], enabled: Boolean(selected)});
  const retry = async (row: TriggerDelivery) => {
    if (!selected) return;
    setBusy(row.id); setError('');
    try { await automationsApi.retry(selected.id, row.id, selected.version); await records.refetch(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(''); }
  };
  const status = (key: string) => ({ submitted: text('已提交任务', 'Run submitted'), skipped: text('已跳过', 'Skipped'), failed: text('触发失败', 'Trigger failed'), pending: text('待重新评估', 'Pending review') }[key] ?? key);
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Collapse defaultActiveKey={['guide']} items={[{ key: 'guide', label: text('自动响应操作指南', 'Automatic response guide'), children: <>
      <Typography.Paragraph>{text('1. 选择隔离 Agent、封禁域名或吊销平台密钥模板，填写目标和最低告警等级。个人可先保留人工审批；企业可启用另一位管理员复核。', '1. Choose an Agent isolation, domain blocking or platform key revocation template. Set the target and minimum severity. Start with approval enabled; enterprises can require a second administrator.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('2. 用当前租户的一条告警做匹配预览，核对关联资产、规则键和步骤。预览不执行动作，也不创建案件。复杂条件与多步骤可使用高级 YAML。', '2. Preview against an alert in this tenant. Review linked assets, rule keys and steps. Preview performs no actions and creates no cases. Use advanced YAML for complex conditions or multiple steps.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('3. 保存并启用；只处理启用后新建的告警。同一告警重复上报、改版或重启不会再次自动执行。停用期间的新告警不补跑。', '3. Save and enable. Only newly created alerts are evaluated. Repeated occurrences, revisions and restarts do not execute the same alert again. Alerts created while disabled are not backfilled.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('4. 查看触发记录，进入关联案件审批并核对实际结果。停用配置只停止新触发；已经提交的任务需要在案件内取消。失败记录可在同一配置版本下明确重试。', '4. Open trigger records and follow the case link to approve and inspect results. Disabling stops new submissions. Cancel existing runs in their cases. Failed evaluations can be retried explicitly against the same configuration revision.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('权限：人工账号需要 cases:admin 与 alerts:read。系统按发布者当前权限重新校验；离职、停用或权限撤销后不再以旧权限执行。每租户最多 50 个配置，保留最近 20 个配置版本。', 'Permissions: a human account needs cases:admin and alerts:read. Current publisher permissions are rechecked, including account disablement and role removal. Each tenant supports 50 configurations with the latest 20 revisions.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('已停用的配置也占用 50 个名额；停用不会释放容量。达到上限后可在列表选择“编辑 / 启停”修改已有配置。保存失败保留草稿，不会自动提交或启用。', 'Disabled configurations still occupy one of the 50 slots. Disabling does not free capacity. At the limit, choose “Edit / enable” on an existing configuration. Failed saves keep your draft and do not submit or enable it automatically.')}</Typography.Paragraph>
    </> }]} />
    <Space wrap><Button type="primary" disabled={!data?.canManage} onClick={() => setEditor({})}>{text('新建自动响应', 'New automatic response')}</Button>
      <Button onClick={() => void list.refetch()}>{text('刷新配置', 'Refresh configurations')}</Button>
      <Input.Search aria-label={text('搜索自动响应', 'Search automations')} placeholder={text('名称或剧本键', 'Name or playbook key')} allowClear onSearch={value => { setKeyword(value); setPage(1); }} /></Space>
    {list.error && <Alert type="error" message={String(list.error)} />}
    {data && !data.durable && <Alert type="warning" message={text('内存演示模式：重启会清空配置与触发记录。正式使用请配置 PostgreSQL。', 'Memory demo mode: restart clears configurations and records. Configure PostgreSQL for persistent operation.')} />}
    <Table rowKey="id" size="small" loading={list.isLoading} dataSource={data?.items ?? []}
      pagination={{ current: page, pageSize: 10, total: data?.total ?? 0, onChange: setPage, showSizeChanger: false }} columns={[
        { title: text('自动响应', 'Automatic response'), render: (_, row: Automation) => <Space direction="vertical"><Typography.Text strong>{row.playbook.name}</Typography.Text><Typography.Text type="secondary">{row.playbook.key} · v{row.version}</Typography.Text></Space> },
        { title: text('状态', 'Status'), render: (_, row) => <Tag color={row.enabled ? 'green' : undefined}>{row.enabled ? text('已启用', 'Enabled') : text('已停用', 'Disabled')}</Tag> },
        { title: text('生效起点', 'New alerts since'), dataIndex: 'since' },
        { title: text('操作', 'Actions'), render: (_, row) => <Space><Button disabled={!data?.canManage} onClick={() => setEditor({ item: row })}>{text('编辑 / 启停', 'Edit / enable')}</Button>
          <Button onClick={() => { setSelected(row); setDeliveryPage(1); setDeliveryKeyword(''); setError(''); }}>{text('触发与版本记录', 'Triggers and revisions')}</Button></Space> },
      ]} scroll={{ x: 900 }} />
    {editor && <AutomationEditor item={editor.item} onClose={() => setEditor(undefined)} onSaved={() => { setEditor(undefined); void list.refetch(); }} />}
    <Drawer width={1100} title={selected?.playbook.name} open={Boolean(selected)} onClose={() => setSelected(undefined)}>
      <Space direction="vertical" style={{ width: '100%' }}>
        {error && <Alert type="error" message={error} />}
        {records.error && <Alert type="error" message={String(records.error)} />}
        {detail.error && <Alert type="error" message={String(detail.error)} />}
        <Input.Search key={selected?.id} allowClear placeholder={text('搜索告警、状态或原因', 'Search alert, status or reason')} onSearch={value => { setDeliveryKeyword(value); setDeliveryPage(1); }} />
        <Table size="small" rowKey="id" dataSource={records.data?.data.items ?? []} loading={records.isLoading}
          expandable={{ expandedRowRender: row => <Space direction="vertical">{row.history?.map((entry, index) => <Typography.Paragraph key={index}>
            {entry.at} · {entry.actor} · {status(entry.status)}: {entry.reason}</Typography.Paragraph>)}</Space> }}
          pagination={{ current: deliveryPage, pageSize: 10, total: records.data?.data.total ?? 0, showSizeChanger: false, onChange: setDeliveryPage }} columns={[
            { title: text('告警', 'Alert'), dataIndex: 'alertTitle' },
            { title: text('状态 / 原因', 'Status / reason'), render: (_, row: TriggerDelivery) => <Space direction="vertical"><Tag>{status(row.status)} · v{row.automationVersion}</Tag><span>{row.reason}</span></Space> },
            { title: text('处理', 'Follow up'), render: (_, row) => <Space direction="vertical">
              {row.caseId && <Link to={`/cases/${encodeURIComponent(row.caseId)}`} onClick={() => setSelected(undefined)}>{text('打开案件及执行记录', 'Open case and runs')}</Link>}
              {row.status === 'failed' && data?.canManage && <Button loading={busy === row.id} disabled={!selected?.enabled || selected.version !== row.automationVersion} onClick={() => void retry(row)}>{text('重新评估触发', 'Retry evaluation')}</Button>}
              <Typography.Text type="secondary">{row.at} · {text('次数', 'Attempts')} {row.attempts}</Typography.Text>
            </Space> },
          ]} />
        <Typography.Title level={5}>{text('配置历史（最近 20 版）', 'Configuration history (latest 20)')}</Typography.Title>
        <Table size="small" rowKey="version" dataSource={[...(detail.data?.data.automation.history ?? [])].reverse()} loading={detail.isLoading} pagination={{pageSize: 5}} columns={[
          { title: text('版本', 'Revision'), dataIndex: 'version' }, { title: text('变更说明', 'Change reason'), dataIndex: 'note' },
          { title: text('操作者', 'Actor'), dataIndex: 'actor' }, { title: text('时间', 'Time'), dataIndex: 'at' },
        ]} expandable={{expandedRowRender: row => <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(row.playbook, null, 2)}</pre>}} />
      </Space>
    </Drawer>
  </Space>;
}

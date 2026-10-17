import { Alert, Button, Descriptions, Drawer, Form, Input, InputNumber, Modal, Space, Table, Tag, Typography, message } from 'antd';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { api, useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { campaign as adaptCampaign } from '@/api/adapters/governance';
import { useScopedOperation } from '@/components/useScopedOperation';
import { DataState } from '@/components/DataState';
import type { Campaign, CampaignResult } from '@/types/domain';
import { downloadText } from '@/utils/download';
import { renderMarkdown } from '@/utils/markdown';
import { categoryLabel, terminal } from './redteam.data';
import type { AgentTargetProfile } from './AgentTargetsPanel';
import type { McpTargetProfile } from './McpTargetsPanel';

export function CampaignDetailDrawer({ selectedId, canExecute, canUseAgentTarget, canUseMcpTarget = false, onClose, onRetest }: {
  selectedId: string; canExecute: boolean; canUseAgentTarget: boolean; canUseMcpTarget?: boolean; onClose: () => void; onRetest: (id: string) => void;
}) {
  const { t, i18n } = useTranslation(); const zh = i18n.language.startsWith('zh');
  const operation = useScopedOperation(); const [retest, setRetest] = useState(false);
  const path = '/api/v1/redteam/campaigns/' + selectedId;
  const detail = useApiQuery('campaign-detail', async () => {
    const response = await callApi<{ campaign: Record<string, unknown> }>(path, () => null as never, { noFallback: true });
    return { ...response, data: adaptCampaign(response.data.campaign) as unknown as Campaign };
  }, { key: [selectedId], refetchInterval: 3000 });
  const selected = detail.data?.data;
  const done = selected && terminal(selected);
  const results = useApiQuery('campaign-results', () => api.campaignResults(selectedId), { key: [selectedId, done], enabled: Boolean(done) });
  const report = useApiQuery('campaign-report', () => api.campaignReport(selectedId), { key: [selectedId, done], enabled: Boolean(done) });
  const targets = useApiQuery('retest-agent-targets', () => callApi<{ items: AgentTargetProfile[] }>(
    '/api/v1/redteam/agent-targets', () => ({ items: [] }), { noFallback: true }),
  { enabled: retest && selected?.executionMode === 'agent-http' && canUseAgentTarget });
  const mcpTargets = useApiQuery('retest-mcp-targets', () => callApi<{ items: McpTargetProfile[] }>(
    '/api/v1/redteam/mcp-targets', () => ({ items: [] }), { noFallback: true }),
  { enabled: retest && selected?.executionMode === 'mcp-http' && canUseMcpTarget });
  const currentTarget = (selected?.executionMode === 'mcp-http' ? mcpTargets.data?.data.items : targets.data?.data.items)
    ?.find(item => item.id === selected?.targetProfileId);
  const perform = (action: (current: () => boolean) => Promise<void>) => operation.run(async current => {
    try { await action(current); } catch (error) { if (current()) void message.error(error instanceof Error ? error.message : String(error)); }
  });
  const cancel = () => perform(async current => {
    await callApi(path + '/cancel', () => null, { method: 'POST', body: {}, noFallback: true });
    if (current()) await detail.refetch();
  });
  const launchRetest = (values: { name: string; guardStrength?: number }) => perform(async current => {
    if (selected?.executionMode !== 'simulator' && !currentTarget?.enabled) {
      throw new Error(zh ? '目标已删除或停用，请先刷新目标配置' : 'Target removed or disabled; refresh its configuration');
    }
    const response = await callApi<{ taskId: string }>(path + '/retest', () => null as never, {
      method: 'POST', body: selected?.executionMode !== 'simulator'
        ? { name: values.name, target_profile_version: currentTarget!.version }
        : { name: values.name, guard_strength: values.guardStrength }, noFallback: true,
    });
    if (current()) { setRetest(false); onRetest(response.data.taskId); }
  });
  const exportEvidence = () => perform(async current => {
    const response = await callApi(path + '/evidence', () => null, { noFallback: true, opaqueKeys: ['record'] });
    if (current()) downloadText('redteam-' + selectedId + '.json', JSON.stringify(response.data, null, 2));
  });
  return <Drawer open width={1100} onClose={onClose} title={selected?.name ?? (zh ? '战役详情' : 'Campaign details')}>
    <DataState loading={detail.isLoading} error={detail.error}>
      {selected && <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Space wrap>
          <Tag color="blue">{selected.executionMode === 'simulator' ? (zh ? '模拟结果' : 'Simulated result') : selected.executionMode === 'agent-http' ? (zh ? '真实 Agent 端点' : 'Real Agent endpoint') : selected.executionMode === 'mcp-http' ? (zh ? '真实 MCP 端点' : 'Real MCP endpoint') : (zh ? '历史模式未知' : 'Historical mode unknown')}</Tag>
          <Typography.Text code copyable>{selected.id}</Typography.Text>
          <Button onClick={() => { void detail.refetch(); void results.refetch(); void report.refetch(); }}>{t('common.refresh')}</Button>
          {canExecute && !done && <Button danger loading={operation.busy} onClick={() => void cancel()}>{zh ? '取消任务' : 'Cancel task'}</Button>}
          {canExecute && done && (selected.executionMode === 'simulator' || (selected.executionMode === 'agent-http' && canUseAgentTarget) || (selected.executionMode === 'mcp-http' && canUseMcpTarget)) &&
            <Button disabled={operation.busy} onClick={() => setRetest(true)}>{zh ? '复测原用例' : 'Retest saved cases'}</Button>}
          <Button loading={operation.busy} onClick={() => void exportEvidence()}>{zh ? '下载证据 JSON' : 'Download evidence JSON'}</Button>
          <Button disabled={!report.data?.data?.markdown} onClick={() => downloadText('redteam-' + selectedId + '.md', report.data?.data?.markdown ?? '')}>{zh ? '下载 Markdown 报告' : 'Download Markdown report'}</Button>
          {done && results.data?.data?.some(row => row.findingId && !row.mocked) &&
            <Link to={'/alerts?q=' + encodeURIComponent('redteam:' + selected.id + ':')} target="_blank" rel="noreferrer">
              {zh ? '查看关联告警与案件' : 'View linked alerts and cases'}
            </Link>}
        </Space>
        {selected.error && <Alert type="error" message={selected.error} />}
        <Descriptions column={2} bordered size="small" items={[
          { key: 'target', label: selected.executionMode === 'simulator' ? (zh ? '模拟目标' : 'Simulator target') : (zh ? '真实目标' : 'Real target'), children: selected.targetName || '—' },
          { key: 'guard', label: zh ? '防护参数' : 'Guard parameter', children: selected.guardStrength ?? '—' },
          { key: 'count', label: zh ? '已执行 / 总数' : 'Executed / total', children: (selected.executedCases ?? 0) + ' / ' + selected.totalCases },
          { key: 'success', label: zh ? '攻击得逞' : 'Successful attacks', children: selected.succeeded },
          { key: 'coverage', label: zh ? '已判定 / 无法判定 / 执行失败' : 'Evaluated / inconclusive / execution errors',
            children: [selected.evaluatedCases, selected.inconclusiveCases, selected.failedCases].map(value => value ?? '—').join(' / ') },
          { key: 'threshold', label: zh ? 'CI 严重等级门槛' : 'CI severity threshold', children: t('severity.' + selected.severityThreshold) },
          { key: 'ci', label: 'CI', children: !selected.ciGateEnabled ? t('common.disabled') : typeof selected.ciPassed !== 'boolean' ? (zh ? '尚无结论' : 'Pending') : selected.ciPassed ? (zh ? '通过' : 'Passed') : (zh ? '未通过' : 'Failed') },
        ]} />
        {selected.retestOf && <Typography.Link onClick={() => onRetest(selected.retestOf!)}>{zh ? '查看原战役：' : 'Baseline: '}{selected.retestOf}</Typography.Link>}
        {selected.comparison && <Alert type="info" message={selected.comparison.simulated === false
          ? (zh ? '复测对比（真实目标）' : 'Retest comparison (real target)')
          : (zh ? '复测对比（模拟）' : 'Retest comparison (simulated)')} description={selected.comparison.comparable
          ? (zh ? '本次未再成功 / 仍成功 / 新增成功：' : 'No longer succeeded / Still succeeded / New successes: ') + [selected.comparison.resolved.length, selected.comparison.persistent.length, selected.comparison.regressed.length].join(' / ')
          : (zh ? '原战役未完成，不计算改善结论。' : 'The baseline did not complete; no improvement conclusion is available.')} />}
        {Boolean(selected.comparison?.unassessed?.length) && <Alert type="warning" message={
          (zh ? '以下用例没有可比结论：' : 'No comparable assessment for: ') + selected.comparison!.unassessed!.join(', ')} />}
        {!done && <Alert type="info" message={zh ? '任务执行中，每 3 秒刷新；关闭页面不会取消任务。' : 'Task in progress; refreshed every 3 seconds. Closing the page does not cancel it.'} />}
        {done && <DataState loading={results.isLoading} error={results.error}>
          <Table<CampaignResult> rowKey="id" dataSource={results.data?.data ?? []} size="small" pagination={{ pageSize: 10 }}
            expandable={{ expandedRowRender: row => <Space direction="vertical" style={{ width: '100%' }}>
              <Typography.Text copyable>{row.evidenceRef}</Typography.Text>
              {row.evaluationNote && <Alert showIcon type="warning" message={row.evaluationNote} />}
              <pre className="agf-code">{JSON.stringify(row.transcript ?? [], null, 2)}</pre>
            </Space> }} columns={[
              { title: zh ? '用例' : 'Case', dataIndex: 'caseId' },
              { title: zh ? '类别' : 'Category', render: (_, row) => categoryLabel(row.category, zh) },
              { title: zh ? '严重等级' : 'Severity', render: (_, row) => t('severity.' + row.severity) },
              { title: zh ? '结果' : 'Outcome', render: (_, row) => (row.mocked ? (zh ? '模拟：' : 'Simulated: ') : '') + (row.outcome === 'inconclusive' ? (zh ? '无法判定' : 'Inconclusive') : row.outcome === 'execution-error' ? (zh ? '执行失败' : 'Execution error') : row.outcome === 'blocked' ? (zh ? '未观测到成功信号' : 'No success signal observed') : (zh ? '命中成功信号' : 'Success signal observed')) },
              { title: zh ? '命中信号' : 'Matched signals', render: (_, row) => row.matchedSignals?.join(', ') || '—' },
              { title: zh ? '风险发现' : 'Finding', render: (_, row) => row.findingId && !row.mocked
                ? <Link to={'/findings?finding=' + encodeURIComponent(row.findingId)} target="_blank" rel="noreferrer">{zh ? '待复核发现' : 'Review finding'}</Link>
                : '—' },
            ]} />
        </DataState>}
        {done && <DataState loading={report.isLoading} error={report.error}>
          {report.data?.data?.markdown ? <div className="agf-report" dangerouslySetInnerHTML={{ __html: renderMarkdown(report.data.data.markdown) }} />
            : <Typography.Text>{zh ? '该任务没有已完成报告。' : 'This task has no completed report.'}</Typography.Text>}
        </DataState>}
      </Space>}
    </DataState>
    <Modal open={retest} onCancel={() => setRetest(false)} footer={null} destroyOnClose title={zh ? '复测原用例' : 'Retest saved cases'}>
      <Typography.Paragraph>{selected?.executionMode !== 'simulator'
        ? (zh ? '使用原用例、同一资产和当前目标配置版本重新执行真实请求；保留原结果和 CI 门槛。' : 'Repeat real requests with saved cases, the same asset and current target revision. The baseline and CI threshold remain.')
        : (zh ? '使用原战役保存的用例、模拟目标和 CI 门槛；仅调整名称和模拟防护参数。保留原结果。' : 'Reuse saved cases, simulator target and CI threshold. Only the name and guard parameter change; the original results remain.')}</Typography.Paragraph>
      {selected?.executionMode !== 'simulator' && <DataState loading={selected?.executionMode === 'mcp-http' ? mcpTargets.isLoading : targets.isLoading} error={selected?.executionMode === 'mcp-http' ? mcpTargets.error : targets.error}>
        <Typography.Text>{currentTarget?.enabled
          ? `${currentTarget.name} · v${currentTarget.version}`
          : (zh ? '目标已删除或停用，无法复测。' : 'Target removed or disabled; retest unavailable.')}</Typography.Text>
      </DataState>}
      <Form layout="vertical" disabled={operation.busy} initialValues={{ name: (selected?.name ?? '') + (zh ? ' 复测' : ' retest'), guardStrength: selected?.guardStrength ?? 30 }} onFinish={values => void launchRetest(values)}>
        <Form.Item name="name" label={zh ? '复测名称' : 'Retest name'} rules={[{ required: true, whitespace: true }]}><Input maxLength={100} /></Form.Item>
        {selected?.executionMode === 'simulator' && <Form.Item name="guardStrength" label={zh ? '模拟防护强度' : 'Simulated guard strength'} rules={[{ required: true }]}><InputNumber min={0} max={100} precision={0} /></Form.Item>}
        <Button type="primary" htmlType="submit" loading={operation.busy} disabled={selected?.executionMode !== 'simulator' && !currentTarget?.enabled}>{zh ? '提交复测' : 'Submit retest'}</Button>
      </Form>
    </Modal>
  </Drawer>;
}

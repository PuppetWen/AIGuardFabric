import { Alert, Button, Drawer, Form, Input, InputNumber, Select, Switch, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { callApi } from '@/api/transport';
import { useApiQuery } from '@/api/client';
import { useScopedOperation } from '@/components/useScopedOperation';
import { CATEGORIES, SEVERITIES, type WizardValues } from './redteam.data';
import type { AgentTargetProfile } from './AgentTargetsPanel';
import type { McpTargetProfile } from './McpTargetsPanel';

export function CampaignWizard({ open, canUseAgentTarget, canUseMcpTarget = false, onClose, onSubmitted }: {
  open: boolean; canUseAgentTarget: boolean; canUseMcpTarget?: boolean; onClose: () => void; onSubmitted: (id: string) => void;
}) {
  const { t, i18n } = useTranslation(); const zh = i18n.language.startsWith('zh');
  const operation = useScopedOperation();
  const [form] = Form.useForm<WizardValues>();
  const mode = Form.useWatch('executionMode', form) ?? 'simulator';
  const targets = useApiQuery('wizard-agent-targets', () => callApi<{ items: AgentTargetProfile[] }>(
    '/api/v1/redteam/agent-targets', () => ({ items: [] }), { noFallback: true }), { enabled: open && mode === 'agent-http' });
  const mcpTargets = useApiQuery('wizard-mcp-targets', () => callApi<{ items: McpTargetProfile[] }>(
    '/api/v1/redteam/mcp-targets', () => ({ items: [] }), { noFallback: true }), { enabled: open && mode === 'mcp-http' });
  const cases = useApiQuery('wizard-agent-cases', () => callApi<{ items: { key: string; title: string }[] }>(
    '/api/v1/redteam/cases', () => ({ items: [] }), { noFallback: true,
      query: mode === 'mcp-http' ? { mcp_http_compatible: true, page_size: 100 }
        : { agent_http_compatible: true, page_size: 100 } }), { enabled: open && mode !== 'simulator', key: [mode] });
  const submit = (values: WizardValues) => operation.run(async current => {
    try {
      const real = values.executionMode !== 'simulator';
      const profile = (values.executionMode === 'mcp-http' ? mcpTargets.data?.data.items : targets.data?.data.items)
        ?.find(item => item.id === values.targetProfileId && item.enabled);
      if (real && !profile) throw new Error(zh ? '请选择已启用的目标' : 'Select an enabled target');
      if (values.executionMode === 'mcp-http' && values.caseKeys?.includes('RT-MCP-003')) {
        const mcp = profile as McpTargetProfile | undefined;
        if (!mcp?.detailToolName || !mcp.detailArgumentName) {
          throw new Error(zh ? '跨工具用例需要先配置只读详情工具和参数' : 'Configure a read-only detail tool and argument before running the cross-tool case');
        }
      }
      const response = await callApi<{ taskId: string }>('/api/v1/redteam/campaigns', () => null as never, {
        method: 'POST', noFallback: true, body: {
          name: values.name, ci_gate: values.ciGateEnabled, severity_threshold: values.severityThreshold,
          ...(real ? {
            execution_mode: values.executionMode, target_profile_id: profile!.id, target_profile_version: profile!.version,
            case_keys: values.caseKeys ?? [], max_cases: values.caseKeys?.length ?? 0,
          } : {
            execution_mode: 'simulator', categories: values.categories, target_name: values.targetName,
            guard_strength: values.guardStrength, max_cases: values.maxCases,
          }),
        },
      });
      if (current()) { onSubmitted(response.data.taskId); onClose(); }
    } catch (error) { if (current()) void message.error(error instanceof Error ? error.message : String(error)); }
  });
  return <Drawer open={open} onClose={onClose} width={560} destroyOnClose title={zh ? '发起红队战役' : 'Launch red-team campaign'}>
    <Alert type="info" showIcon style={{ marginBottom: 18 }} message={mode === 'simulator' ? (zh ? '本地确定性模拟' : 'Local deterministic simulation') : mode === 'mcp-http' ? (zh ? '真实 MCP 只读检测' : 'Real read-only MCP probe') : (zh ? '真实 Agent 端点' : 'Real Agent endpoint')}
      description={mode === 'simulator'
        ? (zh ? '不连接真实资产；模拟成功不会生成真实风险发现。' : 'Does not contact real assets; simulated results are not confirmed findings.')
        : mode === 'mcp-http'
          ? (zh ? '可选一次查询、同工具两步或跨两个只读工具查询。跨工具用例须先配置详情工具；哨兵需预置于上游私有数据，工具须人工审计无副作用。' : 'Choose one query, two steps with one tool, or a cross-tool read-only lookup. Configure the detail tool first; place the canary upstream and audit both tools.')
        : (zh ? '只向已选择的 Agent 端点发送所选用例；必须先将保护哨兵放入该 Agent 的系统提示词。' : 'Only selected cases are sent to the chosen Agent endpoint. Place the protected canary in its system prompt first.')} />
    <Form<WizardValues> form={form} layout="vertical" disabled={operation.busy} onFinish={values => void submit(values)}
      initialValues={{ executionMode: 'simulator', categories: ['direct-injection', 'tool-abuse'], targetName: 'local-simulator', guardStrength: 30, maxCases: 200, ciGateEnabled: true, severityThreshold: 'high' }}>
      <Form.Item name="name" label={t('redteam.wizard.name')} rules={[{ required: true, whitespace: true }]}><Input maxLength={100} /></Form.Item>
      <Form.Item name="executionMode" label={zh ? '执行方式' : 'Execution mode'}>
        <Select options={[{ value: 'simulator', label: zh ? '本地模拟' : 'Local simulator' },
          ...(canUseAgentTarget ? [{ value: 'agent-http', label: zh ? '真实 Agent HTTP' : 'Real Agent HTTP' }] : []),
          ...(canUseMcpTarget ? [{ value: 'mcp-http', label: zh ? '真实 MCP HTTP' : 'Real MCP HTTP' }] : [])]} />
      </Form.Item>
      {mode === 'simulator' ? <>
      <Form.Item name="categories" label={t('redteam.wizard.categories')} rules={[{ required: true }]}>
        <Select mode="multiple" options={CATEGORIES.map(([value, cn, en]) => ({ value, label: zh ? cn : en }))} />
      </Form.Item>
      <Form.Item name="targetName" label={zh ? '模拟目标名称' : 'Simulator target name'} rules={[{ required: true, whitespace: true }]}><Input maxLength={100} /></Form.Item>
      <Form.Item name="guardStrength" label={zh ? '模拟防护强度（0–100）' : 'Simulated guard strength (0–100)'} rules={[{ required: true }]}><InputNumber min={0} max={100} precision={0} /></Form.Item>
      <Form.Item name="maxCases" label={zh ? '最多用例数（1–500）' : 'Case limit (1–500)'} rules={[{ required: true }]}><InputNumber min={1} max={500} precision={0} /></Form.Item>
      </> : <>
        <Form.Item name="targetProfileId" label={mode === 'mcp-http' ? (zh ? '已接入的 MCP 目标' : 'Connected MCP target') : (zh ? '已接入的 Agent 目标' : 'Connected Agent target')} rules={[{ required: true }]}>
          <Select loading={mode === 'mcp-http' ? mcpTargets.isLoading : targets.isLoading}
            options={mode === 'mcp-http'
              ? (mcpTargets.data?.data.items ?? []).filter(item => item.enabled).map(item => ({
                value: item.id, label: `${item.name} · ${item.toolName} (v${item.version})`,
              }))
              : (targets.data?.data.items ?? []).filter(item => item.enabled).map(item => ({
                value: item.id, label: `${item.name} · ${item.model} (v${item.version})`,
              }))}
            placeholder={zh ? '请先在本页目标配置中接入' : 'Configure a target on this page first'} />
        </Form.Item>
        <Form.Item name="caseKeys" label={zh ? '可判定的用例（最多 20 条）' : 'Cases with a supported oracle (up to 20)'} rules={[{ required: true }]}>
          <Select mode="multiple" maxCount={20} loading={cases.isLoading} options={(cases.data?.data.items ?? []).map(item => ({
            value: item.key, label: `${item.key} · ${item.title}`,
          }))} />
        </Form.Item>
      </>}
      <Form.Item name="ciGateEnabled" label={t('redteam.wizard.ciGate')} valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name="severityThreshold" label={zh ? '达到此等级及以上的成功攻击阻断 CI' : 'Successful attacks at or above this severity fail CI'} rules={[{ required: true }]}>
        <Select options={SEVERITIES.map(value => ({ value, label: t(`severity.${value}`) }))} />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={operation.busy}>{zh ? '提交战役' : 'Submit campaign'}</Button>
    </Form>
  </Drawer>;
}

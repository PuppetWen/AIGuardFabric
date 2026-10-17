import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Descriptions, Drawer, Input, Radio, Select, Space, Table, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useApiQuery } from '@/api/client';
import { onboardingApi } from '@/api/onboarding';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { DataState } from '@/components/DataState';
import type { Agent, OnboardingMode } from '@/types/domain';
import { targetChoices, type OnboardingTarget, type PlanRequest, type SourceChoice } from '@/types/onboarding';
import { AgentConnectionGuide } from './AgentConnectionGuide';
import { OnboardingStartupFields } from './OnboardingStartupFields';
import { emptyStartup, missingRequiredTeam } from './onboardingStartup';
import { useOnboardingPlan } from './useOnboardingPlan';
import { mergeStdio } from './onboardingStdio';

interface Props { agent: Agent | null; onClose: () => void }
const modes: OnboardingMode[] = ['sidecar', 'sdk-inject', 'gateway-register'];
function Code({ value }: { value: string }) {
  return <Typography.Paragraph copyable={{ text: value }} className="agf-code agf-code--compact"
    style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{value}</Typography.Paragraph>;
}
export function OnboardingWizard(props: Props) {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Wizard key={`${tenant?.id}:${tenant?.slug}:${generation}:${props.agent?.id ?? ''}`} {...props} />;
}
function Wizard({ agent, onClose }: Props) {
  const { t, i18n } = useTranslation(), access = useSessionAccess();
  const zh = i18n.language.startsWith('zh'), text = (cn: string, en: string) => zh ? cn : en;
  const initial: OnboardingMode = agent && modes.includes(agent.management as OnboardingMode) ? agent.management as OnboardingMode : 'sidecar';
  const [mode, setMode] = useState(initial), [target, setTarget] = useState<OnboardingTarget>(targetChoices[initial][0]);
  const [platform, setPlatform] = useState('windows-amd64'), [selected, setSelected] = useState<Agent | null>(agent), [generic, setGeneric] = useState(!agent);
  const [query, setQuery] = useState({ page: 1, pageSize: 10, keyword: '', sort: 'name' });
  const [model, setModel] = useState(''), [sdk, setSdk] = useState(emptyStartup), [sources, setSources] = useState<SourceChoice[]>([]);
  const [command, setCommand] = useState(''), [argumentsJson, setArgumentsJson] = useState('[]');
  const operation = useOnboardingPlan();
  const sdkTarget = target === 'python-startup' || target === 'node-cjs-startup';
  const modelTarget = target === 'model-openai' || target === 'model-anthropic';
  const readable = access.has('agents:read') && (!sdkTarget || (access.has('sources:read') && access.has('alicloud:read')))
    && (!modelTarget || access.has('models:read'));
  const agents = useApiQuery('onboarding-agents', () => onboardingApi.agents(query), { key: [query], enabled: !generic && access.has('agents:read') });
  const invalidate = operation.invalidate;
  const request = (): PlanRequest => ({ agent_id: generic ? undefined : selected?.id, mode, target, platform,
    locale: zh ? 'zh-CN' : 'en-US', public_base: window.location.origin });
  const chooseMode = (value: OnboardingMode) => { invalidate(); setMode(value); setTarget(targetChoices[value][0]); setSdk(emptyStartup()); setSources([]); };
  const chooseTarget = (value: OnboardingTarget) => { invalidate(); setTarget(value); setSdk(emptyStartup()); setSources([]); setModel(''); };
  const load = async () => { const result = await operation.run(request(), true); if (result) setSources(result.sdkSources); };
  const generate = () => {
    const input = request();
    if (sdkTarget) input.sdk = { ...sdk }; if (modelTarget) input.model = model;
    void operation.run(input);
  };
  const plan = operation.plan;
  let configuration = plan?.configurationJson ?? '', mergeError = '';
  if (plan?.target === 'mcp-stdio' && configuration && command) {
    try { configuration = mergeStdio(configuration, command, argumentsJson); }
    catch (failure) { configuration = ''; mergeError = failure instanceof Error ? failure.message : 'Invalid original argument array'; }
  }
  return <Drawer width={780} open onClose={onClose} title={t('agents.wizard.title')} destroyOnClose>
    <AgentConnectionGuide />
    <Space direction="vertical" size={14} style={{ width: '100%' }}>
      <Radio.Group aria-label={text('纳管模式', 'Onboarding mode')} value={mode} onChange={event => chooseMode(event.target.value)}>
        {modes.map(value => <Radio key={value} value={value}>{value === 'sdk-inject' ? text('SDK 启动注入', 'SDK startup injection') : t(`agents.wizard.mode.${value}`)}</Radio>)}
      </Radio.Group>
      <Select aria-label={text('接入目标', 'Connection target')} value={target} style={{ width: '100%' }}
        options={targetChoices[mode].map(value => ({ value, label: value }))} onChange={chooseTarget} />
      <Select aria-label={text('目标平台', 'Target platform')} value={platform} style={{ width: '100%' }}
        onChange={value => { invalidate(); setPlatform(value); }} options={[
          { value: 'windows-amd64', label: 'Windows x64 · PowerShell' }, { value: 'linux-amd64', label: 'Linux x64 · Bash' },
          { value: 'macos-arm64', label: 'macOS Apple Silicon · Bash' },
        ]} />
      <Radio.Group value={generic} onChange={event => { invalidate(); setGeneric(event.target.value); }}>
        <Radio value={true}>{text('首次接入 / 通用计划', 'First connection / generic plan')}</Radio>
        <Radio value={false}>{text('参考已发现 Agent', 'Reference a discovered agent')}</Radio>
      </Radio.Group>
      {!generic && <><Input.Search allowClear placeholder={text('搜索全部 Agent', 'Search all agents')}
        onSearch={keyword => { invalidate(); setQuery(value => ({ ...value, page: 1, keyword })); }} />
        {selected && <Typography.Text>{text('已选择：', 'Selected: ')}{selected.name}</Typography.Text>}
        <DataState loading={agents.isLoading} error={agents.error}>
          <Table<Agent> rowKey="id" size="small" dataSource={agents.data?.data.items ?? []}
            columns={[{ title: t('agents.column.name'), dataIndex: 'name' }, { title: t('agents.column.host'), dataIndex: 'host' }]}
            rowSelection={{ type: 'radio', preserveSelectedRowKeys: true, selectedRowKeys: selected ? [selected.id] : [], onSelect: row => { invalidate(); setSelected(row); } }}
            pagination={{ current: query.page, pageSize: 10, total: agents.data?.data.total ?? 0, showSizeChanger: false,
              onChange: page => { invalidate(); setQuery(value => ({ ...value, page })); } }} />
        </DataState></>}
      {modelTarget && <label>{text('精确已启用模型 ID（不自动选择）', 'Exact enabled model ID (no automatic selection)')}
        <Input aria-label={text('精确模型 ID', 'Exact model ID')} value={model} onChange={event => { invalidate(); setModel(event.target.value); }} /></label>}
      {sdkTarget && <><Button disabled={!readable || operation.busy} onClick={() => void load()}>{text('只读加载当前来源与 Worker', 'Load current sources and Workers (read only)')}</Button>
        {sources.length === 0 && <Alert type="info" message={text('尚未加载或没有已验证来源；先盘点并建立审计绑定。', 'Not loaded, or no verified source. Inventory Workers and bind an audit source first.')} />}
        <OnboardingStartupFields target={target} sources={sources} value={sdk} onChange={value => { invalidate(); setSdk(value); }} /></>}
      {target === 'mcp-stdio' && <><Input aria-label={text('原 stdio 命令', 'Original stdio command')} placeholder={text('填写原 command', 'Enter the original command')}
        value={command} onChange={event => { invalidate(); setCommand(event.target.value); }} />
        <Input.TextArea aria-label={text('原 stdio 参数 JSON 数组', 'Original stdio arguments JSON array')} value={argumentsJson}
          onChange={event => { invalidate(); setArgumentsJson(event.target.value); }} /></>}
      {!readable && <Alert type="warning" message={text('需要当前 agents:read；SDK 还需 sources:read、alicloud:read，模型还需 models:read。',
        'Requires current agents:read; SDK additionally sources:read and alicloud:read; model additionally models:read.')} />}
      {operation.error && <Alert type="error" message={operation.error} />}
      <Button type="primary" loading={operation.busy} disabled={!readable || (!generic && !selected) || (sdkTarget && missingRequiredTeam(sources, sdk))} onClick={generate}>
        {text('生成只读接入计划', 'Generate read-only connection plan')}</Button>
      {plan && <><Descriptions size="small" column={1} bordered items={[
        { key: 'target', label: text('接入目标', 'Connection target'), children: plan.target },
        { key: 'endpoint', label: t('agents.wizard.endpoint'), children: <Typography.Text copyable>{plan.endpoint}</Typography.Text> },
        { key: 'ready', label: text('模板状态', 'Template state'), children: plan.ready ? text('模板已生成；尚未验证业务部署', 'Template generated; business deployment unverified') : text('需手工填写或登记；未自动派发', 'Needs explicit configuration or registration; nothing dispatched') },
      ]} />
        {plan.links.map(link => <Link key={link.href} to={link.href}>{link.label}</Link>)}
        {plan.artifactUrl && <Button href={plan.artifactUrl}>{t('agents.wizard.downloadArtifact')}</Button>}
        {plan.artifactSha256 && <Typography.Text code copyable>SHA-256: {plan.artifactSha256}</Typography.Text>}
        {plan.keyEnv && <Typography.Text>{text('仅环境变量提供独立 Key：', 'Supply a separate key only through environment: ')}<code>{plan.keyEnv}</code></Typography.Text>}
        {plan.envSnippet && <Code value={plan.envSnippet} />}
        {mergeError && <Alert type="error" message={mergeError} />}
        {configuration && <><Typography.Title level={5}>{text('不含密钥的配置 / 合并模板', 'Noncredential configuration / merge template')}</Typography.Title><Code value={configuration} /></>}
        {plan.steps.map(row => <div key={row.order}><Typography.Title level={5}>{row.order}. {row.title}</Typography.Title><Code value={row.command} />
          <Typography.Text type="secondary">{t('agents.wizard.rollback')}</Typography.Text><Code value={row.rollback} /></div>)}
      </>}
      <Alert showIcon type="info" message={text('不创建 Key、不登记资产、不更改角色、不执行业务。原命令参数由你在本地保留。停机与真实 Claude CLI 需单独验证。',
        'Creates no keys, assets or roles and executes no business. Retain original arguments locally. Downtime and actual Claude CLI require separate verification.')} />
      <Button onClick={onClose}>{t('common.finish')}</Button>
    </Space>
  </Drawer>;
}

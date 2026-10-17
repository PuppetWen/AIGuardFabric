import { Alert, Input, Select, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { OnboardingTarget, SourceChoice, StartupFields } from '@/types/onboarding';

import { missingRequiredTeam } from './onboardingStartup';

export function OnboardingStartupFields({ target, sources, value, onChange }: {
  target: OnboardingTarget; sources: SourceChoice[]; value: StartupFields; onChange: (value: StartupFields) => void;
}) {
  const zh = useTranslation().i18n.language.startsWith('zh'), text = (cn: string, en: string) => zh ? cn : en;
  const selected = sources.find(source => source.sourceId === value.source_id);
  const member = selected?.workers.find(worker => worker.name === value.worker), callee = selected?.workers.find(worker => worker.name === value.callee_worker);
  const workerRequired = (member?.teams.length ?? 0) > 1, calleeRequired = (callee?.teams.length ?? 0) > 1;
  const change = (patch: Partial<StartupFields>) => onChange({ ...value, ...patch });
  const input = (label: string, name: 'operation' | 'module' | 'callable' | 'entry' | 'sdk_directory' | 'spool_directory' | 'configuration_file' | 'target_file') =>
    <label key={name}><Typography.Text>{label}</Typography.Text><Input aria-label={label} value={value[name] ?? ''}
      onChange={event => change({ [name]: event.target.value })} /></label>;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Select aria-label={text('当前审计来源', 'Current audit source')} value={value.source_id || undefined} placeholder={text('明确选择来源', 'Explicitly select a source')}
      style={{ width: '100%' }} options={sources.map(source => ({ value: source.sourceId, label: `${source.name} · ${source.mocked ? 'Mock' : 'Live'} · ${source.sourceId}` }))}
      onChange={sourceId => { const source = sources.find(row => row.sourceId === sourceId); if (source) change({ source_id: sourceId, binding_id: source.bindingId,
        worker: '', team: null, callee_worker: null, callee_team: null }); }} />
    {selected && <Typography.Text code>{`binding=${selected.bindingId}; scope=${selected.scopeId}; mocked=${selected.mocked}`}</Typography.Text>}
    <Select aria-label="Worker" value={value.worker || undefined} placeholder="Worker" style={{ width: '100%' }} options={selected?.workers.map(worker => ({ value: worker.name, label: worker.name })) ?? []}
      onChange={worker => change({ worker, team: null })} />
    <Select aria-label="Team" aria-required={workerRequired} status={workerRequired && !value.team ? 'error' : undefined} allowClear value={value.team ?? undefined}
      placeholder={workerRequired ? text('必须明确选择 Team；不预选', 'Explicit Team required; no default') : text('可选 Team；不预选', 'Optional team; no default')}
      style={{ width: '100%' }} options={member?.teams.map(team => ({ value: team, label: team })) ?? []} onChange={team => change({ team: team ?? null })} />
    <Select aria-label={text('事件边界', 'Event boundary')} value={value.kind} options={[{ value: 'task', label: 'Task' }, { value: 'call', label: 'Worker call' }]}
      onChange={kind => change({ kind, callee_worker: null, callee_team: null })} />
    {value.kind === 'call' && <><Select aria-label={text('被调用 Worker', 'Callee Worker')} value={value.callee_worker ?? undefined} placeholder="Callee Worker"
      style={{ width: '100%' }} options={selected?.workers.map(worker => ({ value: worker.name, label: worker.name })) ?? []} onChange={callee_worker => change({ callee_worker, callee_team: null })} />
      <Select aria-label="Callee Team" aria-required={calleeRequired} status={calleeRequired && !value.callee_team ? 'error' : undefined} allowClear value={value.callee_team ?? undefined}
        placeholder={calleeRequired ? text('必须明确选择被调用 Team；不预选', 'Explicit callee Team required; no default') : text('可选被调用 Team；不预选', 'Optional callee team; no default')} style={{ width: '100%' }}
        options={callee?.teams.map(team => ({ value: team, label: team })) ?? []} onChange={team => change({ callee_team: team ?? null })} /></>}
    {missingRequiredTeam(sources, value) && <Alert type="warning" message={text('所选 Worker 属于多个团队，必须明确选择其当前盘点 Team；不会自动选择。',
      'A selected Worker belongs to multiple Teams. Explicitly select its inventoried Team; none is selected automatically.')} />}
    {input(text('静态操作标签', 'Static operation tag'), 'operation')}
    {target === 'python-startup' && input(text('真实目标模块', 'Actual target module'), 'module')}
    {target === 'node-cjs-startup' && input(text('真实 CommonJS 目标文件绝对路径', 'Absolute CommonJS target file'), 'target_file')}
    {input(text('真实可调用名称 / export 路径', 'Actual callable / export path'), 'callable')}
    {input(text('原业务入口（Python 模块 / Node 文件绝对路径）', 'Original entry (Python module / absolute Node script)'), 'entry')}
    {target === 'node-cjs-startup' && <Select aria-label={text('真实返回类型', 'Actual return kind')} value={value.async_mode ?? undefined} placeholder={text('明确选择；不推断', 'Explicitly select; no inference')}
      options={['sync', 'promise', 'iterator', 'asyncIterator'].map(mode => ({ value: mode, label: mode }))} onChange={async_mode => change({ async_mode })} />}
    {input(text('已安装 SDK 目录绝对路径', 'Absolute installed SDK directory'), 'sdk_directory')}
    {input(text('本应用独占队列目录绝对路径', 'Absolute application-owned queue directory'), 'spool_directory')}
    {input(text('不含密钥配置文件绝对路径', 'Absolute noncredential configuration file'), 'configuration_file')}
    <Alert type="info" message={text('仅包装明确调用边界的 Task/Call；Message 需要显式 SDK。不会捕获参数、提示词、返回正文或密钥。',
      'Wraps explicit Task/Call boundaries; Message requires the explicit SDK. Arguments, prompts, response bodies and keys are omitted.')} />
  </Space>;
}

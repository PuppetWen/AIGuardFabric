import { Alert, Button, Checkbox, Descriptions, Input, Select, Space, Typography } from 'antd';
import { useEffect, useState } from 'react';
import type { ObservationReceipt } from '../scheduler-native/types';
import type { JobKind, SchedulePatch, SchedulerJob } from './types';
import type { ManagedController } from './useManagedJobs';
import { blankDraft, buildChange, type Draft } from './draft';
import { kinds, useText } from './text';

const fields: (keyof Required<SchedulePatch>)[] = ['time_type', 'time_expression', 'timezone', 'calendar', 'max_attempt', 'attempt_interval'];
export function ManagedEditor({ flow, canManage }: { flow: ManagedController; canManage: boolean }) {
  const t = useText(), [draft, setDraft] = useState(blankDraft), [job, setJob] = useState<SchedulerJob | null>(null);
  const [jobObservationId, setJobObservationId] = useState<string | null>(null);
  const [base, setBase] = useState<{ observation: ObservationReceipt; bindingVersion: number } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  // A list summary is not an adoptable receipt; the original GET below loads its jobs.
  const observed = flow.observation, target = flow.data?.target;
  const fresh = observed?.finishedAt ? Date.parse(observed.finishedAt) + 300_000 >= now : false;
  const adoptable = !!observed?.observation && observed.current && observed.available && observed.listingComplete && fresh
    && observed.requestId === flow.data?.latestObservationId && observed.originalTarget?.fingerprint === target?.fingerprint;
  const sourceSame = base?.observation.originalTarget?.fingerprint === target?.fingerprint && base?.observation.originalTarget?.configurationVersion === target?.configurationVersion;
  const baselineCurrent = !!base && sourceSame && base.bindingVersion === flow.data?.bindingVersion
    && base.observation.requestId === flow.data?.latestObservationId && Date.parse(base.observation.finishedAt ?? '') + 300_000 >= now;
  const page = observed?.observation?.jobs ?? [];
  const options = page.filter(row => row.httpJob && row.kind === 'http').map(row => ({ value: row.id, label: `${row.name} · ${row.id} · ${row.enabled === true ? 'enabled' : row.enabled === false ? 'disabled' : 'unknown'}` }));
  if (job && !options.some(row => row.value === job.id)) options.push({ value: job.id, label: `${job.id} · ${t('保留选择；不在当前页', 'retained selection; outside this page')}` });
  const selectionCurrent = draft.action === 'create_disabled' || (!!job && jobObservationId === base?.observation.requestId);
  let valid = false; try { buildChange(draft, job); valid = true; } catch { /* Draft remains editable. */ }
  function update<K extends keyof Draft>(field: K, value: Draft[K]) { setDraft(old => ({ ...old, [field]: value })); }
  const prepare = () => {
    if (!base || !target || !baselineCurrent || !selectionCurrent
      || !(Date.parse(base.observation.finishedAt ?? '') + 300_000 >= Date.now())) return;
    const change = buildChange(draft, job), input = { configuration_version: target.configurationVersion,
      expected_binding_version: base.bindingVersion, observation_id: base.observation.requestId, change };
    if (change.action === 'create_disabled') void flow.prepare(input);
    else if (job && base.observation.appId && base.observation.fingerprint && draft.kind) void flow.prepare({ ...input,
      selection: { kind: draft.kind, app_id: base.observation.appId, job_id: job.id, observation_fingerprint: base.observation.fingerprint } });
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('人工采用完整观察并编辑单个动作', 'Adopt a complete observation and edit one action')}</Typography.Title>
    <Alert type="info" message={t('重新加载不会改草稿或采用版本；运行中的任务必须先独立停用。', 'Reload keeps the draft and adopted version; disable a running job in a separate action first.')} />
    <Button disabled={!canManage || !adoptable || flow.busy || flow.intentLocked} onClick={() => {
      if (observed && flow.data && Date.parse(observed.finishedAt ?? '') + 300_000 >= Date.now())
        setBase({ observation: observed, bindingVersion: flow.data.bindingVersion });
    }}>
      {t('采用当前观察和绑定版本（保留草稿）', 'Adopt current observation and binding version (keep draft)')}</Button>
    <Descriptions size="small" column={1} items={[{ key: 'observation', label: t('已采用观察', 'Adopted observation'), children: base?.observation.requestId ?? '—' },
      { key: 'binding', label: t('预览使用绑定版本', 'Preview uses binding version'), children: base?.bindingVersion ?? '—' }]} />
    {base && !baselineCurrent && <Alert type="warning" message={t('来源、最新观察、绑定版本或采用窗口已变化；草稿保留，需明确采用新基线。', 'Source, observation, binding version or adoption window changed. Keep the draft and explicitly adopt a new baseline.')} />}
    <Select aria-label={t('单次动作', 'Single action')} value={draft.action} style={{ width: 330 }} onChange={value => update('action', value)} options={[
      { value: 'create_disabled', label: t('创建停用任务（仅 Mock）', 'Create disabled job (Mock only)'), disabled: !target?.mocked },
      { value: 'update_schedule', label: t('修改已停用任务的日历/重试', 'Update disabled job calendar/retry') },
      { value: 'disable', label: t('独立停用', 'Separate disable') }, { value: 'enable', label: t('独立启用', 'Separate enable') }]} />
    <Select aria-label={t('真实任务类型', 'Actual task kind')} placeholder={t('明确选择六类之一', 'Choose one of the six kinds')} value={draft.kind || undefined}
      style={{ width: 260 }} onChange={(value: JobKind) => update('kind', value)} options={kinds.map(value => ({ value, label: value }))} />
    {draft.action === 'create_disabled' ? <><Input aria-label={t('Mock 任务名称', 'Mock job name')} value={draft.name} onChange={event => update('name', event.target.value)} />
      <Alert type="warning" message={t('total=1；仅创建本地停用声明。HTTP carrier、Callback、部署和消费者均未验证。', 'total=1; creates a local disabled declaration only. HTTP carrier, Callback, deployment and consumers are unverified.')} /></>
      : <Select aria-label={t('已观察 HTTP Job ID', 'Observed HTTP Job ID')} value={job?.id} placeholder={t('选择已观察的真实 Job ID', 'Select an actual observed Job ID')}
        style={{ width: '100%' }} options={options} onChange={id => { const row = page.find(row => row.id === id); if (row) { setJob(row); setJobObservationId(observed?.requestId ?? null); } }} />}
    {job && !selectionCurrent && <Alert type="warning" message={t('Job ID 保留，但新观察须重新核实并选择该任务。', 'Job ID is retained; verify and select it again from the new observation.')} />}
    {(draft.action === 'create_disabled' || draft.action === 'update_schedule') && fields.map(field => <Space key={field} wrap>
      <Checkbox checked={draft.replace.includes(field)} onChange={event => update('replace', event.target.checked ? [...draft.replace, field] : draft.replace.filter(value => value !== field))}>
        {t('明确设置', 'Set explicitly')} {field}</Checkbox>
      <Input aria-label={field} disabled={!draft.replace.includes(field)} value={draft.patch[field]}
        onChange={event => update('patch', { ...draft.patch, [field]: event.target.value })} style={{ width: 300 }} />
    </Space>)}
    <Button disabled={!canManage || !baselineCurrent || !selectionCurrent || !valid || flow.busy || flow.intentLocked || !flow.data?.canPrepare
      || (draft.action === 'create_disabled' && !target?.mocked)} onClick={prepare}>{t('预览单个受管差异', 'Preview one managed change')}</Button>
  </Space>;
}

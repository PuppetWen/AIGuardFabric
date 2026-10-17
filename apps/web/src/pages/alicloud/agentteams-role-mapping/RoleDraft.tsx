import { useEffect, useState } from 'react';
import { Alert, Button, Checkbox, Popconfirm, Select, Space, Typography } from 'antd';
import { adoptChange, chooseWorker, latestDraft } from './draft';
import type { RoleFlow } from './useRoleMapping';
import { useRoleText, workerKey } from './text';

export function RoleDraft({ flow, canWrite }: { flow: RoleFlow; canWrite: boolean }) {
  const t = useRoleText(), state = flow.data, draft = flow.draft;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  if (!state?.catalogAvailable) return null;
  const selected = draft && state.roles.find(role => role.id === draft.roleId);
  const current = draft && state.items.find(row => row.assetId === draft.worker.assetId);
  const latest = draft && latestDraft(state, draft), expected = current?.version ?? 0;
  const observed = Date.parse(draft?.worker.observedAt ?? '');
  const freshObservation = Number.isFinite(observed) && observed <= now + 60_000 && observed >= now - 300_000;
  const supported = !!selected?.selectable && !!draft?.worker.cloudRole && !!draft.worker.assetId && freshObservation;
  const workers = state.workers.map(worker => ({ value: workerKey(worker), label: `${worker.workerName} / ${worker.teamName} / ${worker.cloudRole ?? t('Role 未知', 'Role unknown')}`,
    disabled: !worker.assetId || !worker.cloudRole }));
  if (draft && !workers.some(row => row.value === workerKey(draft.worker))) workers.push({ value: workerKey(draft.worker),
    label: t('保留草稿成员（当前盘点未加载）', 'Retained draft member (not in current inventory)'), disabled: true });
  const roles = state.roles.map(role => ({ value: role.id, label: `${role.displayName} (${role.name}) · ${role.id}`, disabled: !role.selectable }));
  if (draft?.roleId && !selected) roles.push({ value: draft.roleId, label: t(`保留旧 Role UUID，当前目录不可用：${draft.roleId}`,
    `Retained Role UUID unavailable in current catalog: ${draft.roleId}`), disabled: true });
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('明确选择成员与平台角色', 'Explicit member and platform Role selection')}</Typography.Title>
    <Select aria-label={t('已盘点 Worker / Team / CloudRole', 'Inventoried Worker / Team / CloudRole')} style={{ width: '100%', maxWidth: 640 }}
      value={draft ? workerKey(draft.worker) : undefined} options={workers} placeholder={t('选择真实盘点成员，不默认指派', 'Choose actual inventory membership; no default assignment')}
      disabled={!canWrite || !state.canManage || flow.busy || flow.writeLocked} onChange={value => {
        const worker = state.workers.find(row => workerKey(row) === value); if (worker) flow.changeDraft(chooseWorker(state, worker));
      }} />
    {!state.workers.length && <Alert type="info" message={t('暂无可采用成员。请在连接配置启用 AgentTeams，并人工完整盘点。',
      'No adoptable membership. Enable AgentTeams in Connection configuration and perform a complete inventory manually.')} />}
    {draft && <>
      <Typography.Text>{t('Worker 资产', 'Worker asset')}: {draft.worker.assetId} · {t('草稿保存版本 / 当前映射版本', 'Draft save version / current mapping version')}: {draft.expectedVersion} / {expected}</Typography.Text>
      <Typography.Text>{t('草稿原盘点', 'Draft inventory source')}: cfg {draft.worker.configurationVersion} · {draft.worker.observedAt}</Typography.Text>
      {!freshObservation && <Alert type="warning" message={t('该草稿盘点超过采用窗口或时间未知；先人工完整盘点，再 GET 比较并明确采用。',
        'Draft inventory is outside the adoption window or has an unknown time. Perform a complete inventory manually, then compare via GET and adopt explicitly.')} />}
      <Select aria-label={t('真实平台 Role UUID', 'Actual platform Role UUID')} style={{ width: '100%', maxWidth: 640 }} value={draft.roleId || undefined}
        placeholder={t('选择本租户已保存角色', 'Choose a saved tenant Role')} options={roles} disabled={!canWrite || flow.busy || flow.writeLocked || !state.canManage}
        onChange={value => flow.changeDraft({ ...draft, roleId: value, confirmed: false })} />
      <Typography.Text>{t('选定角色权限', 'Selected Role permissions')}: {selected?.permissions.join(', ') || '—'}</Typography.Text>
      {selected && !selected.selectable && <Alert type="warning" message={selected.reason || t('此角色不可采用', 'This Role cannot be adopted')} />}
      {draft.roleId && !selected && <Alert type="warning" message={t('旧 Role UUID 保留供修复；不能把未知目录当任意有效角色。',
        'The old Role UUID is retained for repair; an unknown catalog does not validate an arbitrary Role.')} />}
      <Checkbox checked={draft.confirmed} disabled={!canWrite || !supported || flow.busy || flow.writeLocked} onChange={event => flow.changeDraft({ ...draft, confirmed: event.target.checked })}>
        {t('确认只约束绑定此 Agent 的 Key；现有采集或调用权限可能缩小，云 Role/RAM 不变',
          'Confirm constraining Keys bound to this Agent; existing collection or call permissions may narrow, while cloud Role/RAM remain unchanged')}</Checkbox>
      <Popconfirm title={t('明确提交本地角色约束？', 'Explicitly commit the local Role constraint?')} okText={t('确认采用', 'Confirm adoption')}
        onConfirm={() => { if (draft.worker.assetId && supported && draft.confirmed && !flow.busy && !flow.writeLocked) return flow.save(draft.worker.assetId, draft.expectedVersion, adoptChange(state, draft)); }}>
        <Button disabled={!canWrite || !supported || !draft.confirmed || flow.busy || flow.writeLocked || !state.canManage}>{t('人工采用角色约束', 'Adopt Role constraint manually')}</Button>
      </Popconfirm>
      <Typography.Text type="secondary">{t('300 秒仅为人工采用门槛。保存后按当前来源、成员和身份复核，不因五分钟自动停掉日/月任务。',
        'The 300-second window is only for human adoption. Saved authority follows current source, membership and identity; daily/monthly jobs do not expire after five minutes.')}</Typography.Text>
      {latest && <>
        <Typography.Text>{t('GET 最新比较（不会改变草稿版本）', 'Latest GET comparison (does not change draft revision)')}: v{expected} · cfg {latest.worker.configurationVersion} · {latest.worker.observedAt} · {latest.worker.cloudRole ?? 'unknown'}</Typography.Text>
        <Popconfirm title={t('保留所选 Role，明确采用最新成员证明和 CAS 版本？', 'Keep the selected Role and explicitly adopt latest membership evidence and CAS revision?')}
          okText={t('确认采用最新', 'Confirm latest adoption')} onConfirm={() => flow.changeDraft(latest)}>
          <Button disabled={!canWrite || flow.busy || flow.writeLocked}>{t('明确采用最新比较（不保存）', 'Adopt latest comparison explicitly (no save)')}</Button>
        </Popconfirm>
      </>}
      {!latest && <Alert type="warning" message={t('当前盘点已无此成员；草稿保留，不能从缺失证据恢复授权。',
        'The current inventory has no such member. The draft is retained; missing evidence cannot restore authority.')} />}
    </>}
  </Space>;
}

import { Alert, Button, Checkbox, Input, Popconfirm, Radio, Select, Space, Typography } from 'antd';
import { adopt } from './definition';
import { failure, useText } from './text';
import { NodeEditor } from './NodeEditor';
import type { OrchestrationFlow } from './useOrchestration';

export function DefinitionEditor({ flow, canWrite }: { flow: OrchestrationFlow; canWrite: boolean }) {
  const t = useText(), { data, draft } = flow;
  if (!data) return null;
  const disabled = !canWrite || !data.canManage || flow.busy || flow.writeLocked;
  const latest = draft && data.teams.find(team => team.teamName === draft.target.teamName);
  const different = draft && latest && (draft.expectedVersion !== (latest.current?.version ?? 0)
    || draft.target.source.inventoryFingerprint !== latest.source.inventoryFingerprint
    || draft.target.source.configurationVersion !== latest.source.configurationVersion);
  const change = (value: Partial<NonNullable<typeof draft>>) => draft && flow.updateDraft({ ...draft, ...value });
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('编辑应用所有的 DAG 声明', 'Edit the application-owned DAG declaration')}</Typography.Title>
    <Select aria-label={t('已盘点 Team', 'Observed Team')} style={{ minWidth: 260 }} value={draft?.target.teamName}
      placeholder={t('人工选择真实 Team', 'Choose an actual Team')} disabled={disabled}
      options={data.teams.map(team => ({ value: team.teamName, label: team.teamName }))}
      onChange={name => { const target = data.teams.find(team => team.teamName === name); if (target) flow.select(target); }} />
    {draft && <>
      <Typography.Text>{t('草稿基线版本', 'Draft baseline revision')}: {draft.expectedVersion}; {t('配置版本', 'Configuration revision')}: {draft.target.source.configurationVersion}</Typography.Text>
      <Typography.Paragraph>{t('可引用的真实 Worker 名称', 'Actual Worker names that may be referenced')}: {draft.target.workers.map(worker => worker.name).join(', ') || t('未观察到成员', 'No observed members')}</Typography.Paragraph>
      {different && <Alert type="warning" message={t('当前版本或来源已变化；草稿保持原基线。', 'The current revision or source changed; the draft retains its original baseline.')}
        description={`${t('最新已读版本', 'Latest read revision')}: ${latest.current?.version ?? 0}`} />}
      <Popconfirm title={t('采用已读取的最新版本和来源，并保留草稿节点？', 'Adopt the latest read revision and source while keeping draft nodes?')}
        okText={t('明确采用', 'Adopt explicitly')} onConfirm={() => {
          if (!latest || disabled) return;
          try { flow.updateDraft(adopt(draft, latest)); } catch (cause) { flow.reportError(failure(cause)); }
        }}>
        <Button disabled={disabled || !latest}>{t('明确采用已读基线（不保存）', 'Adopt the read baseline explicitly (no save)')}</Button>
      </Popconfirm>
      <Radio.Group aria-label={t('操作类型', 'Operation type')} value={draft.action} disabled={disabled}
        options={[{ value: 'save_definition', label: t('保存本地声明', 'Save local declaration') }, { value: 'sync', label: t('同步 Mock 接收端', 'Sync the Mock receiver') }]}
        onChange={event => change({ action: event.target.value, confirmed: false, mockConfirmed: false })} />
      {draft.action === 'save_definition' ? <>
        <Alert type="info" message={t('粘贴或编辑 JSON。节点 agent_ids 使用上方 Worker 名称；depends_on 使用 node_id。不会执行节点。',
          'Paste or edit JSON. Node agent_ids use the Worker names above; depends_on uses node_id. Nodes will not execute.')} />
        <NodeEditor key={draft.target.teamName} draft={draft} disabled={disabled} onChange={flow.updateDraft} />
        <Input.TextArea aria-label={t('DAG 声明 JSON', 'DAG declaration JSON')} value={draft.text} rows={12} disabled={disabled}
          onChange={event => change({ text: event.target.value, confirmed: false })} />
      </> : <>
        <Select aria-label={t('同步方向', 'Sync direction')} style={{ minWidth: 320 }} value={draft.direction} disabled={disabled}
          options={[{ value: 'push', label: t('推送：本地 → Mock 接收端', 'Push: local → Mock receiver') },
            { value: 'pull', label: t('拉取：Mock 接收端 → 本地', 'Pull: Mock receiver → local') },
            { value: 'both', label: t('双向：冲突时采用本地定义', 'Both: use local definition on conflict') }]}
          onChange={direction => change({ direction, confirmed: false, mockConfirmed: false })} />
        <Checkbox checked={draft.mockConfirmed} disabled={disabled} onChange={event => change({ mockConfirmed: event.target.checked })}>
          {t('确认仅同步应用所有的 Mock 接收端，不调用厂商写接口', 'Confirm syncing only the application-owned Mock receiver, with no vendor write API')}
        </Checkbox>
      </>}
      <Checkbox checked={draft.sourceConfirmed} disabled={disabled} onChange={event => change({ sourceConfirmed: event.target.checked })}>
        {t('如来源发生变化，确认重新绑定声明并清空旧 Mock 接收端', 'If the source changed, confirm rebinding the declaration and clearing the old Mock receiver')}
      </Checkbox>
      <Checkbox checked={draft.confirmed} disabled={disabled} onChange={event => change({ confirmed: event.target.checked })}>
        {t('确认这是应用所有的编排声明，不表示云 DAG 或消费者已运行', 'Confirm this is an application-owned declaration, without claiming a cloud DAG or a running consumer')}
      </Checkbox>
      <Button loading={flow.busy} disabled={disabled} onClick={() => void flow.prepare()}>{t('验证 DAG 并预览差异（不保存）', 'Validate DAG and preview differences (no save)')}</Button>
    </>}
  </Space>;
}

import { useState } from 'react';
import { Alert, Button, Input, Select, Space, Table } from 'antd';
import { parseDefinition } from './definition';
import { failure, useText } from './text';
import type { DeclaredNode, Draft } from './types';

export function NodeEditor({ draft, disabled, onChange }: { draft: Draft; disabled: boolean; onChange: (value: Draft) => void }) {
  const t = useText();
  const [id, setId] = useState(''), [name, setName] = useState(''), [workers, setWorkers] = useState<string[]>([]), [parents, setParents] = useState<string[]>([]);
  const [trigger, setTrigger] = useState<DeclaredNode['trigger']>('manual'), [cron, setCron] = useState(''), [error, setError] = useState('');
  let nodes: DeclaredNode[] = [], valid = true;
  try { nodes = parseDefinition(draft.text).nodes; } catch { valid = false; }
  const add = () => {
    try {
      const doc = parseDefinition(draft.text);
      if (!id || id.trim() !== id || id.length > 128 || !name || name.trim() !== name || name.length > 256 || Array.from(id + name).some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
        || workers.length === 0 || workers.length > 32 || nodes.length >= 128 || nodes.some(node => node.node_id === id)
        || workers.some(worker => !draft.target.workers.some(actual => actual.name === worker)) || (trigger === 'cron' && (!cron || cron.trim() !== cron))) throw new Error(t('请填写唯一节点和已盘点 Worker；cron 必须明确填写。', 'Provide a unique node and observed Workers; cron must be explicit.'));
      const node: DeclaredNode = { node_id: id, name, agent_ids: [...workers], depends_on: [...parents], trigger, cron: trigger === 'cron' ? cron : null };
      onChange({ ...draft, text: JSON.stringify({ ...doc, nodes: [...doc.nodes, node] }, null, 2), confirmed: false }); setId(''); setName(''); setWorkers([]); setParents([]); setError('');
    } catch (cause) { setError(failure(cause)); }
  };
  const remove = (id: string) => {
    try { const doc = parseDefinition(draft.text); onChange({ ...draft, text: JSON.stringify({ ...doc, nodes: doc.nodes.filter(node => node.node_id !== id) }, null, 2), confirmed: false }); }
    catch (cause) { setError(failure(cause)); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    {!valid && <Alert type="info" message={t('先修正 JSON 才能使用节点表单；原文本仍保留。', 'Correct the JSON before using the node form; original text remains intact.')} />}
    {error && <Alert type="error" message={error} />}
    <Space wrap>
      <Input aria-label={t('新节点 ID', 'New node ID')} value={id} disabled={disabled || !valid} onChange={event => setId(event.target.value)} />
      <Input aria-label={t('新节点名称', 'New node name')} value={name} disabled={disabled || !valid} onChange={event => setName(event.target.value)} />
      <Select mode="multiple" aria-label={t('指派已盘点 Worker', 'Assign observed Workers')} value={workers} style={{ minWidth: 240 }} disabled={disabled || !valid}
        options={draft.target.workers.map(worker => ({ value: worker.name, label: worker.name }))} onChange={setWorkers} />
      <Select mode="multiple" aria-label={t('依赖已有节点', 'Depend on existing nodes')} value={parents} style={{ minWidth: 240 }} disabled={disabled || !valid}
        options={nodes.map(node => ({ value: node.node_id, label: node.node_id }))} onChange={setParents} />
      <Select aria-label={t('声明触发方式', 'Declared trigger')} value={trigger} disabled={disabled || !valid}
        options={['manual', 'event', 'cron'].map(value => ({ value, label: value }))} onChange={setTrigger} />
      {trigger === 'cron' && <Input aria-label={t('cron 声明', 'Cron declaration')} value={cron} disabled={disabled || !valid} onChange={event => setCron(event.target.value)} />}
      <Button disabled={disabled || !valid} onClick={add}>{t('仅加入草稿节点', 'Add a node to the draft only')}</Button>
    </Space>
    <Table rowKey="node_id" size="small" dataSource={nodes} pagination={{ pageSize: 20, showSizeChanger: false }} columns={[
      { title: 'ID', dataIndex: 'node_id' }, { title: t('名称', 'Name'), dataIndex: 'name' },
      { title: 'Workers', render: (_, node) => node.agent_ids.join(', ') }, { title: t('依赖', 'Dependencies'), render: (_, node) => node.depends_on.join(', ') || '—' },
      { title: t('触发声明', 'Declared trigger'), dataIndex: 'trigger' },
      { title: t('操作', 'Action'), render: (_, node) => <Button disabled={disabled || nodes.some(other => other.depends_on.includes(node.node_id))}
        onClick={() => remove(node.node_id)}>{t('移除草稿节点', 'Remove draft node')}</Button> },
    ]} />
  </Space>;
}

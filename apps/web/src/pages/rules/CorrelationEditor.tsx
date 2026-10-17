import { useState } from 'react';
import { Alert, Button, Collapse, Form, Input, InputNumber, Select, Space, Switch, Tabs, Typography } from 'antd';
import { correlationApi, type Definition, type Revision, type RuleRow } from './correlationApi';
import { downloadText } from '@/utils/download';

export function CorrelationEditor({ definition, row, zh, onSaved }: {
  definition: Definition; row?: RuleRow; zh: boolean; onSaved: () => void;
}) {
  const [source, setSource] = useState(JSON.stringify(definition, null, 2));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [expected, setExpected] = useState(row?.current.version ?? 0);
  const [latest, setLatest] = useState<Revision>();
  const [preview, setPreview] = useState<{ passed: boolean; positive: unknown; negative: unknown }>();
  let draft: Definition | undefined;
  try { draft = JSON.parse(source) as Definition; } catch { /* Draft JSON may be incomplete while typing. */ }
  const update = (patch: Partial<Definition>) => { if (draft) { setSource(JSON.stringify({ ...draft, ...patch }, null, 2)); setPreview(undefined); } };
  const rule = (patch: Partial<Definition['rule']>) => { if (draft) update({ rule: { ...draft.rule, ...patch } }); };
  const act = async (save: boolean) => {
    setBusy(true); setError('');
    try {
      const parsed = JSON.parse(source) as Definition;
      if (row && parsed.rule.key !== row.current.definition.rule.key) throw new Error(zh ? '编辑已有规则时请保持标识不变' : 'Keep the existing rule key when editing');
      if (save) { await correlationApi('rules', { definition: parsed, expected_version: expected }); onSaved(); }
      else setPreview(await correlationApi('validate', parsed));
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const checkLatest = async () => {
    setBusy(true); setError('');
    try {
      const result = await correlationApi<{ items: RuleRow[] }>('rules');
      const saved = result.items.find(item => item.current.definition.rule.key === row?.current.definition.rule.key);
      if (!saved) throw new Error(zh ? '找不到当前规则' : 'Current rule was not found');
      setLatest(saved.current);
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    {error && <Alert showIcon type="error" message={error} />}
    {row && <Space><Typography.Text>{zh ? '草稿基于版本' : 'Draft based on version'} {expected}</Typography.Text>
      <Button loading={busy} onClick={() => void checkLatest()}>{zh ? '检查最新版本' : 'Check latest version'}</Button></Space>}
    {latest && <Alert type="info" showIcon message={`${zh ? '服务器版本' : 'Server version'} ${latest.version} · ${latest.actor}`}
      description={<Space direction="vertical" style={{ width: '100%' }}>
        <Typography.Text>{zh ? '请对照下方服务器内容与当前草稿，合并需要保留的修改后采用此版本号。草稿内容保持不变。' : 'Compare the server content with your draft and merge changes before adopting this version. Your draft content is preserved.'}</Typography.Text>
        <Collapse items={[{ key: 'latest', label: zh ? '查看服务器内容' : 'View server content', children: <pre style={{ maxHeight: 260, overflow: 'auto' }}>{JSON.stringify(latest.definition, null, 2)}</pre> }]} />
        <Button onClick={() => { setExpected(latest.version); setLatest(undefined); setPreview(undefined); }}>{zh ? '采用此版本号，保留草稿' : 'Adopt version and keep draft'}</Button>
      </Space>} />}
    <Form layout="inline" disabled={busy || !draft?.rule}>
      <Form.Item label={zh ? '标识' : 'Key'}><Input value={draft?.rule?.key} disabled={!!row} onChange={e => rule({ key: e.target.value })} /></Form.Item>
      <Form.Item label={zh ? '名称' : 'Name'}><Input value={draft?.rule?.name} onChange={e => rule({ name: e.target.value })} /></Form.Item>
      <Form.Item label={zh ? '等级' : 'Severity'}><Select style={{ width: 115 }} value={draft?.rule?.severity} onChange={severity => rule({ severity })}
        options={['critical', 'high', 'medium', 'low', 'info'].map(value => ({ value, label: value }))} /></Form.Item>
      <Form.Item label={zh ? '启用' : 'Enabled'}><Switch checked={draft?.enabled} onChange={enabled => update({ enabled })} /></Form.Item>
      <Form.Item label={zh ? '窗口（秒）' : 'Window (seconds)'}><InputNumber min={1} max={604800} value={draft?.window_secs} onChange={value => {
        if (draft && value) update({ window_secs: value, rule: { ...draft.rule, ...(draft.rule.kind === 'temporal' ? { window_secs: value } : {}) } });
      }} /></Form.Item>
      <Form.Item label={zh ? '分组' : 'Group by'}><Select style={{ width: 160 }} value={draft?.group_by} onChange={group_by => update({ group_by })}
        options={[['entity', zh ? '实体' : 'Entity'], ['source', zh ? '来源' : 'Source'], ['session', zh ? '会话' : 'Session'], ['none', zh ? '全部事件' : 'All events']].map(([value, label]) => ({ value, label }))} /></Form.Item>
    </Form>
    <Tabs items={[
      { key: 'definition', label: zh ? '条件与样本 JSON' : 'Conditions and sample JSON', children: <>
        <Typography.Paragraph>{zh ? '使用样例字段修改条件和正负序列。可以在接入管理的来源事件中复制归一化 JSON；不要把真实密钥写进规则样本。' : 'Adapt the example conditions and event sequences. Copy normalized JSON from source event details in Ingestion; keep live credentials out of samples.'}</Typography.Paragraph>
        <Input.TextArea aria-label="Correlation definition JSON" value={source} disabled={busy} rows={18} style={{ fontFamily: 'monospace' }} onChange={e => { setSource(e.target.value); setPreview(undefined); }} />
      </> },
      { key: 'history', label: zh ? '版本历史' : 'Version history', children: row?.history.slice().reverse().map(revision => <div key={revision.version}>
        <Space><Typography.Text>v{revision.version} · {revision.actor} · {revision.changedAt}</Typography.Text>
          <Button onClick={() => { setSource(JSON.stringify(revision.definition, null, 2)); setPreview(undefined); }}>{zh ? '载入草稿' : 'Load draft'}</Button></Space>
      </div>) ?? <Typography.Text>{zh ? '保存后保留最近 10 个版本' : 'The latest ten versions are retained after saving'}</Typography.Text> },
    ]} />
    {preview && <Alert showIcon type={preview.passed ? 'success' : 'error'} message={preview.passed ? (zh ? '正负样本全部通过' : 'Positive and negative samples passed') : (zh ? '样本未通过，请查看结果' : 'Samples failed; inspect the result')}
      description={<pre style={{ maxHeight: 250, overflow: 'auto' }}>{JSON.stringify(preview, null, 2)}</pre>} />}
    <Space><Button loading={busy} onClick={() => void act(false)}>{zh ? '试跑正负样本' : 'Validate samples'}</Button>
      <Button type="primary" loading={busy} onClick={() => void act(true)}>{zh ? '验证并保存' : 'Validate and save'}</Button>
      <Button disabled={!draft} onClick={() => downloadText(`correlation-${draft?.rule?.key ?? 'draft'}.json`, source)}>{zh ? '导出配置' : 'Export configuration'}</Button>
    </Space>
  </Space>;
}

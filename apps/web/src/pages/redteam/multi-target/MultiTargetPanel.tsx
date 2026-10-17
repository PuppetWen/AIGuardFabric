import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input, Popconfirm, Select, Space, Typography } from 'antd';
import type { MultiProfile, MultiSelection } from '@/api/redteamMultiTarget';
import { useMultiTarget } from './useMultiTarget';
import { RecentRuns } from './RecentRuns';
import { ManagedTransport } from './ManagedTransport';
export function MultiTargetPanel({ canExecute, canManage = false }: { canExecute: boolean; canManage?: boolean }) {
  const zh = useTranslation().i18n.language.startsWith('zh'); const model = useMultiTarget();
  const [ids, setIds] = useState<string[]>(['', '', '']); const [reviewed, setReviewed] = useState(false); const [live, setLive] = useState(false);
  const inventories = [model.agents, model.mcps, model.agents];
  const rows = ids.map((id, index) => inventories[index].find(row => row.id === id));
  const ready = rows.every(row => row?.enabled && Number.isSafeInteger(row.version) && row.version > 0) && ids[0] !== ids[2] && rows[0]?.assetId !== rows[2]?.assetId;
  const selection = (): MultiSelection[] => rows.map((row, index) => ({ kind: index === 1 ? 'mcp-http' : 'agent-http', profile_id: (row as MultiProfile).id, expected_version: (row as MultiProfile).version }));
  const label = (en: string, cn: string) => zh ? cn : en;
  return <Space direction="vertical" style={{ width: '100%' }}>
    {canManage && <ManagedTransport agents={model.agents} mcps={model.mcps} zh={zh} />}
    <Alert type="info" showIcon message={label('Agent A → read-only MCP → Agent B', 'Agent A → MCP 只读工具 → Agent B')}
      description={label('Select existing current target profiles. SQL is required for execution. Three fixed requests plus complete MCP tool discovery use protected canaries. Read-only tools can still consume quota. Public HTTPS targets need explicit live confirmation. No arbitrary YAML, shell or business replay.', '请选择已登记的当前目标配置。执行需要 SQL。固定三步请求与完整 MCP 工具清单使用保护哨兵；只读工具也会消耗配额。公共 HTTPS 目标须显式确认 Live。不接受任意 YAML、shell 或业务重放。')} />
    {inventories.map((inventory, index) => <Select key={index} aria-label={['Agent A', 'Read-only MCP', 'Agent B'][index]} style={{ width: '100%' }}
      placeholder={label('Select a registered current profile', '选择已登记的当前配置')} value={ids[index] || undefined}
      disabled={!canExecute || model.busy || model.attempted} options={inventory.map(row => ({ value: row.id, label: `${row.name} · v${row.version} · ${row.id}`, disabled: !row.enabled }))}
      onChange={id => { setIds(current => current.map((old, at) => at === index ? id : old)); setReviewed(false); model.resetPreview(); }} />)}
    <Button disabled={!canExecute || !ready || model.attempted} loading={model.busy} onClick={() => void model.review(selection())}>{label('Preview fixed topology', '预览固定拓扑')}</Button>
    {model.preview && <><Typography.Paragraph code>{JSON.stringify(model.preview.topology, null, 2)}</Typography.Paragraph>
      <Checkbox checked={reviewed} disabled={model.attempted || model.busy} onChange={event => setReviewed(event.target.checked)}>{label('I reviewed these exact profiles and versions', '我已核对这些准确配置与版本')}</Checkbox>
      <Checkbox checked={live} disabled={model.attempted || model.busy} onChange={event => setLive(event.target.checked)}>{label('Allow these exact registered and currently approved live read requests', '允许向这些准确登记且当前批准的 Live 目标发送只读请求')}</Checkbox>
      <Popconfirm title={label('Send the fixed three-step chain once?', '仅发送一次固定三步链路？')} onConfirm={() => model.execute(live)}>
        <Button disabled={!canExecute || !reviewed || !live || model.attempted || model.busy}>{label('Execute once', '执行一次')}</Button>
      </Popconfirm></>}
    <RecentRuns model={model} canExecute={canExecute} zh={zh} />
    <Input aria-label="Original multi-target UUID" value={model.requestId} placeholder={label('Original UUID for manual receipt lookup', '手动读取原 UUID 回执')}
      onChange={event => model.setRequestId(event.target.value)} />
    <Button disabled={!model.requestId} loading={model.readBusy} onClick={() => void model.read()}>{label('Read original receipt', '读取原回执')}</Button>
    {canExecute && model.requestId && <Space>
      <Popconfirm title={label('Publish known evidence locally; send no target request?', '仅本地发布已知证据，不发送目标请求？')} onConfirm={() => model.local('recover')}><Button disabled={model.localBusy}>{label('Recover local publication', '恢复本地发布')}</Button></Popconfirm>
      <Popconfirm title={label('Cancel subsequent steps? An already sent read cannot be undone.', '取消后续步骤？已发送的读取无法撤回。')} onConfirm={() => model.local('cancel')}><Button disabled={model.localBusy}>{label('Cancel subsequent steps', '取消后续步骤')}</Button></Popconfirm>
    </Space>}
    {model.error && <Alert type="warning" message={model.error} />}
    {model.receipt && <><Typography.Paragraph code>{JSON.stringify(model.receipt, null, 2)}</Typography.Paragraph>
      <Alert type="info" message={label('Completion and protected-canary result are separate', '完成状态与保护哨兵结果分别显示')}
        description={label('Null means unverified. A local fixture result does not verify an external defense. Source freshness is current metadata; evidence remains the original immutable campaign. Unknown or HTTP 404 never authorizes resend.', 'null 表示未验证。本地模拟结果不证明外部防护。来源资格是当前元数据，证据仍归原不可变战役。Unknown 或 HTTP 404 不授权重发。')} />
      <Button disabled={!model.canNewIntent} onClick={() => { model.newIntent(); setReviewed(false); }}>{label('Prepare a new explicit intent', '准备新的明确意图')}</Button></>}
  </Space>;
}

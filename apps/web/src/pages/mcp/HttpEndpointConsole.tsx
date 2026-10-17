import { useState } from 'react';
import { Alert, Button, Checkbox, Collapse, Drawer, Form, Input, InputNumber, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import { HttpClientGuide } from './HttpClientGuide';
import { McpEndpointUsage } from './McpEndpointUsage';
import { McpOAuthPanel } from './McpOAuthPanel';

export interface HttpEndpoint {
  id: string; name: string; url: string; enabled: boolean; version: number;
  transport: 'streamable-http' | 'legacy-sse';
  idleTimeoutSecs: number; allowedOrigins: string[]; credentialConfigured: boolean;
}
function request<T>(path = '', body?: unknown) {
  return callApi<T>(`/api/v1/mcp/endpoints${path}`, () => { throw new Error('MCP API unavailable'); }, {
    noFallback: true, timeoutMs: 55_000, opaqueKeys: ['server', 'tools'], ...(body === undefined ? {} : { method: 'POST' as const, body }),
  });
}
function connectionError(error: unknown, zh: boolean) {
  const message = String(error);
  if (!zh) return message;
  if (message.includes('MCP upstream rejected its configured credential (401)')) {
    return '上游 MCP 服务拒绝已保存的凭据（401）。请更新固定 Bearer token，或在上游 OAuth 授权中重新连接。';
  }
  if (message.includes('MCP upstream denied this request (403)')) {
    return '上游 MCP 服务拒绝此请求（403）。请核对令牌受众及工具权限，再重试只读探测。';
  }
  if (message.includes('discovery rejected by upstream')) {
    const code = message.match(/JSON-RPC code -?\d+/)?.[0];
    return `上游 MCP 服务拒绝只读探测${code ? `（${code}）` : ''}。请核对协议、端点权限和上游服务日志。`;
  }
  return message;
}
function input(row: Partial<HttpEndpoint>, token?: string) {
  return { id: row.id, expected_version: row.version ?? 0, name: row.name ?? '', url: row.url ?? '',
    transport: row.transport ?? 'streamable-http', enabled: row.enabled ?? true,
    idle_timeout_secs: row.idleTimeoutSecs ?? 60, allowed_origins: (row.allowedOrigins ?? []).map(value => value.trim()).filter(Boolean),
    ...(token === undefined ? {} : { bearer_token: token }) };
}

export function HttpEndpointConsole() {
  const [open, setOpen] = useState(false);
  const { i18n } = useTranslation();
  const tenant = useAuthStore(state => state.tenant);
  const zh = i18n.language.startsWith('zh');
  return <><Button onClick={() => setOpen(true)}>{zh ? 'HTTP 接入配置' : 'HTTP connections'}</Button>
    <Drawer width={1080} open={open} onClose={() => setOpen(false)} destroyOnClose title={zh ? 'MCP HTTP 接入与客户端指南' : 'MCP HTTP connections and client guide'}>
      {open && <Content key={tenant?.id} zh={zh} />}
    </Drawer></>;
}

function Content({ zh }: { zh: boolean }) {
  const query = useApiQuery('mcp-http-endpoints', () => request<{ items: HttpEndpoint[]; canWrite: boolean; canExecute: boolean }>());
  const canWrite = query.data?.data.canWrite ?? false;
  const canExecute = query.data?.data.canExecute ?? false;
  const [draft, setDraft] = useState<Partial<HttpEndpoint>>();
  const [token, setToken] = useState('');
  const [clearToken, setClearToken] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<HttpEndpoint>();
  const [protocol, setProtocol] = useState('2025-11-25');
  const [probe, setProbe] = useState<{ protocol: string; server: unknown; tools: unknown; sessionClosed: boolean }>();
  const [latest, setLatest] = useState<HttpEndpoint>();
  const edit = (row: Partial<HttpEndpoint>) => { setDraft(row); setToken(''); setClearToken(false); setError(''); setLatest(undefined); };
  const act = async (run: () => Promise<void>) => {
    setBusy(true); setError('');
    try { await run(); } catch (error) { setError(connectionError(error, zh)); }
    finally { setBusy(false); }
  };
  const save = () => act(async () => {
    if (!draft) return;
    const row = (await request<HttpEndpoint>('', input(draft, clearToken ? '' : (token || undefined)))).data;
    setDraft(undefined); setSelected(row); setProtocol(row.transport === 'legacy-sse' ? '2024-11-05' : '2025-11-25');
    setToken(''); setProbe(undefined); await query.refetch();
  });
  const choose = (row: HttpEndpoint) => { setSelected(row); setProtocol(row.transport === 'legacy-sse' ? '2024-11-05' : '2025-11-25'); setProbe(undefined); setError(''); };
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Alert showIcon type="info" message={zh ? '接入步骤：保存上游 → 检测连接 → 创建平台 API Key → 导出客户端配置 → 验证拦截' : 'Save upstream → Test connection → Create platform API key → Export client config → Verify policy'}
      description={zh ? 'Streamable HTTP 填 /mcp 等单端点；旧版 SSE 填 /sse 等流端点。客户端使用平台生成的代理地址。上游 Bearer token 与平台 API Key 分别管理。' : 'Use the upstream /mcp URL for Streamable HTTP or its /sse URL for legacy SSE. Clients connect to the generated proxy URL; upstream and platform credentials are separate.'} />
    {(error || query.error) && <Alert showIcon type="error" message={error || String(query.error)} />}
    <Space><Button type="primary" disabled={!canWrite || busy} onClick={() => edit({ enabled: true, transport: 'streamable-http', idleTimeoutSecs: 60, allowedOrigins: [] })}>{zh ? '新增 MCP 端点' : 'Add MCP endpoint'}</Button>
      <Button loading={query.isLoading} disabled={busy} onClick={() => void query.refetch()}>{zh ? '刷新列表' : 'Refresh'}</Button></Space>
    <Table<HttpEndpoint> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data?.data.items ?? []} pagination={{ pageSize: 6 }} columns={[
      { title: zh ? '名称 / 上游地址' : 'Name / upstream', render: (_, row) => <><div>{row.name}</div><Typography.Text style={{ wordBreak: 'break-all' }}>{row.url}</Typography.Text></> },
      { title: zh ? '版本 / 凭据' : 'Version / credential', render: (_, row) => <>{row.version} · {row.credentialConfigured ? (zh ? '已配置' : 'Configured') : (zh ? '无' : 'None')}</> },
      { title: zh ? '传输' : 'Transport', render: (_, row) => <Tag>{row.transport === 'legacy-sse' ? 'SSE 2024' : 'HTTP'}</Tag> },
      { title: zh ? '状态' : 'Status', render: (_, row) => <Tag color={row.enabled ? 'green' : 'default'}>{row.enabled ? (zh ? '启用' : 'Enabled') : (zh ? '停用' : 'Disabled')}</Tag> },
      { title: zh ? '操作' : 'Actions', render: (_, row) => <Space><Button disabled={!canWrite || busy} onClick={() => edit(row)}>{zh ? '编辑' : 'Edit'}</Button>
        <Button disabled={busy} onClick={() => choose(row)}>{zh ? '连接指南' : 'Connect'}</Button></Space> },
    ]} />
    {draft && <Form layout="vertical" disabled={busy || !canWrite}>
      <Typography.Title level={5}>{draft.id ? (zh ? '编辑端点' : 'Edit endpoint') : (zh ? '新增端点' : 'New endpoint')}</Typography.Title>
      <Form.Item label={zh ? '名称' : 'Name'} required><Input aria-label={zh ? '名称' : 'Name'} value={draft.name} maxLength={160} onChange={e => setDraft({ ...draft, name: e.target.value })} /></Form.Item>
      <Form.Item label={zh ? '传输协议' : 'Transport'} required><Select aria-label={zh ? '传输协议' : 'Transport'} value={draft.transport ?? 'streamable-http'} onChange={transport => setDraft({ ...draft, transport })}
        options={[{ value: 'streamable-http', label: 'Streamable HTTP (2025/2026)' }, { value: 'legacy-sse', label: 'HTTP + SSE (2024-11-05)' }]} /></Form.Item>
      <Form.Item label={zh ? '上游 MCP URL' : 'Upstream MCP URL'} required><Input aria-label={zh ? '上游 MCP URL' : 'Upstream MCP URL'} value={draft.url}
        placeholder={draft.transport === 'legacy-sse' ? 'https://mcp.example.com/sse' : 'https://mcp.example.com/mcp'}
        onChange={e => setDraft({ ...draft, url: e.target.value })} /></Form.Item>
      <Form.Item label={zh ? '上游 Bearer token（留空保留已有凭据）' : 'Upstream bearer token (leave blank to keep)'}><Input.Password aria-label={zh ? '上游 Bearer token（留空保留已有凭据）' : 'Upstream bearer token (leave blank to keep)'} autoComplete="new-password" value={token} disabled={clearToken} onChange={e => setToken(e.target.value)} />
        <Checkbox checked={clearToken} onChange={e => setClearToken(e.target.checked)}>{zh ? '明确清除上游凭据' : 'Remove upstream credential'}</Checkbox></Form.Item>
      <Form.Item label={zh ? '允许的浏览器 Origin（每行一个；命令行客户端可留空）' : 'Allowed browser origins (one per line; optional for CLI clients)'}>
        <Input.TextArea aria-label={zh ? '允许的浏览器 Origin' : 'Allowed browser origins'} value={draft.allowedOrigins?.join('\n')} onChange={e => setDraft({ ...draft, allowedOrigins: e.target.value.split('\n') })} placeholder="https://console.example.com" />
      </Form.Item>
      <Space><Form.Item label={zh ? '空闲超时（秒）' : 'Idle timeout (seconds)'}><InputNumber aria-label={zh ? '空闲超时（秒）' : 'Idle timeout (seconds)'} min={5} max={600} value={draft.idleTimeoutSecs} onChange={value => setDraft({ ...draft, idleTimeoutSecs: value ?? 60 })} /></Form.Item>
        <Form.Item label={zh ? '启用' : 'Enabled'}><Switch aria-label={zh ? '启用' : 'Enabled'} checked={draft.enabled} onChange={enabled => setDraft({ ...draft, enabled })} /></Form.Item></Space>
      <Space><Button type="primary" loading={busy} onClick={() => void save()}>{zh ? '保存' : 'Save'}</Button><Button onClick={() => setDraft(undefined)}>{zh ? '取消' : 'Cancel'}</Button>
        {draft.id && <Button onClick={() => void act(async () => setLatest((await request<{ items: HttpEndpoint[] }>()).data.items.find(row => row.id === draft.id)))}>{zh ? '查看服务器最新版本' : 'Check latest version'}</Button>}</Space>
      {latest && <Alert type="info" message={zh ? `服务器版本 ${latest.version}；当前草稿基于 ${draft.version}` : `Server version ${latest.version}; draft based on ${draft.version}`}
        description={<><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(latest, null, 2)}</pre><Button onClick={() => { setDraft({ ...draft, version: latest.version }); setLatest(undefined); }}>{zh ? '已比较，保留草稿并使用此版本号' : 'Keep draft and use this version after comparison'}</Button></>} />}
    </Form>}
    {selected && <>
      <HttpClientGuide row={selected} zh={zh} />
      <McpOAuthPanel key={selected.id} id={selected.id} canWrite={canWrite} staticCredential={selected.credentialConfigured} zh={zh} />
      <McpEndpointUsage id={selected.id} zh={zh} />
      <Space><Select aria-label="MCP probe protocol" value={protocol} onChange={setProtocol} options={selected.transport === 'legacy-sse'
        ? [{ value: '2024-11-05', label: '2024-11-05 HTTP+SSE' }]
        : ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'].map(value => ({ value, label: value }))} />
        <Button disabled={!selected.enabled || !canExecute} loading={busy} onClick={() => void act(async () => {
          setProbe(undefined); setProbe((await request<NonNullable<typeof probe>>(`/${selected.id}/probe`, { protocol })).data);
        })}>{zh ? '检测连接与工具列表' : 'Test connection and list tools'}</Button></Space>
      {probe && <><Alert showIcon type={probe.sessionClosed ? 'success' : 'warning'} message={probe.sessionClosed ? (zh ? '握手与工具列表获取成功' : 'Discovery and tool listing succeeded') : (zh ? '连接成功，但上游未确认关闭临时会话' : 'Connected; upstream did not confirm closing the temporary session')} />
        <Collapse items={[{ key: 'result', label: zh ? '查看服务和工具详情' : 'Server and tool details', children: <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(probe, null, 2)}</pre> }]} /></>}
    </>}
  </Space>;
}

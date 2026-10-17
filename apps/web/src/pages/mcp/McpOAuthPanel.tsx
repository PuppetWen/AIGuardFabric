import { useEffect, useState } from 'react';
import { Alert, Button, Form, Input, Select, Space, Typography } from 'antd';
import { callApi } from '@/api/transport';

export const MCP_OAUTH_FLOW_KEY = 'agf-mcp-oauth-flow';

interface OAuthConfiguration {
  revision: string; endpointUrl: string; issuer: string; resource: string;
  registration: 'pre_registered' | 'client_id_metadata' | 'dynamic';
  clientId: string; clientAuth: 'none' | 'client_secret_basic' | 'client_secret_post';
  requestedClientAuth: 'none' | 'client_secret_basic' | 'client_secret_post' | null;
  scope: string; redirectUri: string; clientSecretConfigured: boolean;
  clientSecretExpiresAt: number | null;
}
interface OAuthStatus { connected: boolean; expiresAt: number | null; refreshable: boolean }
interface OAuthView { configuration: OAuthConfiguration | null; status: OAuthStatus }
interface Draft {
  registration: OAuthConfiguration['registration'];
  issuer: string; clientId: string; clientAuth: OAuthConfiguration['clientAuth'];
  clientSecret: string; registrationAccessToken: string; scope: string; redirectUri: string;
}

function api<T>(id: string, suffix = '', method: 'GET' | 'PUT' | 'POST' = 'GET', body?: unknown) {
  return callApi<T>(`/api/v1/mcp/endpoints/${id}/oauth${suffix}`,
    () => { throw new Error('MCP OAuth API unavailable'); },
    { noFallback: true, method, ...(body === undefined ? {} : { body }) });
}

function form(row: OAuthConfiguration | null): Draft {
  return { registration: row?.registration ?? 'pre_registered', issuer: row?.issuer ?? '',
    clientId: row?.registration && row.registration !== 'pre_registered' ? '' : row?.clientId ?? '',
    clientAuth: row?.requestedClientAuth ?? row?.clientAuth ?? 'none',
    clientSecret: '', registrationAccessToken: '', scope: row?.scope ?? '',
    redirectUri: row?.redirectUri ?? `${window.location.origin}/mcp/oauth/callback` };
}

export function McpOAuthPanel({ id, canWrite, staticCredential, zh }: {
  id: string; canWrite: boolean; staticCredential: boolean; zh: boolean;
}) {
  const [view, setView] = useState<OAuthView>();
  const [draft, setDraft] = useState<Draft>(() => form(null));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const insecureLan = window.location.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(window.location.hostname);
  const reload = async () => {
    const current = (await api<OAuthView>(id)).data;
    setView(current); setDraft(form(current.configuration));
  };
  useEffect(() => {
    let active = true;
    void api<OAuthView>(id).then(({ data }) => {
      if (active) { setView(data); setDraft(form(data.configuration)); }
    }).catch((cause: unknown) => { if (active) setError(String(cause)); });
    return () => { active = false; };
  }, [id]);
  const act = async (run: () => Promise<void>) => {
    setBusy(true); setError('');
    try { await run(); } catch (cause) { setError(String(cause)); }
    finally { setBusy(false); }
  };
  const save = () => act(async () => {
    await api(id, '', 'PUT', {
      expected_revision: view?.configuration?.revision ?? null,
      registration: draft.registration, issuer: draft.issuer.trim(),
      client_id: draft.registration === 'pre_registered' ? draft.clientId.trim() : '',
      client_auth: draft.registration === 'client_id_metadata' ? 'none' : draft.clientAuth,
      client_secret: draft.registration === 'pre_registered' ? draft.clientSecret || null : null,
      registration_access_token: draft.registration === 'dynamic' ? draft.registrationAccessToken || null : null,
      scope: draft.scope.trim(), redirect_uri: draft.redirectUri.trim(),
    });
    await reload();
  });
  const connect = () => act(async () => {
    if (view?.configuration && new URL(view.configuration.redirectUri).origin !== window.location.origin) {
      throw new Error(zh
        ? '请先通过已登记的 HTTPS 回调地址所在的控制台入口打开本页，再开始上游授权；跨来源标签页无法读取本次授权状态。'
        : 'Open this console from the registered HTTPS callback origin before authorizing; another origin cannot read this tab’s authorization state.');
    }
    const flow = (await api<{ authorizationUrl: string; state: string; binding: string; redirectUri: string }>(id, '/start', 'POST')).data;
    sessionStorage.setItem(MCP_OAUTH_FLOW_KEY, JSON.stringify({ endpointId: id,
      state: flow.state, binding: flow.binding, createdAt: Date.now() }));
    window.location.assign(flow.authorizationUrl);
  });
  const disconnect = () => act(async () => {
    await api(id, '/disconnect', 'POST');
    await reload();
  });
  return <div style={{ borderTop: '1px solid var(--ant-color-border)', paddingTop: 16 }}>
    <Typography.Title level={5}>{zh ? '上游 OAuth 授权' : 'Upstream OAuth authorization'}</Typography.Title>
    <Alert showIcon type="info" message={zh ? '选择上游支持的客户端注册方式，再保存并授权。' : 'Select a client registration method supported by the upstream, then save and authorize.'}
      description={zh ? '优先使用托管 Client ID 元数据；旧授权服务可用动态注册，或使用预注册客户端。此令牌只用于当前 MCP 上游，平台代理 Key 仍单独发给客户端。' : 'Prefer hosted Client ID metadata. Older authorization servers may support dynamic registration, or use a pre-registered client. This token is only for the upstream MCP service; clients still need a platform key.'} />
    {insecureLan && <Alert showIcon type="warning" message={zh ? '当前控制台使用局域网 HTTP。请先切换到已登记的 HTTPS 控制台入口，再开始授权；仅 127.0.0.1 回环测试允许 HTTP。' : 'This console uses LAN HTTP. Open the registered HTTPS console origin before authorizing; only 127.0.0.1 loopback testing may use HTTP.'} />}
    {staticCredential && <Alert showIcon type="warning" message={zh ? '请先编辑端点并清除固定 Bearer token，才能使用 OAuth。' : 'Clear the endpoint’s static bearer token before enabling OAuth.'} />}
    {error && <Alert showIcon type="error" message={error} />}
    {view?.configuration && <Typography.Paragraph>{zh ? '资源' : 'Resource'}: <Typography.Text copyable>{view.configuration.resource}</Typography.Text><br />
      {view.configuration.registration === 'client_id_metadata' && <>{zh ? '公开 Client ID 元数据' : 'Public Client ID metadata'}: <Typography.Text copyable>{view.configuration.clientId}</Typography.Text><br /></>}
      {view.configuration.registration === 'dynamic' && <>{zh ? '动态注册的 Client ID' : 'Dynamically registered Client ID'}: <Typography.Text copyable>{view.configuration.clientId}</Typography.Text><br /></>}
      {view.configuration.clientSecretExpiresAt && <>{zh ? '客户端密钥到期' : 'Client secret expiry'}: {new Date(view.configuration.clientSecretExpiresAt * 1000).toLocaleString()}<br /></>}
      {zh ? '状态' : 'Status'}: {view.status.connected ? (zh ? '已连接' : 'Connected') : (zh ? '未连接或需重新授权' : 'Disconnected or reauthorization required')}
      {view.status.expiresAt && <> · {zh ? '令牌到期' : 'Token expiry'}: {new Date(view.status.expiresAt * 1000).toLocaleString()}</>}</Typography.Paragraph>}
    <Form layout="vertical" disabled={!canWrite || busy || staticCredential}>
      <Form.Item label={zh ? '客户端注册方式' : 'Client registration'}><Select aria-label="OAuth registration" value={draft.registration}
        onChange={registration => setDraft({ ...draft, registration })}
        options={[{ value: 'pre_registered', label: zh ? '预注册客户端' : 'Pre-registered client' },
          { value: 'client_id_metadata', label: zh ? '托管 Client ID 元数据（推荐）' : 'Hosted Client ID metadata (recommended)' },
          { value: 'dynamic', label: zh ? '动态注册（旧版兼容）' : 'Dynamic registration (legacy)' }]} /></Form.Item>
      {draft.registration === 'client_id_metadata' && <Alert showIcon type="info"
        message={zh ? '需要公开可访问的 HTTPS 控制台入口；上游授权服务会读取这里发布的公开客户端元数据。' : 'Requires a publicly reachable HTTPS console origin; the upstream authorization server fetches its public client metadata here.'} />}
      {draft.registration === 'dynamic' && <Alert showIcon type="info"
        message={zh ? '保存时平台会调用授权服务声明的注册接口；可选择公开客户端或 Client Secret 认证。若上游要求初始注册令牌，可在下方一次性填写；平台不会保存它。相同配置再次保存不会重复注册。' : 'Saving calls the authorization server’s advertised registration endpoint. Choose public or client secret authentication. Enter an initial registration token below if required; the platform does not store it. Saving unchanged settings does not register again.'} />}
      <Form.Item label={zh ? '授权服务 Issuer' : 'Authorization server issuer'} required><Input aria-label="OAuth issuer" value={draft.issuer}
        placeholder="https://auth.example.com" onChange={event => setDraft({ ...draft, issuer: event.target.value })} /></Form.Item>
      {draft.registration === 'pre_registered' && <Form.Item label="Client ID" required><Input aria-label="OAuth client ID" value={draft.clientId}
        onChange={event => setDraft({ ...draft, clientId: event.target.value })} /></Form.Item>}
      {draft.registration !== 'client_id_metadata' && <Form.Item label={zh ? '客户端认证方式' : 'Client authentication'}><Select aria-label="OAuth client authentication" value={draft.clientAuth}
        onChange={clientAuth => setDraft({ ...draft, clientAuth })}
        options={[{ value: 'none', label: 'Public client (PKCE)' }, { value: 'client_secret_basic', label: 'Client Secret Basic' },
          { value: 'client_secret_post', label: 'Client Secret Post' }]} /></Form.Item>}
      {draft.registration === 'pre_registered' && draft.clientAuth !== 'none' && <Form.Item label="Client Secret"><Input.Password aria-label="OAuth client secret" autoComplete="new-password"
        value={draft.clientSecret} placeholder={view?.configuration?.clientSecretConfigured ? (zh ? '留空保留原密钥' : 'Leave blank to retain') : ''}
        onChange={event => setDraft({ ...draft, clientSecret: event.target.value })} /></Form.Item>}
      {draft.registration === 'dynamic' && <Form.Item label={zh ? '初始注册令牌（可选，仅当次使用）' : 'Initial registration token (optional, one-time)'}>
        <Input.Password aria-label="OAuth initial registration token" autoComplete="new-password"
          value={draft.registrationAccessToken} onChange={event => setDraft({ ...draft, registrationAccessToken: event.target.value })} /></Form.Item>}
      <Form.Item label={zh ? '权限范围（空格分隔）' : 'Scopes (space separated)'}><Input aria-label="OAuth scopes" value={draft.scope}
        placeholder="mcp:tools offline_access" onChange={event => setDraft({ ...draft, scope: event.target.value })} /></Form.Item>
      <Form.Item label={zh ? '注册到上游的回调地址' : 'Registered redirect URI'} required><Input aria-label="OAuth redirect URI" value={draft.redirectUri}
        onChange={event => setDraft({ ...draft, redirectUri: event.target.value })} /></Form.Item>
      <Space wrap><Button onClick={() => void save()} loading={busy} disabled={!canWrite || staticCredential}>{zh ? '保存 OAuth 配置' : 'Save OAuth configuration'}</Button>
        <Button type="primary" onClick={() => void connect()} loading={busy} disabled={!canWrite || !view?.configuration || staticCredential}>{zh ? '登录上游并授权' : 'Authorize upstream'}</Button>
        <Button danger onClick={() => void disconnect()} loading={busy} disabled={!canWrite || !view?.status.connected}>{zh ? '断开并清除令牌' : 'Disconnect and remove token'}</Button>
        <Button onClick={() => void act(reload)} disabled={busy}>{zh ? '刷新状态' : 'Refresh status'}</Button></Space>
    </Form>
  </div>;
}

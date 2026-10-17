import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Space, Spin, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { callApi } from '@/api/transport';
import { MCP_OAUTH_FLOW_KEY } from './McpOAuthPanel';

interface Flow { endpointId: string; state: string; binding: string; createdAt: number }

function callback() {
  const params = new URLSearchParams(window.location.search);
  window.history.replaceState(null, '', window.location.pathname);
  const saved = sessionStorage.getItem(MCP_OAUTH_FLOW_KEY);
  if (!saved || params.has('error')) throw new Error('MCP OAuth authorization was cancelled or expired');
  const flow = JSON.parse(saved) as Flow;
  if (flow.state !== params.get('state') || !params.get('code') || Date.now() - flow.createdAt > 600_000) {
    throw new Error('MCP OAuth state did not match this browser tab');
  }
  return { flow, code: params.get('code')!, iss: params.get('iss') };
}

export default function McpOAuthCallbackPage() {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const job = useRef<Promise<void> | null>(null);
  useEffect(() => {
    let active = true;
    job.current ??= (async () => {
      const { flow, code, iss } = callback();
      await callApi(`/api/v1/mcp/endpoints/${flow.endpointId}/oauth/complete`,
        () => { throw new Error('MCP OAuth API unavailable'); }, {
          method: 'POST', noFallback: true,
          body: { state: flow.state, binding: flow.binding, code, iss },
        });
      sessionStorage.removeItem(MCP_OAUTH_FLOW_KEY);
    })();
    void job.current.then(() => { if (active) setDone(true); })
      .catch((cause: unknown) => { if (active) setError(String(cause)); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, []);
  return <Card style={{ maxWidth: 560, margin: '12vh auto' }}><Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={3}>{zh ? 'MCP 上游授权' : 'MCP upstream authorization'}</Typography.Title>
    {busy && <Spin tip={zh ? '正在交换并加密保存访问令牌' : 'Exchanging and encrypting the access token'}><div style={{ height: 64 }} /></Spin>}
    {done && <Alert type="success" showIcon message={zh ? '已连接 MCP 上游；现在可返回端点执行只读探测。' : 'MCP upstream connected. Return to the endpoint and run read-only discovery.'} />}
    {error && <Alert type="error" showIcon message={error} />}
    <Button href="/mcps">{zh ? '返回 MCP 管理' : 'Back to MCP management'}</Button>
  </Space></Card>;
}

import { useState } from 'react';
import { Alert, Button, Form, Input, Select, Space, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { API_BASE_URL } from '@/api/config';
import { downloadText } from '@/utils/download';
import type { HttpEndpoint } from './HttpEndpointConsole';

export function HttpClientGuide({ row, zh }: { row: HttpEndpoint; zh: boolean }) {
  const [base, setBase] = useState(API_BASE_URL || window.location.origin);
  const [client, setClient] = useState('claude');
  const legacy = row.transport === 'legacy-sse';
  const url = `${base.replace(/\/$/, '')}${legacy ? `/api/v1/mcp/legacy/${row.id}/sse` : `/api/v1/mcp/proxy/${row.id}`}`;
  const config = JSON.stringify({ mcpServers: { aiguardfabric: {
    ...(legacy ? { type: 'sse' } : client === 'claude' ? { type: 'http' } : {}), url,
    headers: { Authorization: client === 'claude' ? 'Bearer ${AGF_MCP_KEY}' : 'Bearer REPLACE_WITH_PLATFORM_API_KEY' },
  } } }, null, 2);
  const path = client === 'claude' ? '.mcp.json' : '.cursor/mcp.json';
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{row.name} · {zh ? '客户端接入' : 'Client connection'}</Typography.Title>
    <Typography.Paragraph>{zh ? '在当前组织创建专用 API Key，权限只选择 mcps:execute、policies:read。企业可为每个 Agent 单独创建并绑定密钥；密钥所属组织决定接入租户。' : 'Create a dedicated API key in this organization with only mcps:execute and policies:read. Enterprises can issue a separate key bound to each Agent; the key determines the tenant.'}
      {' '}<Link to="/settings?tab=apiKeys&createKey=1&scopes=mcps%3Aexecute%2Cpolicies%3Aread">{zh ? '前往创建平台 API Key' : 'Create a platform API key'}</Link>
    </Typography.Paragraph>
    {legacy && <Alert showIcon type="info" message={zh ? '旧版 SSE 使用独立接收流和 POST 消息地址' : 'Legacy SSE uses separate receive and POST message endpoints'}
      description={zh ? '只把生成的 /sse 地址填入客户端。平台连接上游后会自动下发 POST 地址；不要把上游 /messages 地址或凭据直接填进客户端。' : 'Configure only the generated /sse URL in the client. The platform announces its POST endpoint after connecting upstream; do not expose the upstream /messages URL or credential to the client.'} />}
    {!legacy && <Alert showIcon type="info" message={zh ? '断线后的事件流恢复' : 'Recovering an interrupted event stream'}
      description={zh ? '2025 协议中，若上游提供会话和事件 ID，客户端可用原平台 Key、Mcp-Session-Id 和最后收到的 Last-Event-ID 发 GET 恢复；游标无效时重新初始化。2026 协议没有此功能。请勿因断线自动重发工具调用。' : 'With a 2025 server that provides sessions and event IDs, a compatible client can resume with GET using the same platform key, Mcp-Session-Id and last Last-Event-ID. Reinitialize if the cursor expires. The 2026 transport does not support this. Do not automatically repeat a tool call after disconnect.'} />}
    <Form layout="vertical"><Form.Item label={zh ? '客户端可访问的平台地址（可用 HTTPS 入口或默认 http://主机:8092）' : 'Platform URL reachable by the client (HTTPS ingress or default http://host:8092)'}>
      <Input value={base} onChange={e => setBase(e.target.value)} /></Form.Item></Form>
    <Select aria-label="MCP client" value={client} onChange={setClient} options={[{ value: 'claude', label: 'Claude Code' }, { value: 'cursor', label: 'Cursor' }]} />
    <Typography.Paragraph>{zh ? `合并到项目 ${path} 的 mcpServers 中，保留其他服务。` : `Merge into mcpServers in the project ${path}, preserving other servers.`}</Typography.Paragraph>
    {client === 'claude' ? <><Typography.Paragraph>{zh ? '启动 Claude Code 前设置平台密钥，再运行 /mcp 检查连接。' : 'Set the platform key before launching Claude Code, then run /mcp to verify.'}</Typography.Paragraph>
      <Typography.Paragraph copyable code>{`$env:AGF_MCP_KEY=[System.Net.NetworkCredential]::new('',(Read-Host 'AIGuardFabric API Key' -AsSecureString)).Password`}</Typography.Paragraph></>
      : <Typography.Paragraph>{zh ? '在本地配置中替换平台 API Key 占位符；不要把实际密钥提交到仓库。在 Cursor 的 MCP 设置中启用服务并查看连接状态。' : 'Replace the platform API key placeholder in your local config. Keep the key out of source control. Enable the server in Cursor MCP settings and inspect its connection status.'}</Typography.Paragraph>}
    <Typography.Paragraph copyable={{ text: config }}><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{config}</pre></Typography.Paragraph>
    <Button onClick={() => downloadText(client === 'claude' ? 'agf-claude-mcp.json' : 'agf-cursor-mcp.json', config)}>{zh ? '下载配置模板' : 'Download config template'}</Button>
    <Alert showIcon type="info" message={zh ? '先用只读工具验证，然后在运行时防护中增加一条测试黑名单，确认危险调用在到达上游前被拒绝。' : 'Verify a read-only tool first, then add a test runtime blacklist rule and confirm the blocked call never reaches upstream.'}
      description={zh ? '401：检查平台密钥；403：检查权限、浏览器 Origin 和策略；404 会话：重新连接；412：端点已停用；429：检查配额；502 且提示上游 401/403：管理员核对固定 Bearer 或在本端点的“上游 OAuth 授权”中重新连接，并检查受众和工具权限。支持预注册、托管 Client ID 元数据和旧版动态注册；HTTP/SSE 中断不会自动重试工具调用。' : '401: check the platform key; 403: permissions, browser origin or policy; session 404: reconnect; 412: disabled endpoint; 429: quota; 502 with upstream 401/403: check the static bearer or reconnect in this endpoint’s Upstream OAuth authorization panel, then verify audience and tool scopes. Pre-registered clients, hosted Client ID metadata, and legacy dynamic registration are supported; interrupted HTTP/SSE tool calls are not retried automatically.'} />
    <Typography.Paragraph>{zh ? '命令行无需 Origin。浏览器客户端须同时配置端点允许来源及平台 AGF_CORS_ALLOW_ORIGINS；带自定义 Mcp-Param 头时使用默认宿主机端口 8092 或其 HTTPS 反向代理。' : 'CLI clients do not need Origin. Browser clients require both endpoint allowed origins and AGF_CORS_ALLOW_ORIGINS. Use the default host port 8092 or its HTTPS reverse proxy for custom Mcp-Param headers.'}</Typography.Paragraph>
    <Space><a href="https://code.claude.com/docs/en/mcp" target="_blank" rel="noreferrer">Claude Code MCP</a>
      <a href="https://prod.cursor.com/help/customization/mcp" target="_blank" rel="noreferrer">Cursor MCP</a></Space>
  </Space>;
}

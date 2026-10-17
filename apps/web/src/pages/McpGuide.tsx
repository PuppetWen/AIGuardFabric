import { Alert, Typography, Steps, Tabs } from 'antd';
import { Link } from 'react-router-dom';
import { Panel } from '@/components/Panel';
import { useTranslation } from 'react-i18next';
import { powershellSecretPrompt } from './powershellSecret';

export function McpGuide({ base }: { base: string }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const windowsExample = JSON.stringify({ mcpServers: { guarded: {
    command: 'C:\\agf\\agf-agent.exe', args: ['mcp-proxy', '--server', base, '--', 'node', 'C:\\mcp\\server.js'],
  } } }, null, 2);
  const unixExample = JSON.stringify({ mcpServers: { guarded: {
    command: '/opt/aiguardfabric/agf-agent',
    args: ['mcp-proxy', '--server', base, '--', 'node', '/opt/mcp/server.js'],
  } } }, null, 2);
  const envWindows = `${powershellSecretPrompt('AGF_AGENT_TOKEN', zh ? '平台代理 API Key' : 'Platform proxy API key')}\n$env:AGF_AGENT_SERVER_URL='${base}'`;
  const envUnix = `printf 'Platform proxy API key: '; read -r -s AGF_AGENT_TOKEN; export AGF_AGENT_TOKEN; printf '\\n'\nexport AGF_AGENT_SERVER_URL='${base}'`;
  const copyBlock = (value: string) => <Typography.Paragraph copyable={{ text: value }}
    style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontFamily: 'monospace' }}>{value}</Typography.Paragraph>;
  const environmentTabs = <Tabs items={[
    { key: 'windows', label: 'Windows', children: copyBlock(envWindows) },
    { key: 'unix', label: 'Linux / macOS', children: copyBlock(envUnix) },
  ]} />;
  const configTabs = <Tabs items={[
    { key: 'windows', label: 'Windows', children: copyBlock(windowsExample) },
    { key: 'unix', label: 'Linux / macOS', children: copyBlock(unixExample) },
  ]} />;
  const httpGuide = <Panel title={zh ? '接入远程 HTTP / SSE MCP 服务' : 'Connect a remote HTTP / SSE MCP server'}>
    <Steps direction="vertical" items={[
      { title: zh ? '登记上游服务' : 'Register the upstream server', description: <span>
        {zh ? '打开 ' : 'Open '}<Link to="/mcps">{zh ? 'MCP 管理' : 'MCP management'}</Link>
        {zh ? '，点「HTTP 接入配置」，选择 Streamable HTTP 或 2024 HTTP+SSE，填写原服务地址。上游凭据可用固定 Bearer，或保存端点后按“上游 OAuth 授权”连接。'
          : ', choose HTTP connections, select Streamable HTTP or 2024 HTTP+SSE, then enter the upstream URL. Use a static bearer credential or authorize the saved endpoint through Upstream OAuth authorization.'}
      </span> },
      { title: zh ? '只读探测与客户端配置' : 'Probe and configure a client',
        description: zh
          ? '保存后执行「检测连接与工具列表」，确认协议和工具；在连接指南创建只具 mcps:execute、policies:read 的平台 Key，并导出 Claude Code 或 Cursor 配置。'
          : 'Save and run the read-only connection and tool probe. In the connection guide, create a platform key with mcps:execute and policies:read, then export the Claude Code or Cursor template.' },
      { title: zh ? '验证调用和用量' : 'Verify calls and usage',
        description: zh
          ? '重启客户端后先调用只读工具，再回到同一端点查看「此端点的工具用量」和运行时拦截记录。结果计数不代表业务动作成功或费用。'
          : 'Restart the client and call a read-only tool. On the same endpoint, inspect tool usage and runtime interception records. A checked result is not proof of the business action or a bill.' },
    ]} />
    <Alert showIcon type="info" message={zh ? '上游 OAuth 注册方式' : 'Upstream OAuth registration'}
      description={zh
        ? '优先使用平台托管的公开 HTTPS Client ID 文档；旧授权服务声明动态注册接口时可由平台自动注册，否则在上游预注册客户端。授权码与刷新令牌加密保存并自动刷新。须从已登记回调地址的 HTTPS 控制台入口开始授权；平台代理 Key 与上游令牌分别使用。'
        : 'Prefer the platform’s public HTTPS Client ID metadata. For older authorization servers with a dynamic registration endpoint, register through the platform; otherwise pre-register a client upstream. Access and refresh tokens are encrypted and refreshed automatically. Begin authorization from the registered HTTPS callback origin. The platform key and upstream token serve different purposes.'} />
  </Panel>;
  if (!zh) return <><Panel title="Protect local MCP with a proxy (Claude Code / Cursor / custom clients)">
    <Steps direction="vertical" items={[
      { title: 'Prepare the collector and a dedicated API key', description:
        'Download the collector from this page. Create a key with policies:read for the proxy. The proxy contacts the platform; the upstream MCP process does not inherit this key.' },
      { title: 'Set environment variables before starting the client', description: environmentTabs },
      { title: 'Update the client MCP configuration', description:
        'Place the original MCP command and arguments after the final -- in the proxy arguments. Replace example paths with actual paths on your device. Preserve other environment variables required by the original service.' },
      { title: 'Restart the client and verify enforcement', description:
        'Call a read-only tool first. Add a distinctive test command to the runtime blacklist, then confirm the call is denied and an enforcement record appears. Disable the test rule and repeat the call to verify recovery.' },
    ]} />
    {configTabs}
    <Alert showIcon type="info" message="Configuration location" description=
      "Claude Code projects use .mcp.json; Cursor projects use .cursor/mcp.json. Enterprise endpoint management can distribute the proxy command and provide keys through controlled environment variables. This stdio proxy controls only traffic passing through it." />
    <Typography.Paragraph>
      The proxy rejects dangerous requests and redacts responses. It refuses forwarding when the policy service is
      unreachable. Standard output contains only MCP messages; diagnostic logs go to standard error. Run the local
      onboarding smoke test in <Typography.Text code>docs/local-onboarding-smoke.md</Typography.Text> before using real keys.
    </Typography.Paragraph>
  </Panel>{httpGuide}</>;
  return <><Panel title="通过代理纳管本地 MCP（Claude Code / Cursor / 自研客户端）">
    <Steps direction="vertical" items={[
      { title: '准备采集器与专用 API Key', description: '下载本页终端采集器，为代理创建仅具有 policies:read 的密钥。代理需要访问平台，但上游 MCP 进程不会继承这个密钥。' },
      { title: '在启动客户端的终端中设置环境变量', description: environmentTabs },
      { title: '修改客户端 MCP 配置', description: '将原 MCP 的 command 和 args 放到代理参数最后一个 -- 后面。下例中的绝对路径需要替换为你电脑上的实际路径；保留原服务需要的其他环境变量。' },
      { title: '重新启动客户端并验证', description: '先调用一个只读工具，再在运行时防护添加一个独特的测试命令黑名单，确认调用被拒绝并出现拦截记录。禁用测试规则后复测，验证启停确实生效。' },
    ]} />
    {configTabs}
    <Alert showIcon type="info" message="配置位置"
      description="Claude Code 项目使用 .mcp.json；Cursor 项目使用 .cursor/mcp.json。企业集中部署可以由终端管理系统下发相同代理命令，密钥通过受控环境变量提供。未经过代理的其他进程不会被这个 stdio 代理拦截。" />
    <Typography.Paragraph>代理拒绝危险请求并对响应脱敏；策略服务不可达时拒绝转发。代理的 stdout 只输出 MCP 消息，诊断日志写入 stderr。真实密钥接入前，可先按 <Typography.Text code>docs/local-onboarding-smoke.md</Typography.Text> 运行本地模拟验收。</Typography.Paragraph>
  </Panel>{httpGuide}</>;
}

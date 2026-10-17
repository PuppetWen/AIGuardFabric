import { useGuideCopy } from './useGuideCopy';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Collapse, Descriptions, Space, Steps, Table, Tabs, Typography } from 'antd';
import { Link, useSearchParams } from 'react-router-dom';
import { PageHeader, DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import { McpGuide } from './McpGuide';
import { CaseResponseGuide } from './cases/CaseResponseGuide';
import { IntegrationGuide } from './integrations/IntegrationGuide';
import { CloudGuide } from './alicloud/CloudGuide';
import { AssetGuide } from './AssetGuide';
import { SearchGuide } from './SearchGuide';
import { RuleGuide } from './rules/RuleGuide';
import { ScanGuide } from './findings/ScanGuide';
import { OverviewGuide } from './OverviewGuide';
import { RedteamGuide } from './redteam/RedteamGuide';
import { ApiRetryGuide } from './ApiRetryGuide';
import { ObservationGuide } from './ObservationGuide';
import { ModelUsageGuide } from './models/ModelUsageGuide';
import { AgentConnectionGuide } from './agents/AgentConnectionGuide';
import { SkillGuide } from './skills/SkillGuide';
import { IdentityGuide } from './IdentityGuide';
import { powershellSecretPrompt } from './powershellSecret';

interface Artifact { platform: string; url: string; sha256: string; sizeBytes: number }
function Code({ children }: { children: string }) {
  return <Typography.Paragraph copyable={{ text: children }} style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
    padding: 14, border: '1px solid var(--border-color, #334155)', borderRadius: 8, fontFamily: 'monospace' }}>{children}</Typography.Paragraph>;
}

export default function GuidePage() {
  const copy = useGuideCopy();
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get('tab');
  const guideTab = ['cases', 'integrations', 'cloud', 'identity', 'mcp', 'start',
    'platforms', 'operations'].includes(requestedTab ?? '') ? (requestedTab ?? 'start') : 'start';
  const base = window.location.origin;
  const tenant = useAuthStore(s => s.tenant);
  const artifacts = useApiQuery('agent-downloads', () => callApi<{ items: Artifact[] }>('/downloads/agents',
    () => ({ items: [] }), { noFallback: true }));
  const collector = `$env:AGF_MOCK_MODE='0'
$env:AGF_AGENT_SERVER_URL='${base}'
$env:AGF_AGENT_TENANT_ID='${tenant?.id ?? ''}'
${powershellSecretPrompt('AGF_AGENT_TOKEN', copy.pasteAnApiKeyWithSourcesWrite)}
# ${zh ? '可选：改成要发现项目级 MCP 配置的绝对目录' : 'Optional: set absolute roots for project-scoped MCP discovery'}
# $env:AGF_AGENT_PROJECT_ROOTS='D:\\RepoA;D:\\RepoB'
.\\agf-agent.exe tls-check
.\\agf-agent.exe run --once --data-dir .\\agf-data
# ${copy.afterTheFirstSuccessfulReportRunContinuously}
.\\agf-agent.exe run --interval 60 --data-dir .\\agf-data`;
  const linux = `export AGF_MOCK_MODE=0
export AGF_AGENT_SERVER_URL='${base}'
export AGF_AGENT_TENANT_ID='${tenant?.id ?? ''}'
printf 'API Key: '; read -r -s AGF_AGENT_TOKEN; export AGF_AGENT_TOKEN; printf '\\n'
# ${zh ? '可选：改成要发现项目级 MCP 配置的绝对目录' : 'Optional: set absolute roots for project-scoped MCP discovery'}
# export AGF_AGENT_PROJECT_ROOTS='/workspace/repo-a:/workspace/repo-b'
chmod +x ./agf-agent
./agf-agent run --once --data-dir ./agf-data
./agf-agent run --interval 60 --data-dir ./agf-data`;
  const chat = `$env:OPENAI_BASE_URL='${base}/v1'
${powershellSecretPrompt('OPENAI_API_KEY', copy.pasteAnApiKeyWithModelsRead)}
$headers=@{Authorization="Bearer $env:OPENAI_API_KEY"}
Invoke-RestMethod "$env:OPENAI_BASE_URL/models" -Headers $headers
$body=@{model='auto';messages=@(@{role='user';content='${copy.pleaseReplyConnectionSuccessful}'});max_tokens=64} | ConvertTo-Json -Depth 8
Invoke-RestMethod "$env:OPENAI_BASE_URL/chat/completions" -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))`;
  const claude = `$env:ANTHROPIC_BASE_URL='${base}'
$env:ANTHROPIC_MODEL='<${zh ? '模型接入配置中的模型 ID' : 'model ID from gateway configuration'}>'
${powershellSecretPrompt('ANTHROPIC_API_KEY', copy.pasteAnApiKeyWithModelsRead)}
claude --bare --print --model $env:ANTHROPIC_MODEL '${zh ? '只回答 OK' : 'Reply with only OK'}'`;
  const platforms = [
    { name: 'Claude Code', mode: copy.discoverEndpointAssets, steps: copy.runTheCollectorAsTheUserWho },
    { name: 'Cursor', mode: copy.assetDiscoveryAndModelGateway, steps: copy.runTheCollectorToDiscoverCursorAnd },
    { name: copy.langgraphCustomAgent, mode: copy.modelGateway, steps: copy.setTheOpenaiClientBaseUrlAnd },
    { name: 'Dify', mode: copy.modelGateway, steps: copy.inAProviderConfigurationSupportingOpenaiCompatible },
    { name: copy.cozeHostedAgent, mode: copy.useSupportedPlatformIntegration, steps: copy.setThePlatformUrlWhereCustomModel },
    { name: 'Ollama / vLLM', mode: copy.privateModel, steps: copy.registerTheEndpointProtocolAndLocalModel },
    { name: copy.openaiAzureAnthropicGeminiOtherProviders, mode: copy.providerAdapters, steps: copy.selectTheProviderProtocolAndEnterIts },
  ];
  return <>
    <PageHeader title={copy.connectionAndOperationGuide} subtitle={copy.connectVerifyAndRespondUsingThisPlatform} />
    <Alert showIcon type="info" message={copy.verifyTheCompleteFlowOnOneDevice}
      description={copy.confirmIntegrationThroughRecentAssetActivityIngested} style={{ marginBottom: 16 }} />
    <Tabs activeKey={guideTab} onChange={key => setSearchParams({ tab: key })} items={[
      { key: 'cases', label: copy.caseResponseSoar, children: <CaseResponseGuide /> },
      { key: 'integrations', label: copy.externalIntegrations, children: <IntegrationGuide /> },
      { key: 'cloud', label: copy.alibabaCloud, children: <CloudGuide /> },
      { key: 'identity', label: zh ? '企业身份' : 'Enterprise identity', children: <IdentityGuide /> },
      { key: 'mcp', label: copy.mcpRuntimeProxy, children: <McpGuide base={base} /> },
      { key: 'start', label: copy.gettingStarted, children: <Panel>
        <Steps direction="vertical" items={[
          { title: copy.confirmYourAccountAndTenant, description: <span>{copy.in}<Link to="/settings">{copy.settings}</Link>{copy.addMembersAndCreateSeparateKeysFor}</span> },
          { title: copy.connectTheFirstEndpoint, description: copy.openEndpointCollectorAndDownloadTheBuild },
          { title: copy.configureModelsAndLogSources, description: <span>{copy.in}<Link to="/models">{copy.modelGateway}</Link>{copy.addAnEndpointIn}<Link to="/ingest">{copy.ingestion}</Link>{copy.configureLogInputProviderCredentialsAndPlatform}</span> },
          { title: copy.verifyDetectionAndResponse, description: <span>{copy.open}<Link to="/assets">{copy.assetInventory}</Link>{copy.toVerifyDiscoveryAndRunAScan}<Link to="/findings">{copy.findings}</Link>{copy.reviewEvidenceHandleAlertsLinkCasesVerify}</span> },
          { title: copy.expandTheEnterpriseDeployment, description: copy.assignAccountsCredentialsAndDataClassificationBy },
        ]} />
      </Panel> },
      { key: 'agent', label: copy.endpointCollector, children: <Space direction="vertical" style={{ width: '100%' }}>
        <AgentConnectionGuide />
        <Panel title={copy.step1DownloadTheCollectorAndVerifySha}>
          <DataState loading={artifacts.isLoading} error={artifacts.error}>
            <Table rowKey="platform" pagination={false} dataSource={artifacts.data?.data.items ?? []} columns={[
              { title: copy.operatingSystem, dataIndex: 'platform' },
              { title: 'SHA-256', dataIndex: 'sha256', render: (v: string) => <Typography.Text code copyable>{v}</Typography.Text> },
              { title: copy.download, render: (_, row) => <Button href={row.url}>{copy.downloadCollector}</Button> },
            ]} />
          </DataState>
          <Typography.Paragraph>{copy.placeTheProgramInItsOwnDirectory}<Typography.Text code>Get-FileHash .\agf-agent.exe -Algorithm SHA256</Typography.Text>{copy.ifABuildIsUnavailableBuildIn}<Typography.Text code>cargo build --release -p agf-agent --bin agf-agent</Typography.Text>.</Typography.Paragraph>
        </Panel>
        <Panel title={copy.step2CreateACollectorApiKeyAnd}>
          <Typography.Paragraph>{copy.underSettingsApiKeysCreateAKey}</Typography.Paragraph>
          <Tabs items={[{ key: 'win', label: 'Windows PowerShell', children: <Code>{collector}</Code> },
            { key: 'unix', label: 'Linux / macOS (Bash / zsh)', children: <Code>{linux}</Code> }]} />
          <Typography.Paragraph>{copy.forAPrivateHttpsCaSetAgf}</Typography.Paragraph>
        </Panel>
        <Panel title={copy.step3VerifyAndStopCollection}><Typography.Paragraph>{copy.searchAssetInventoryByHostnameOrAgent}</Typography.Paragraph></Panel>
      </Space> },
      { key: 'platforms', label: copy.applicationsAndModels, children: <Space direction="vertical" style={{ width: '100%' }}>
        <ModelUsageGuide /><Panel title={copy.connectionOptions}><Table rowKey="name" dataSource={platforms} pagination={false} columns={[
          { title: copy.applicationPlatform, dataIndex: 'name', width: 210 }, { title: copy.connectionMethod, dataIndex: 'mode', width: 180 },
          { title: copy.instructions, dataIndex: 'steps' },
        ]} /></Panel>
        <Panel title={copy.testAnOpenaiCompatibleClient}><Code>{chat}</Code>
          <Descriptions column={1} items={[
            { key: 'base', label: copy.clientBaseUrl, children: <Typography.Text copyable>{`${base}/v1`}</Typography.Text> },
            { key: 'tenant', label: copy.currentTenant, children: tenant?.id },
            { key: 'stream', label: copy.streaming, children: copy.setStreamTrueToReceiveSseWhen },
            { key: 'class', label: copy.dataClassification, children: copy.setXAgfDataClassToPublic },
          ]} />
        </Panel>
        <Panel title={zh ? 'Claude Code：原生 Messages 接入' : 'Claude Code: native Messages gateway'}>
          <Typography.Paragraph>{zh
            ? '先在模型接入配置添加支持流式和工具的 Mock 或 Anthropic 端点，再创建仅供模型调用的 models:read、models:write Key。下方 Base URL 是平台根地址，不加 /v1；模型 ID 与端点保持一致。'
            : 'Register a streaming, tool-capable Mock or Anthropic endpoint and create a dedicated models:read/models:write key. The Base URL below is the platform root without /v1; use the endpoint model ID.'}</Typography.Paragraph>
          <Code>{claude}</Code>
          <Alert showIcon type="warning" message={zh ? '原生 Claude 扩展仅支持 Anthropic 端点' : 'Native Claude extensions require an Anthropic endpoint'}
            description={zh
              ? '默认请求中的思考、签名、context_management 和提示缓存标记会透传给 Anthropic 端点；Mock 只验证链路。消息若被策略脱敏改写，原生透传会被拒绝。跨协议接入其它厂商时可设置 CLAUDE_CODE_DISABLE_THINKING=1 和 CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1，使用基础模式；若仍发送原生选项，请改用 Anthropic 端点。命令成功后检查模型用量，再在项目目录测试无害工具调用。若客户端报告 group 不允许 /v1/messages 且平台无用量记录，先检查本机代理或组织托管策略。MCP 需另用 Key；PDF/文件块和服务端工具尚未完整兼容。'
              : 'Thinking, signatures, context_management and prompt-cache markers pass through to Anthropic endpoints; Mock verifies transport only. Native forwarding is rejected if policy redacts messages. For a basic cross-provider path, set CLAUDE_CODE_DISABLE_THINKING=1 and CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1; if the client still sends native options, select an Anthropic endpoint. Check usage after the smoke test, then test a harmless tool call in your project. If the client reports that its group disallows /v1/messages and platform usage is empty, check local proxy or managed client policy. MCP needs a separate key. PDF/file blocks and server tools remain incomplete.'} />
        </Panel>
      </Space> },
      { key: 'operations', label: copy.operationsAndTroubleshooting, children: <Panel><Collapse items={[
        { key: 'inventory', label: copy.assetInventory, children: <><AssetGuide /><ObservationGuide /><SkillGuide /></> },
        { key: 'search', label: zh ? '搜索与告警' : 'Search & alerts', children: <SearchGuide /> },
        { key: 'tenants', label: copy.enterpriseTenantsAndMembers, children: copy.aPlatformAdministratorCreatesAnOrganizationUnder },
        { key: 'scans', label: zh ? '内容扫描与模型研判' : 'Content scans and model judgements', children: <ScanGuide /> },
        { key: 'overview', label: zh ? '总览指标与权限' : 'Overview metrics and permissions', children: <OverviewGuide /> },
        { key: 'redteam', label: zh ? '红队战役与 CI' : 'Red-team campaigns and CI', children: <RedteamGuide /> },
        { key: 'retries', label: zh ? 'API 重试与去重' : 'API retries and deduplication', children: <ApiRetryGuide /> },
        { key: 'rules', label: copy.publishRollOutAndRestoreRules, children: <RuleGuide /> },
        { key: 'reports', label: copy.reportDownloadsAndSchedules, children: copy.configureAndTestRecipientsUnderSettingsNotification },
        { key: 'recovery', label: copy.eventRecovery, children: <Space direction="vertical">
          <Typography.Paragraph>{copy.eventRecoverySteps}</Typography.Paragraph>
          <Link to="/ingest">{copy.openIngestRecovery}</Link></Space> },
        { key: 'azure', label: copy.azureEndpointConfiguration, children: copy.useHttpsResourceOpenaiAzureComOpenai },
        { key: 'messages', label: copy.basicAnthropicMessagesClients, children: copy.thePlatformExposesV1MessagesForText },
        { key: 'workflow', label: copy.assetsFindingsAlertsCasesPolicyReports, children: <ol>
          <li>{copy.checkAssetNamesOwnersDepartmentsDataClasses}</li>
          <li>{copy.runAScanAndInspectMatchedRules}</li>
          <li>{copy.acknowledgeAssignAndCloseAlertsLinkEvidence}</li>
          <li>{copy.simulatePolicyMatchingBeforeEnablingAPolicy}</li>
          <li>{copy.verifyActualEnforcementRecordsInRuntimeProtection}</li>
        </ol> },
        { key: '401', label: copy.step401403AuthenticationOrPermissions, children: copy.for401CheckForExpiredOrRevoked },
        { key: 'network', label: copy.unreachableEndpointOrModelTimeout, children: copy.firstAccessHealthzFromTheTargetDevice },
        { key: 'mock', label: copy.responsesRemainSimulated, children: copy.checkTheEndpointMockSettingAndDeployment },
        { key: 'missing', label: copy.missingApplicationsOrStaleData, children: copy.runTheCollectorAsTheApplicationS },
        { key: 'security', label: copy.credentialsAndEnterpriseDeployment, children: copy.createSeparateApiKeysForEachPurpose },
      ]} /></Panel> },
    ]} />
  </>;
}

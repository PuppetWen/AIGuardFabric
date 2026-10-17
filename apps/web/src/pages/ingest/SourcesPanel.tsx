import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Alert, Button, Drawer, Input, Popconfirm, Space, Switch, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { NativeSourceGuide } from './NativeSourceGuide';
import { logSourcesApi } from '@/api/logSources';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { HealthTag } from '@/components/Tags';
import { useAuthStore } from '@/stores/authStore';
import type { LogSource } from '@/types/domain';
import { powershellSecretPrompt } from '../powershellSecret';

interface Props {
  canWrite: boolean;
  loading: boolean; error: unknown; sources: LogSource[]; total: number; page: number;
  query: string; onQuery: (value: string) => void; onPage: (value: number) => void;
  onSelectReplay: (id: string) => void; onEdit: (value: LogSource) => void; onRefetch: () => void;
}
export function SourcesPanel({ canWrite, loading, error, sources, total, page, query, onQuery, onPage, onSelectReplay, onEdit, onRefetch }: Props) {
  const zh = !(useTranslation().i18n.language?.startsWith('en') ?? false);
  const text = (cn: string, en: string) => zh ? cn : en;
  const [busy, setBusy] = useState<string>();
  const [result, setResult] = useState<{ error: boolean; text: string }>();
  const [guide, setGuide] = useState<LogSource>();
  const tenant = useAuthStore((state) => state.tenant);
  const run = async (source: LogSource, action: () => Promise<string>) => {
    setBusy(source.id); setResult(undefined);
    try { setResult({ error: false, text: await action() }); onRefetch(); }
    catch (reason) { setResult({ error: true, text: reason instanceof Error ? reason.message : String(reason) }); }
    finally { setBusy(undefined); }
  };
  const columns: ColumnsType<LogSource> = [
    { title: text('日志源', 'Log source'), dataIndex: 'name', width: 210, render: (name: string, source) =>
      <Space direction="vertical" size={0}><Typography.Link onClick={() => onSelectReplay(source.id)}>{name}</Typography.Link>
        <Typography.Text type="secondary">{source.protocol}</Typography.Text></Space> },
    { title: text('地址', 'Endpoint'), dataIndex: 'endpoint', width: 300, render: (value: string) =>
      <Typography.Text style={{ wordBreak: 'break-all' }} copyable>{value}</Typography.Text> },
    { title: text('状态', 'Status'), width: 100, render: (_, source) => source.enabled ? <HealthTag health={source.health} /> : <Tag>{text('已停用', 'Disabled')}</Tag> },
    { title: text('累计保存', 'Saved'), dataIndex: 'totalEvents', width: 95, render: (value?: number) => value ?? '—' },
    { title: text('解析命中', 'Parsed'), dataIndex: 'matched', width: 95, render: (value?: number) => value ?? '—' },
    { title: text('最近接入', 'Latest event'), dataIndex: 'lastEventAt', width: 185, render: (value?: string) =>
      value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString(zh ? 'zh-CN' : 'en-US', { hour12: false }) : '—' },
    { title: text('最近错误', 'Latest error'), dataIndex: 'lastError', width: 200, render: (value?: string) => value || '—' },
    { title: text('启用', 'Enabled'), width: 85, render: (_, source) => <Switch size="small" checked={source.enabled}
      loading={busy === source.id} disabled={!canWrite || busy !== undefined}
      onChange={(enabled) => void run(source, async () => { await logSourcesApi.toggle(source.id, enabled); return enabled ? text('日志源已启用', 'Source enabled') : text('日志源已停用', 'Source disabled'); })} /> },
    { title: text('操作', 'Actions'), width: 260, fixed: 'right', render: (_, source) => <Space wrap>
      <Button size="small" onClick={() => setGuide(source)}>{text('接入指南', 'Connection guide')}</Button>
      <Button size="small" disabled={!canWrite || busy !== undefined} onClick={() => onEdit(source)}>{text('编辑', 'Edit')}</Button>
      {!source.nativeReceiver && source.mode === 'pull' && <Button size="small" disabled={!canWrite || !source.enabled || busy !== undefined}
        onClick={() => void run(source, async () => {
          const value = (await logSourcesApi.poll(source.id)).data;
          return text(`收到 ${value.received} 条，保存 ${value.accepted} 条，解析命中 ${value.matched} 条，失败 ${value.failed} 条。`,
            `Received ${value.received}, saved ${value.accepted}, parsed ${value.matched}, failed ${value.failed}. `) + value.errors.join('；');
        })}>{text('立即拉取', 'Pull now')}</Button>}
      <Popconfirm title={text('删除此接入配置？', 'Delete this source?')}
        description={text('停止后续接入，已保存日志和事件仍然保留。', 'Future ingest stops; saved logs and events remain.')}
        onConfirm={() => run(source, async () => { await logSourcesApi.remove(source.id); return text('日志源配置已删除', 'Source configuration deleted'); })}>
        <Button size="small" danger disabled={!canWrite || busy !== undefined}>{text('删除', 'Delete')}</Button>
      </Popconfirm>
    </Space> },
  ];
  const url = guide && !guide.nativeReceiver ? new URL(guide.endpoint, window.location.origin).href : '';
  const command = [
    powershellSecretPrompt('AGF_SOURCE_KEY', text('本租户 sources:write API Key', 'Tenant sources:write API key')),
    '$headers = @{ Authorization = "Bearer $env:AGF_SOURCE_KEY" }',
    '$body = \'{"message":"connection check"}\'',
    "Invoke-RestMethod -Method Post -Uri '" + url.replaceAll("'", "''") + "' -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))",
    'Remove-Item Env:AGF_SOURCE_KEY -ErrorAction SilentlyContinue',
  ].join('\n');
  const aiEvent = '{"message":"controlled test","severity":"high","category":"ai-tool-call","mcp":"<MCP_ASSET_UUID>"}';
  return <Panel title={text('已配置日志源', 'Configured log sources')} padded={false}>
    <Space direction="vertical" style={{ width: '100%', padding: 14 }}>
      <Input.Search allowClear value={query} placeholder={text('搜索全部日志源名称或地址', 'Search all source names or endpoints')}
        onChange={(event) => onQuery(event.target.value)} />
      {result && <Alert closable showIcon type={result.error ? 'error' : 'success'} message={result.text} />}
      <DataState loading={loading} error={error} skeletonRows={5}>
        <Table rowKey="id" size="small" dataSource={sources} columns={columns} scroll={{ x: 1650 }}
          pagination={{ current: page, pageSize: 10, total, showSizeChanger: false, onChange: onPage }} />
      </DataState>
    </Space>
    <Drawer open={!!guide} width={760} title={(guide?.name ?? '') + ' · ' + text('接入指南', 'Connection guide')}
      onClose={() => setGuide(undefined)}>
      {guide?.nativeReceiver && <NativeSourceGuide source={guide} tenant={tenant?.id ?? ''} />}
      {guide && !guide.nativeReceiver && <Space direction="vertical" size={18} style={{ width: '100%' }}>
        <Typography.Paragraph copyable>{url}</Typography.Paragraph>
        {guide.mode === 'push' ? <>
          <Alert showIcon type="info" message={text('创建本租户采集 API Key', 'Create a tenant ingest API key')}
            description={<>{text('在 ', 'In ')}<Link to="/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite">{text('设置 → API Key', 'Settings → API keys')}</Link>
              {text(' 创建仅含 sources:write 的密钥。在目标 Windows 主机执行下方命令；密钥输入不回显。收到响应后刷新列表，检查保存和解析条数。',
                ', create a key with only sources:write. Run the command on the sending Windows host; key input is hidden. Refresh this list and check saved and parsed counts.')}</>} />
          <Typography.Paragraph copyable={{ text: command }}><pre style={{ whiteSpace: 'pre-wrap' }}>{command}</pre></Typography.Paragraph>
          <Typography.Paragraph>{text('Webhook 地址填上方 URL，Authorization 使用 Bearer API Key。支持 JSON 对象、数组、NDJSON 或 UTF-8 文本，每批最多 1000 条、2 MiB；对外接入须由 HTTPS 反向代理承载。',
            'Use the URL above with an Authorization Bearer API key. JSON objects, arrays, NDJSON and UTF-8 text are supported, up to 1,000 records or 2 MiB per batch. Use an HTTPS reverse proxy for external senders.')}</Typography.Paragraph>
          <Typography.Paragraph>{text('要触发 AI 工具风险链路，请先给本源选 JSONPath 模板：message → message、severity → event.severity、category → event.category、mcp → ai.mcp_server_id；必填字段设为 message 和 mcp。把下例 MCP_ASSET_UUID 换成当前租户资产台账中的 MCP 服务 UUID，并启用目标为 tool-arguments 的检测规则。投递接受后查看事件分析、风险发现、告警和待审批案件；计数为零时先检查解析命中与规则目标。',
            'For the AI tool risk workflow, select a JSONPath parser: map message → message, severity → event.severity, category → event.category, and mcp → ai.mcp_server_id; require message and mcp. Replace MCP_ASSET_UUID below with an MCP server asset UUID from this tenant, then enable a detection rule targeting tool-arguments. After delivery, check analysis progress, findings, alerts and pending-approval cases. If counts stay zero, check parser matches and the rule target.')}</Typography.Paragraph>
          <Typography.Paragraph copyable={{ text: aiEvent }}><code>{aiEvent}</code></Typography.Paragraph>
        </> : <Alert showIcon type="info" message={text('定时拉取与增量游标', 'Scheduled pull and incremental cursors')}
          description={text('上游返回 JSON 对象、数组或 NDJSON，每批最多 1000 条、2 MiB。上游通过 X-AGF-Next-Cursor 返回游标，平台下次通过 X-AGF-Cursor 发送。只有全部保存成功才推进游标。点击“立即拉取”验证。',
            'Upstream returns JSON objects, arrays or NDJSON, up to 1,000 records or 2 MiB per batch. X-AGF-Next-Cursor returns a cursor, then the platform sends X-AGF-Cursor on the next pull. The cursor advances only after all records are saved. Use Pull now to verify.')} />}
        <Typography.Paragraph>{text('未命中的原始日志会保留。选择适配的解析模板后，可点击源名称回放。停用阻止新数据接入；删除配置保留历史日志。',
          'Unmatched raw logs are retained. Select a parser and click the source name to replay. Disabling stops new ingest; deleting the configuration retains historical logs.')}</Typography.Paragraph>
      </Space>}
    </Drawer>
  </Panel>;
}


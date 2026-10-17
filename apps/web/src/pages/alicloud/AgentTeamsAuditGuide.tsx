import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Alert, Button, Space, Steps, Table, Typography } from 'antd';
import { API_BASE_URL } from '@/api/config';
import { newRequestId } from '@/utils/requestId';
import type { AgentTeamsAuditBinding } from '@/types/agentTeamsAudit';
import type { AgentTeam } from '@/types/domain';
import { powershellSecretPrompt } from '../powershellSecret';

interface Props {
  binding?: AgentTeamsAuditBinding;
  currentCloudVersion: number;
  teams: AgentTeam[];
}

export default function AgentTeamsAuditGuide({ binding, currentCloudVersion, teams }: Props) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [sample, setSample] = useState(() => ({ at: Date.now(), id: newRequestId() }));
  const ready = !!binding && binding.acceptsEvents && binding.state !== 'disabled' && binding.cloudVersion === currentCloudVersion;
  const endpoint = ready ? new URL(`${API_BASE_URL.replace(/\/$/, '')}/api/v1/alicloud/agentteams/audit-sources/${encodeURIComponent(binding.sourceId)}/events`, window.location.origin).href : '';
  const payload = useMemo(() => {
    if (!binding) return '';
    const eventTime = new Date(Math.max(sample.at, Date.parse(binding.boundAt))).toISOString();
    const events = [{ event_id: sample.id, event_time: eventTime, kind: 'heartbeat' }];
    return JSON.stringify({ binding_id: binding.bindingId, events }, null, 2);
  }, [binding, sample]);
  const command = [
    powershellSecretPrompt('AGF_SOURCE_KEY', text('本租户 sources:write API Key', 'Tenant sources:write API key')),
    '$headers = @{ Authorization = "Bearer $env:AGF_SOURCE_KEY" }',
    "$body = @'", payload, "'@",
    "Invoke-RestMethod -Method Post -Uri '" + endpoint.replaceAll("'", "''") + "' -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))",
    'Remove-Item Env:AGF_SOURCE_KEY -ErrorAction SilentlyContinue',
  ].join('\n');

  return <Space direction="vertical" size={14} style={{ width: '100%' }}>
    <Steps size="small" direction="vertical" items={[
      { title: text('完成团队盘点', 'Complete inventory'), description: text('在本页“云服务接入与操作”找到 AgentTeams，点击“配置与接入”保存账号与实例，然后打开“台账同步”，点击“完整盘点并同步台账”。更换实例或云配置后重新同步并绑定；相同成员与资产映射的日常盘点可继续使用原绑定。', 'Find AgentTeams in Cloud connections and operations, choose Configure and save the account and instance. In Inventory sync, choose Read complete inventory and synchronize. Sync and rebind after changing instance or cloud configuration; daily inventory with unchanged membership and asset mapping preserves the binding.') },
      { title: text('创建 HTTP Webhook 日志源', 'Create an HTTP Webhook source'), description: <><Link to="/ingest">{text('打开日志接入，接入方式选择 HTTP Webhook 并启用日志源', 'Open Log ingest, select HTTP Webhook and enable the source')}</Link>{text('；解析模板可留空。完成绑定后，发送端使用本页生成的审计接入地址。', '; leave the parser blank. After binding, send to the audit endpoint generated on this page.')}</> },
      { title: text('绑定当前实例', 'Bind the current instance'), description: text('在此页选择日志源并绑定。绑定版本用于防止覆盖他人的修改；重新绑定生成新的 binding_id，发送端必须更新，并清空或隔离旧账号、旧绑定的待发送队列。事件发生时间不得早于当前绑定。', 'Select and bind the source here. The binding version prevents overwriting concurrent changes. Rebinding generates a new binding_id: update senders and clear or isolate queues for the previous account or binding. Event occurrence time must not precede the current binding.') },
      { title: text('创建最小权限 Key', 'Create a minimum-permission key'), description: <><Link to="/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite">{text('创建仅含 sources:write 的 API Key', 'Create an API key with only sources:write')}</Link>{text('。Key 属于当前租户，并非日志源专用；需要管理员创建时将本页指南交给管理员。', '. The key is tenant-scoped, not restricted to this source. Ask the administrator to create it if needed.')}</> },
      { title: text('发送平台审计事件', 'Send platform audit events'), description: text('应用或日志转发器调用下方平台地址。把实际团队、Worker 名称、事件时间和 trace/span 写入事件；仅心跳不产生调用量。重复发送同一事件须保留 event_id，新事件使用新的 ID。', 'Have the application or log forwarder call the platform endpoint below. Send actual team and Worker names, event times and trace/span IDs; heartbeats do not add call volume. Preserve event_id for retries and use a new ID for each new event.') },
      { title: text('验证日志和指标', 'Verify events and metrics'), description: text('刷新本页检查来源变为活跃、消息预览和调用链，再到团队盘点查看调用量。24 小时覆盖和活跃状态独立显示；尚未观测不能解释为零调用。', 'Refresh to check active source status, message previews and traces, then inspect call volume in Inventory. The full 24-hour window is separate from activity; unobserved does not mean zero calls.') },
    ]} />
    <Alert type="info" showIcon message={text('应用日志与平台权限', 'Application logs and platform permissions')}
      description={text('绑定和管理需要 sources:write、alicloud:write；查看需要 sources:read、alicloud:read。应用只需租户 sources:write Key。这里接收经过平台 Key 认证的审计上报，不把未认证 OTLP 当成可信来源，也不会把上报中的“已授权”当成授权证据。', 'Binding and management need sources:write and alicloud:write; viewing needs sources:read and alicloud:read. The application needs only a tenant sources:write key. This endpoint authenticates reports with that key; unauthenticated OTLP and caller-provided authorization claims are not trusted authorization evidence.')} />
    <Typography.Paragraph>{text('仅发送契约中的事件字段。不要提供 tenant、account、资产 ID 或 authorized；平台按照绑定实例解析资产，消息预览经过脱敏。把现有 SDK 或日志转发器采集的真实事件转换为此格式。', 'Send only the event contract fields. Do not send tenant, account, asset IDs or authorized; the platform maps assets using the bound instance and redacts previews. Adapt actual SDK or forwarded audit logs to this format.')}</Typography.Paragraph>
    <Typography.Title level={5}>{text('真实 SDK / 业务日志字段映射', 'Actual SDK / business log field mapping')}</Typography.Title>
    <Typography.Paragraph>{text(`当前盘点有 ${teams.length} 个团队。使用盘点中的实际团队和 Worker 名称；只有实际业务调用才发送 kind=call，连接验证示例只发送心跳。`, `Inventory contains ${teams.length} teams. Use inventoried team and Worker names; emit kind=call only for actual business calls. The connection check below sends only a heartbeat.`)}</Typography.Paragraph>
    <Table size="small" pagination={false} rowKey="field" columns={[
      { title: text('平台字段', 'Platform field'), dataIndex: 'field' },
      { title: text('填写依据', 'Value source'), dataIndex: 'source' },
    ]} dataSource={[
      { field: 'event_id / event_time', source: text('唯一 ID：1–256 个 ASCII 字母、数字、_.:-；实际 UTC 时间为 RFC 3339，不早于绑定、最多晚到 30 天或超前 5 分钟。重试保留 ID 和内容', 'Unique ID: 1–256 ASCII letters, digits or _.:-. Actual UTC occurrence time in RFC 3339, no earlier than binding, at most 30 days late or 5 minutes ahead. Keep ID and content on retries') },
      { field: 'kind', source: text('真实调用 call、消息 message、任务 task；连接检查 heartbeat', 'Actual call, message or task; heartbeat for connection checks') },
      { field: 'from_team / from_worker / to_team / to_worker', source: text('当前实例盘点名称；call 须包含双方 Worker，message 须有发送方，task 至少一方。单团队成员可省略团队名，多团队成员必须指定其已盘点团队', 'Names in current instance inventory; call requires both Workers, message a sender, task at least one participant. Omit the team for a single-team Worker; specify an inventoried team for multi-team membership') },
      { field: 'status', source: text('真实业务结果 success / error / unknown；未记录则省略', 'Actual success / error / unknown result; omit when unrecorded') },
      { field: 'trace_id / span_id / parent_span_id / duration_ms', source: text('实际关联 ID（最多 128 个上述 ASCII 字符）；耗时为非负整数毫秒，最多 7 天。没有实际值就省略', 'Actual correlation IDs, at most 128 of the ASCII characters above. Duration is a nonnegative integer in milliseconds, at most 7 days. Omit unrecorded values') },
      { field: 'task_id / message', source: text('真实任务 ID（最多 128 个上述 ASCII 字符）/ UTF-8 消息（最多 16 KiB）。心跳不带成员、任务或消息；预览脱敏不等于原始证据被删除', 'Actual task ID, at most 128 of the ASCII characters above, and UTF-8 message, at most 16 KiB. Heartbeats carry no participant, task or message. Preview redaction does not delete raw evidence') },
    ]} />
    <Typography.Paragraph>{text('每批最多 1000 条、总请求不超过 2 MiB，并遵守日志源单条大小与 EPS 限制。429 时减小批次并稍后按原内容重试；409 时先区分绑定失效与 ID 内容冲突。建议每分钟发送一次心跳，心跳也占接入容量。', 'At most 1,000 events and 2 MiB per request, within the source message-size and EPS limits. For 429, reduce the batch and retry later with unchanged event content. For 409, distinguish an invalid binding from conflicting content for an ID. Send a heartbeat each minute; heartbeats also consume ingest capacity.')}</Typography.Paragraph>
    {ready ? <>
      {binding.mocked && <Alert type="info" showIcon message={text('当前绑定是 Mock；结果属于模拟环境。', 'This binding is Mock; results belong to the simulated environment.')} />}
      <Typography.Paragraph copyable>{endpoint}</Typography.Paragraph>
      <Button size="small" onClick={() => setSample({ at: Date.now(), id: newRequestId() })}>{text('更新示例时间与事件 ID', 'Update example time and event ID')}</Button>
      <Typography.Paragraph copyable={{ text: payload }}><pre style={{ whiteSpace: 'pre-wrap' }}>{payload}</pre></Typography.Paragraph>
      <Typography.Paragraph>{text('Windows 验证命令：按提示输入 Key，输入不回显。复制的事件时间用于当前验证；实际集成中使用事件发生时的 UTC 时间，并生成真实 trace/span 和事件 ID。', 'Windows verification command: enter the key at the hidden prompt. The copied timestamp is for this check; integrations must supply occurrence time in UTC and actual trace/span and event IDs.')}</Typography.Paragraph>
      <Typography.Paragraph copyable={{ text: command }}><pre style={{ whiteSpace: 'pre-wrap' }}>{command}</pre></Typography.Paragraph>
    </> : <Alert type="info" showIcon message={text('完成盘点并选择当前有效绑定后，将生成 JSON 和发送命令。', 'Complete inventory and select a current enabled binding to generate JSON and the send command.')} />}
  </Space>;
}

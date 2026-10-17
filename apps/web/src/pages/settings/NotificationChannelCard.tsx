import { Card, Input, InputNumber, Select, Space, Switch, Button, Typography, Tag } from 'antd';
import { useNotificationText } from './notificationText';
import type { ChannelRow } from '@/api/notifications';
const labels: Record<string, string> = {
  email: '邮件 SMTP', webhook: '通用 Webhook', dingtalk: '钉钉机器人', feishu: '飞书机器人',
  wecom: '企业微信机器人', slack: 'Slack', sms: '企业短信 HTTP 网关', pagerduty: 'PagerDuty', 'in-app': '站内消息',
};
const secretFields: Record<string, [string, string][]> = {
  email: [['smtp_password', 'SMTP 密码']], dingtalk: [['signing_secret', '加签密钥（可选）']],
  feishu: [['signing_secret', '签名密钥（可选）']], webhook: [['auth_header_value', 'Authorization 头（可选）']],
  sms: [['token', '网关 Bearer Token（可选）']], pagerduty: [['routing_key', 'Events V2 Integration Key']],
};
export function NotificationChannelCard({ row, busy, conflicted, onChange, onSave }: {
  row: ChannelRow; busy: boolean; conflicted: boolean; onChange: (row: ChannelRow) => void; onSave: (test: boolean) => void;
}) {
  const text = useNotificationText();
  const settings = JSON.parse(row.settingsJson || '{}') as Record<string, unknown>;
  const update = (key: string, value: unknown) => onChange({ ...row, settingsJson: JSON.stringify({ ...settings, [key]: value }) });
  const secret = (key: string, value: string) => onChange({ ...row, editingSecrets: { ...row.editingSecrets, [key]: value } });
  const targetLabel = text(row.channel === 'email' ? '收件人（逗号分隔）' : row.channel === 'sms' ? '接收号码（逗号分隔）' : '机器人 Webhook 完整 URL');
  return <Card size="small" title={<Space>{text(labels[row.channel] ?? row.channel)}
    <Tag color={row.mocked ? 'orange' : 'blue'}>{text(row.mocked ? '模拟模式' : '实际投递')}</Tag></Space>}
    extra={<Switch aria-label={text('启用') + ' ' + text(labels[row.channel] ?? row.channel)} checked={row.enabled} onChange={(enabled) => onChange({ ...row, enabled })} />}>
    <Space direction="vertical" style={{ width: '100%', maxWidth: 760 }}>
      {!['in-app', 'pagerduty'].includes(row.channel) && <label>{targetLabel}
        <Input value={row.target} autoComplete="off" placeholder={row.configured ? text('已有配置；留空保留') : targetLabel}
          onChange={(event) => onChange({ ...row, target: event.target.value })} /></label>}
      {row.channel === 'email' && <>
        <label>{text('SMTP 主机')}<Input value={String(settings.smtp_host ?? '')} placeholder="smtp.example.com" onChange={(e) => update('smtp_host', e.target.value)} /></label>
        <Space><label>{text('端口')}<InputNumber min={1} max={65535} value={Number(settings.smtp_port ?? 587)} onChange={(v) => update('smtp_port', v ?? 587)} /></label>
          <Select style={{ width: 185 }} value={String(settings.smtp_security ?? 'starttls')} onChange={(v) => update('smtp_security', v)}
            options={[{ value: 'starttls', label: text('STARTTLS（推荐）') }, { value: 'tls', label: 'SMTPS / TLS' }, { value: 'none', label: text('内网明文中继') }]} /></Space>
        <label>{text('发件人')}<Input value={String(settings.from ?? '')} onChange={(e) => update('from', e.target.value)} /></label>
        <label>{text('SMTP 用户名')}<Input value={String(settings.smtp_user ?? '')} onChange={(e) => update('smtp_user', e.target.value)} /></label>
      </>}
      {row.channel === 'sms' && <>
        <label>{text('短信网关 URL')}<Input value={String(settings.endpoint ?? '')} onChange={(e) => update('endpoint', e.target.value)} /></label>
        <Typography.Text type="secondary">{text('短信网关协议说明')}</Typography.Text>
      </>}
      {(secretFields[row.channel] ?? []).map(([key, name]) => <label key={key}>{text(name)}
        <Input.Password autoComplete="new-password" value={row.editingSecrets?.[key] ?? ''}
          placeholder={row.secretKeys.includes(key) ? text('已保存；留空保留') : text(name)} onChange={(e) => secret(key, e.target.value)} /></label>)}
      <Space>{text('最低通知等级')}<Select value={row.minSeverity} style={{ width: 135 }} onChange={(minSeverity) => onChange({ ...row, minSeverity })}
        options={['info','low','medium','high','critical'].map((value) => ({ value, label: value }))} />
        <Button type="primary" disabled={busy || conflicted} onClick={() => onSave(false)}>{text('保存')}</Button>
        <Button disabled={busy || conflicted || !row.enabled} onClick={() => onSave(true)}>{text('保存并发送测试')}</Button></Space>
    </Space>
  </Card>;
}

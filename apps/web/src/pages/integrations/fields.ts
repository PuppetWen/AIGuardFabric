export interface SettingField { key: string; zh: string; en: string; placeholder?: string; number?: boolean; choices?: string[] }
export const settingFields: Record<string, SettingField[]> = {
  jira: [
    { key: 'project_key', zh: '项目标识', en: 'Project key', placeholder: 'SEC' },
    { key: 'issue_type', zh: '工单类型', en: 'Issue type', placeholder: 'Task' },
  ],
  zentao: [
    { key: 'product_id', zh: '产品编号', en: 'Product ID', number: true },
    { key: 'opened_by', zh: '创建人账号', en: 'Creator account', placeholder: 'aiguardfabric' },
  ],
  servicenow: [{ key: 'table', zh: '表名', en: 'Table', placeholder: 'incident' }],
  email: [
    { key: 'smtp_host', zh: 'SMTP 主机', en: 'SMTP host', placeholder: 'smtp.example.com' },
    { key: 'smtp_port', zh: 'SMTP 端口', en: 'SMTP port', number: true, placeholder: '587' },
    { key: 'smtp_security', zh: '连接加密', en: 'Transport encryption', choices: ['starttls', 'tls', 'none'] },
    { key: 'smtp_user', zh: 'SMTP 账号', en: 'SMTP user' },
    { key: 'from', zh: '发件人', en: 'Sender', placeholder: 'alerts@example.com' },
    { key: 'to', zh: '收件人（多个用逗号分隔）', en: 'Recipients (comma separated)', placeholder: 'soc@example.com' },
  ],
  'syslog-forwarder': [
    { key: 'protocol', zh: '传输协议', en: 'Transport', choices: ['udp', 'tcp'] },
    { key: 'app_name', zh: '应用标识', en: 'Application name', placeholder: 'aiguardfabric' },
    { key: 'facility', zh: 'Facility 编号（0–23）', en: 'Facility (0–23)', number: true, placeholder: '10' },
  ],
  slack: [{ key: 'channel', zh: '频道（可选）', en: 'Channel (optional)', placeholder: '#soc' }],
};
export const resources: Record<string, string> = { jira: 'issues', servicenow: 'incident', zentao: 'bugs', 'edr-isolation': 'hosts' };
export function pushExample(name: string) {
  if (name === 'jira') return { entity: 'ticket.status', entity_id: 'SEC-1', body: { comment: 'Reviewed by the SOC' } };
  if (name === 'servicenow') return { entity: 'ticket.status', entity_id: 'REMOTE_SYS_ID', body: { work_notes: 'Reviewed by the SOC' } };
  if (name === 'zentao') return { entity: 'ticket.status', entity_id: 'REMOTE_BUG_ID', body: { comment: 'Reviewed by the SOC' } };
  if (name === 'slack') return { entity: 'message.update', entity_id: 'REMOTE_MESSAGE_TS', body: { channel: 'CHANNEL_ID', text: 'Reviewed by the SOC' } };
  return { entity: 'host.isolation', entity_id: 'HOST_ID', body: { action: 'release' } };
}

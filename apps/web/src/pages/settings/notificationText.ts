import { useTranslation } from 'react-i18next';

const english: Record<string, string> = {
  '邮件 SMTP': 'Email SMTP', '通用 Webhook': 'Generic Webhook', '钉钉机器人': 'DingTalk bot',
  '飞书机器人': 'Feishu bot', '企业微信机器人': 'WeCom bot', '企业短信 HTTP 网关': 'Enterprise SMS HTTP gateway',
  '站内消息': 'In-app messages', 'SMTP 密码': 'SMTP password', '加签密钥（可选）': 'Signing secret (optional)',
  '签名密钥（可选）': 'Signing secret (optional)', 'Authorization 头（可选）': 'Authorization header (optional)',
  '网关 Bearer Token（可选）': 'Gateway bearer token (optional)', '收件人（逗号分隔）': 'Recipients (comma-separated)',
  '接收号码（逗号分隔）': 'Phone numbers (comma-separated)', '机器人 Webhook 完整 URL': 'Full webhook URL',
  '模拟模式': 'Mock mode', '实际投递': 'Live delivery', '启用': 'Enable',
  '已有配置；留空保留': 'Configured; leave blank to keep', '已保存；留空保留': 'Saved; leave blank to keep',
  'SMTP 主机': 'SMTP host', '端口': 'Port', 'STARTTLS（推荐）': 'STARTTLS (recommended)',
  '内网明文中继': 'Internal plaintext relay', '发件人': 'Sender', 'SMTP 用户名': 'SMTP username',
  '短信网关 URL': 'SMS gateway URL', '最低通知等级': 'Minimum severity',
  '保存': 'Save', '保存并发送测试': 'Save and send test', '重新加载': 'Reload',
  '读取通知配置失败': 'Could not load notification settings', '投递成功': 'Delivered',
  '通知配置已保存': 'Notification settings saved', '操作失败': 'Operation failed',
  '通知冲突说明': 'Your draft is retained. Copy changes you need before reloading the latest configuration. A changed delivery destination requires re-entering stored channel credentials.',
  '丢弃通知草稿并加载最新配置？': 'Discard notification drafts and load the latest configuration?',
  '模拟测试通过，未发送到外部系统': 'Mock test passed; no external message sent',
  '先配置渠道，再启用通知': 'Configure channels, then enable notifications',
  '渠道配置说明': 'Webhook URLs and credentials are encrypted and are not displayed after saving. Blank fields preserve saved credentials. The test button saves your edits and sends a test message. Mock mode is clearly marked and does not contact external systems.',
  '短信网关协议说明': 'POST JSON: to is an array of phone numbers, text is the message, and idempotency_key identifies retries. The gateway must return accepted: true. An existing enterprise SMS gateway can translate this contract.',
};
const chinese: Record<string, string> = {
  '渠道配置说明': 'Webhook 地址和密码加密保存，保存后不回显。留空保留已有凭据。测试按钮会保存当前配置并发送一条测试通知；模拟模式会明确标记，不会对外发送。',
  '通知冲突说明': '草稿已保留。重新加载会丢弃草稿，请先复制要保留的修改。更换投递地址时须重新填写已保存的渠道凭据。',
  '短信网关协议说明': 'POST JSON：to 为号码数组，text 为通知正文，idempotency_key 为去重键；网关须返回 accepted: true。可对接企业已有短信服务转换层。',
};
export function useNotificationText() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  return (value: string) => zh ? chinese[value] ?? value : english[value] ?? value;
}

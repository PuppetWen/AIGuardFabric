import type { NotificationChannel, UserRole } from '@/types/domain';

export const ROLES: UserRole[] = ['owner', 'admin', 'analyst', 'responder', 'auditor', 'viewer'];
export const CHANNELS: NotificationChannel[] = ['email', 'webhook', 'dingtalk', 'feishu', 'wecom', 'slack', 'sms'];

export interface NotificationRow {
  channel: NotificationChannel;
  target: string;
  enabled: boolean;
}

/** Notification defaults; a fresh list per mount keeps edits scoped to the page. */
export function createNotificationRows(): NotificationRow[] {
  return [
    { channel: 'feishu', target: 'https://open.feishu.cn/open-apis/bot/v2/hook/***', enabled: true },
    { channel: 'email', target: 'ai-sec-oncall@acme.example', enabled: true },
    { channel: 'webhook', target: 'https://soar.intra.acme/hooks/agf', enabled: true },
    { channel: 'dingtalk', target: 'AI 安全值班群机器人', enabled: false },
    { channel: 'sms', target: '+86-138-****-2211', enabled: false },
    { channel: 'slack', target: '', enabled: false },
    { channel: 'wecom', target: '', enabled: false },
  ];
}

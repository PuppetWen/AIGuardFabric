import type { SoarRun } from '@/types/domain';

import { agoHours, agoMinutes } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* SOAR runs                                                           */
/* ------------------------------------------------------------------ */

export const demoSoarRuns: SoarRun[] = [
  {
    id: 'soar-0001',
    caseId: 'CASE-2025-0041',
    playbook: 'ai-shadow-mcp-response',
    status: 'running',
    startedAt: agoHours(4.8),
    finishedAt: null,
    steps: [
      {
        name: '抓取工具清单与进程快照',
        status: 'done',
        output: '已归档 3 个工具定义、1 份 ps 快照、2 份网络连接列表',
        durationMs: 8_420,
      },
      {
        name: '在 egress-proxy 阻断出站',
        status: 'done',
        output: '策略 pol-egress-deny 已下发，阻断 47 次出站',
        durationMs: 640,
      },
      {
        name: 'EDR 隔离受影响主机',
        status: 'running',
        output: 'ops-analyzer.acme.internal 隔离指令已下发，等待终端确认',
        durationMs: 12_000,
      },
      {
        name: '生成凭据轮换工单',
        status: 'pending',
        output: '',
        durationMs: 0,
      },
    ],
  },
  {
    id: 'soar-0002',
    caseId: 'CASE-2025-0040',
    playbook: 'ai-data-exfil-response',
    status: 'running',
    startedAt: agoHours(3.4),
    finishedAt: null,
    steps: [
      {
        name: '解码外带 payload 并评估影响面',
        status: 'done',
        output: '解码出 4,182 条记录，涉及 3 个业务表',
        durationMs: 21_300,
      },
      {
        name: '阻断外传目标域名',
        status: 'done',
        output: 'attacker.example 已加入黑名单，24h 命中 96 次',
        durationMs: 420,
      },
      {
        name: '修复 DLP 探针',
        status: 'running',
        output: '探针重部署中，当前版本 1.2.7 → 1.2.9',
        durationMs: 45_000,
      },
      {
        name: '生成客户通知草稿',
        status: 'pending',
        output: '',
        durationMs: 0,
      },
      {
        name: '回写审计留痕',
        status: 'pending',
        output: '',
        durationMs: 0,
      },
    ],
  },
  {
    id: 'soar-0003',
    caseId: 'CASE-2025-0036',
    playbook: 'identity-token-hardening',
    status: 'succeeded',
    startedAt: agoHours(8),
    finishedAt: agoHours(7.6),
    steps: [
      {
        name: '吊销受影响令牌',
        status: 'done',
        output: '已吊销 1 个主令牌，3 个会话重新认证',
        durationMs: 1_240,
      },
      {
        name: '下发令牌绑定策略',
        status: 'done',
        output: 'pol-token-binding 已生效，绑定会话 ID + 来源指纹',
        durationMs: 860,
      },
      {
        name: '启用跨主机使用告警',
        status: 'done',
        output: '规则 RULE-ID-003 灰度提升至 45%',
        durationMs: 320,
      },
    ],
  },
  {
    id: 'soar-0004',
    caseId: 'CASE-2025-0034',
    playbook: 'log-secret-cleanup',
    status: 'succeeded',
    startedAt: agoHours(60),
    finishedAt: agoHours(59.4),
    steps: [
      {
        name: '定位含明文凭据的日志记录',
        status: 'done',
        output: '命中 41 条记录，涉及 3 个日志源',
        durationMs: 3_400,
      },
      {
        name: '更新解析器脱敏规则',
        status: 'done',
        output: '解析器 pars-http-json 升级至 v2.4.0',
        durationMs: 1_120,
      },
      {
        name: '清理历史明文记录',
        status: 'done',
        output: '已重写 41 条记录，哈希链已重新签名',
        durationMs: 8_900,
      },
    ],
  },
  {
    id: 'soar-0005',
    caseId: 'CASE-2025-0039',
    playbook: 'credential-rotation',
    status: 'queued',
    startedAt: agoMinutes(40),
    finishedAt: null,
    steps: [
      { name: '申请新口令', status: 'pending', output: '', durationMs: 0 },
      { name: '写入 Vault', status: 'pending', output: '', durationMs: 0 },
      { name: '滚动重启 postgres-mcp', status: 'pending', output: '', durationMs: 0 },
      { name: '验证连通性', status: 'pending', output: '', durationMs: 0 },
    ],
  },
];

export function soarRunsForCase(caseId: string): SoarRun[] {
  return demoSoarRuns.filter((run) => run.caseId === caseId);
}

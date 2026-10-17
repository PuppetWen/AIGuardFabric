import type { Case, CaseTimelineEntry } from '@/types/domain';

import { agoHours, agoMinutes, seeded } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Case timeline                                                       */
/* ------------------------------------------------------------------ */

const TIMELINE: Record<string, CaseTimelineEntry[]> = {
  'CASE-2025-0041': [
    {
      id: 'tl-41-1',
      caseId: 'CASE-2025-0041',
      at: agoHours(5.4),
      actor: '系统',
      kind: 'state-change',
      title: '案件创建（new）',
      detail: '由告警 ALR-2025-0318-0001 聚合生成，关联 2 条告警、2 个资产。',
    },
    {
      id: 'tl-41-2',
      caseId: 'CASE-2025-0041',
      at: agoHours(5.1),
      actor: '陈昊',
      kind: 'state-change',
      title: '定级并转入 triaged',
      detail: '确认 shell-mcp 为影子资产，影响面为宿主机 root 权限。',
    },
    {
      id: 'tl-41-3',
      caseId: 'CASE-2025-0041',
      at: agoHours(4.8),
      actor: 'SOAR',
      kind: 'soar',
      title: '执行剧本 ai-shadow-mcp-response',
      detail: '步骤 1/4 完成：抓取当前工具清单与进程快照作为证据。',
    },
    {
      id: 'tl-41-4',
      caseId: 'CASE-2025-0041',
      at: agoHours(4.5),
      actor: '陈昊',
      kind: 'action',
      title: '执行「封禁出口」',
      detail: '在 egress-proxy 阻断 shell-mcp 的公网出站，命中策略 pol-egress-deny。',
    },
    {
      id: 'tl-41-5',
      caseId: 'CASE-2025-0041',
      at: agoHours(3.2),
      actor: '陈昊',
      kind: 'state-change',
      title: '转入 containing',
      detail: '遏制措施生效，仍有 2 台主机的凭据待轮换。',
    },
    {
      id: 'tl-41-6',
      caseId: 'CASE-2025-0041',
      at: agoMinutes(24),
      actor: '孙琪',
      kind: 'note',
      title: '补充说明',
      detail: 'ops-analyzer 的纳管计划已生成，采用 Sidecar 模式，预计零中断。',
    },
  ],
  'CASE-2025-0040': [
    {
      id: 'tl-40-1',
      caseId: 'CASE-2025-0040',
      at: agoHours(4.2),
      actor: '系统',
      kind: 'state-change',
      title: '案件创建（new）',
      detail: '数据域严重告警自动升级为案件。',
    },
    {
      id: 'tl-40-2',
      caseId: 'CASE-2025-0040',
      at: agoHours(4),
      actor: '王萌',
      kind: 'action',
      title: '执行「封禁出口」',
      detail: 'attacker.example 加入域名黑名单，阻断生效。',
    },
    {
      id: 'tl-40-3',
      caseId: 'CASE-2025-0040',
      at: agoHours(3.4),
      actor: 'SOAR',
      kind: 'soar',
      title: '执行剧本 ai-data-exfil-response',
      detail: '步骤 3/5 完成：DLP 探针进入修复流程。',
    },
    {
      id: 'tl-40-4',
      caseId: 'CASE-2025-0040',
      at: agoHours(1.2),
      actor: '王萌',
      kind: 'state-change',
      title: '转入 containing',
      detail: '开始清理受影响数据并准备客户通知。',
    },
  ],
  'CASE-2025-0038': [
    {
      id: 'tl-38-1',
      caseId: 'CASE-2025-0038',
      at: agoMinutes(42),
      actor: '系统',
      kind: 'state-change',
      title: '案件创建（new）',
      detail: '高危越狱告警进入待处置队列，SLA 剩余 14 分钟。',
    },
    {
      id: 'tl-38-2',
      caseId: 'CASE-2025-0038',
      at: agoMinutes(30),
      actor: '张伟',
      kind: 'note',
      title: '初步研判',
      detail: '与 2024Q4 基线红队中的 JB-022 用例同源，护栏需增加解码后语义检测。',
    },
  ],
  'CASE-2025-0036': [
    {
      id: 'tl-36-1',
      caseId: 'CASE-2025-0036',
      at: agoHours(30),
      actor: '系统',
      kind: 'state-change',
      title: '案件创建（new）',
      detail: '令牌重放告警聚合生成案件。',
    },
    {
      id: 'tl-36-2',
      caseId: 'CASE-2025-0036',
      at: agoHours(28),
      actor: '孙琪',
      kind: 'action',
      title: '执行「吊销凭据」',
      detail: '吊销 agt-risk 的主令牌并触发全部会话重新认证。',
    },
    {
      id: 'tl-36-3',
      caseId: 'CASE-2025-0036',
      at: agoHours(20),
      actor: '孙琪',
      kind: 'action',
      title: '执行「隔离资产」',
      detail: 'dev-tools-01 进入隔离网段，等待取证完成。',
    },
    {
      id: 'tl-36-4',
      caseId: 'CASE-2025-0036',
      at: agoHours(8),
      actor: 'SOAR',
      kind: 'soar',
      title: '执行剧本 identity-token-hardening',
      detail: '令牌绑定策略已下发，跨主机使用告警已启用。',
    },
    {
      id: 'tl-36-5',
      caseId: 'CASE-2025-0036',
      at: agoHours(6),
      actor: '孙琪',
      kind: 'state-change',
      title: '转入 recovered',
      detail: '业务恢复，dev-tools-01 退出隔离，进入观察期。',
    },
  ],
};

/** Fallback timeline for cases without hand-written history. */
function genericTimeline(caseItem: Case): CaseTimelineEntry[] {
  const rand = seeded(caseItem.id.length * 977);
  return [
    {
      id: `${caseItem.id}-tl-1`,
      caseId: caseItem.id,
      at: caseItem.createdAt,
      actor: '系统',
      kind: 'state-change',
      title: `案件创建（${caseItem.state}）`,
      detail: caseItem.summary,
    },
    {
      id: `${caseItem.id}-tl-2`,
      caseId: caseItem.id,
      at: caseItem.updatedAt,
      actor: caseItem.owner,
      kind: 'note',
      title: '处置进展',
      detail: `已关联 ${caseItem.alertIds.length} 条告警、${
        caseItem.assetNames.length
      } 个资产，当前处置完成度 ${Math.round(20 + rand() * 70)}%。`,
    },
  ];
}

export function timelineForCase(caseItem: Case): CaseTimelineEntry[] {
  const explicit = TIMELINE[caseItem.id];
  if (explicit) {
    return [...explicit].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  }
  return genericTimeline(caseItem).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

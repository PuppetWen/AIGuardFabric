import type { AuditEntry, ChainCheckResult, UserRole } from '@/types/domain';

import { agoMinutes, agoSeconds } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Audit log with a verifiable hash chain                              */
/* ------------------------------------------------------------------ */

interface AuditSeed {
  actor: string;
  actorRole: UserRole;
  action: string;
  sensitive: boolean;
  resourceKind: AuditEntry['resourceKind'];
  resourceId: string;
  resourceName: string;
  result: AuditEntry['result'];
  ip: string;
  detail: string;
  minutesAgo: number;
}

const auditSeeds: AuditSeed[] = [
  {
    actor: '张伟',
    actorRole: 'admin',
    action: 'policy.update',
    sensitive: true,
    resourceKind: 'policy',
    resourceId: 'pol-egress-deny',
    resourceName: '出网域名黑名单阻断',
    result: 'success',
    ip: '10.20.5.31',
    detail: '将优先级由 20 调整为 10，命中动作保持 deny。',
    minutesAgo: 620,
  },
  {
    actor: '孙琪',
    actorRole: 'admin',
    action: 'apikey.create',
    sensitive: true,
    resourceKind: 'tenant',
    resourceId: 'ten-acme',
    resourceName: 'Acme 智能科技',
    result: 'success',
    ip: '10.20.5.44',
    detail: '创建 API Key「日志接入网关」（agf_ig_2b91），范围 ingest:write。',
    minutesAgo: 540,
  },
  {
    actor: 'system',
    actorRole: 'owner',
    action: 'rule.rollout.change',
    sensitive: true,
    resourceKind: 'policy',
    resourceId: 'RULE-RT-003',
    resourceName: '越狱与护栏绕过语义检测',
    result: 'success',
    ip: '127.0.0.1',
    detail: '灰度比例由 2% 恢复至 60%（自动回滚流程）。',
    minutesAgo: 480,
  },
  {
    actor: '刘燕',
    actorRole: 'analyst',
    action: 'finding.status.update',
    sensitive: false,
    resourceKind: 'endpoint',
    resourceId: 'FND-2025-0318-003',
    resourceName: '提示注入导致系统提示词泄露',
    result: 'success',
    ip: '10.20.31.9',
    detail: '状态由 pending 变更为 code-reviewed。',
    minutesAgo: 420,
  },
  {
    actor: 'unknown',
    actorRole: 'viewer',
    action: 'asset.export',
    sensitive: true,
    resourceKind: 'datasource',
    resourceId: 'ast-ds-0002',
    resourceName: '客户画像数仓 dw_user',
    result: 'denied',
    ip: '47.98.**.***',
    detail: '缺少 assets:read 权限，请求被策略 pol-skill-whitelist 拒绝。',
    minutesAgo: 360,
  },
  {
    actor: '陈昊',
    actorRole: 'responder',
    action: 'case.action.isolate',
    sensitive: true,
    resourceKind: 'agent',
    resourceId: 'CASE-2025-0041',
    resourceName: '影子 MCP 命令执行面处置',
    result: 'success',
    ip: '10.20.44.5',
    detail: '通过 EDR 适配器隔离 ops-analyzer.acme.internal。',
    minutesAgo: 300,
  },
  {
    actor: '王萌',
    actorRole: 'analyst',
    action: 'skill.reject',
    sensitive: false,
    resourceKind: 'skill',
    resourceId: 'skl-email-send',
    resourceName: '邮件批量发送',
    result: 'success',
    ip: '10.20.72.9',
    detail: '驳回理由：具备 network + write 能力且无出网白名单。',
    minutesAgo: 240,
  },
  {
    actor: 'service-deploy',
    actorRole: 'admin',
    action: 'adapter.config.update',
    sensitive: true,
    resourceKind: 'tenant',
    resourceId: 'adp-dlp',
    resourceName: '数据防泄漏 (DLP)',
    result: 'failure',
    ip: '10.20.5.77',
    detail: '连通性测试失败：connection refused (dlp.intra.acme:9099)。',
    minutesAgo: 180,
  },
  {
    actor: '张伟',
    actorRole: 'admin',
    action: 'redteam.campaign.launch',
    sensitive: false,
    resourceKind: 'endpoint',
    resourceId: 'camp-2025-q1-agentless',
    resourceName: '未纳管 Agent 定向评估',
    result: 'success',
    ip: '10.20.5.31',
    detail: '发起战役，用例类别 tool-abuse / supply-chain，目标 ast-agent-0006。',
    minutesAgo: 150,
  },
  {
    actor: '李静',
    actorRole: 'auditor',
    action: 'audit.chain.verify',
    sensitive: false,
    resourceKind: 'report',
    resourceId: 'audit-chain',
    resourceName: '审计哈希链',
    result: 'success',
    ip: '10.20.99.8',
    detail: '校验最近 500 条审计记录，链路结论：部分可校验（1 条问题项）。',
    minutesAgo: 120,
  },
  {
    actor: '孙琪',
    actorRole: 'admin',
    action: 'blacklist.create',
    sensitive: true,
    resourceKind: 'policy',
    resourceId: 'bl-dom-001',
    resourceName: 'attacker.example',
    result: 'success',
    ip: '10.20.5.44',
    detail: '新增域名黑名单条目，命中动作 deny，作用范围 tenant。',
    minutesAgo: 90,
  },
  {
    actor: 'system',
    actorRole: 'owner',
    action: 'quota.throttle.trigger',
    sensitive: false,
    resourceKind: 'agent',
    resourceId: 'agt-copilot',
    resourceName: '客服智能助手 Copilot',
    result: 'success',
    ip: '127.0.0.1',
    detail: 'Agent 级 Token 配额达到 97%，触发限流（5 rps）。',
    minutesAgo: 60,
  },
  {
    actor: 'chenhao',
    actorRole: 'responder',
    action: 'case.timeline.note',
    sensitive: false,
    resourceKind: 'endpoint',
    resourceId: 'CASE-2025-0040',
    resourceName: '客户画像数据外传事件',
    result: 'success',
    ip: '10.20.44.5',
    detail: '记录处置进展：外传目标已阻断，DLP 探针修复中。',
    minutesAgo: 30,
  },
  {
    actor: 'unknown',
    actorRole: 'viewer',
    action: 'auth.login',
    sensitive: true,
    resourceKind: 'user',
    resourceId: 'usr-0006',
    resourceName: '孙琪',
    result: 'denied',
    ip: '103.27.**.**',
    detail: '连续 5 次密码错误，账号已锁定 30 分钟。',
    minutesAgo: 15,
  },
];

/**
 * Deterministic FNV-1a style digest. It is *not* a cryptographic hash — it only
 * needs to be stable and sensitive to every input byte so the tamper detection
 * demo is honest about being a simulation.
 */
function chainHash(prevHash: string, payload: string): string {
  let hash = 0x811c9dc5;
  const input = `${prevHash}|${payload}`;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const second = (hash ^ 0x5bf03635) >>> 0;
  return `sha256:${hash.toString(16).padStart(8, '0')}${second.toString(16).padStart(8, '0')}${(
    (hash ^ second) >>>
    0
  )
    .toString(16)
    .padStart(8, '0')}`;
}

function auditPayload(entry: Omit<AuditEntry, 'hash' | 'prevHash'>): string {
  return [
    entry.id,
    entry.ts,
    entry.actor,
    entry.action,
    entry.resourceId,
    entry.result,
    entry.ip,
    entry.detail,
  ].join('~');
}

/** Build the audit log, deliberately corrupting exactly one entry's hash. */
function buildAuditLog(): AuditEntry[] {
  const ordered = [...auditSeeds].sort((a, b) => b.minutesAgo - a.minutesAgo);
  let prevHash = 'sha256:00000000000000000000000000000000';
  const entries: AuditEntry[] = [];
  ordered.forEach((seed, index) => {
    const base: Omit<AuditEntry, 'hash' | 'prevHash'> = {
      id: `AUD-2025-${String(index + 1).padStart(5, '0')}`,
      ts: agoSeconds(seed.minutesAgo * 60 + (index % 7) * 11),
      actor: seed.actor,
      actorRole: seed.actorRole,
      action: seed.action,
      sensitive: seed.sensitive,
      resourceKind: seed.resourceKind,
      resourceId: seed.resourceId,
      resourceName: seed.resourceName,
      result: seed.result,
      ip: seed.ip,
      userAgent: 'AIGuardFabric-Console/0.1.0 (Windows NT 10.0; Win64; x64)',
      detail: seed.detail,
    };
    const hash = chainHash(prevHash, auditPayload(base));
    entries.push({ ...base, hash, prevHash });
    prevHash = hash;
  });

  // Tamper with entry #6 so the verifier has a real problem item to report.
  const victim = entries[5];
  if (victim) {
    entries[5] = { ...victim, hash: `${victim.hash.slice(0, -4)}dead` };
  }
  return entries;
}

export const demoAuditEntries: AuditEntry[] = buildAuditLog();

/** Recompute the chain over `entries` and report every break. */
export function verifyAuditChain(entries: AuditEntry[] = demoAuditEntries): ChainCheckResult {
  const ordered = [...entries].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  const issues: ChainCheckResult['issues'] = [];
  let prevHash = 'sha256:00000000000000000000000000000000';

  ordered.forEach((entry, index) => {
    const expected = chainHash(prevHash, auditPayload(entry));
    if (index > 0 && entry.prevHash !== prevHash) {
      issues.push({
        entryId: entry.id,
        ts: entry.ts,
        expectedHash: prevHash,
        actualHash: entry.prevHash,
        reason: 'prevHash 与上一条记录的哈希不一致（链路被插入或重排）',
      });
    }
    if (entry.hash !== expected) {
      issues.push({
        entryId: entry.id,
        ts: entry.ts,
        expectedHash: expected,
        actualHash: entry.hash,
        reason: '记录内容与哈希不匹配（记录被篡改）',
      });
    }
    prevHash = entry.hash;
  });

  const verdict: ChainCheckResult['verdict'] =
    issues.length === 0 ? 'valid' : issues.length >= ordered.length ? 'broken' : 'partial';

  return {
    verdict,
    checkedEntries: ordered.length,
    from: ordered[0]?.ts ?? '',
    to: ordered[ordered.length - 1]?.ts ?? '',
    issues,
    checkedAt: agoMinutes(0),
  };
}

export { chainHash, auditPayload };

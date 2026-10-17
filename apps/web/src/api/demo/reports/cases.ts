import type { Case, CaseState, Severity } from '@/types/domain';

import { agoHours, aheadHours } from '../../../utils/time';
import { ASSET_ID, demoAssetById } from '../assets';

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

interface CaseSeed {
  id: string;
  title: string;
  state: CaseState;
  severity: Severity;
  alertIds: string[];
  assetIds: string[];
  owner: string;
  createdHours: number;
  updatedHours: number;
  dueInHours: number;
  summary: string;
}

const caseSeeds: CaseSeed[] = [
  {
    id: 'CASE-2025-0041',
    title: '影子 MCP 命令执行面处置',
    state: 'containing',
    severity: 'critical',
    alertIds: ['ALR-2025-0318-0001', 'ALR-2025-0318-0009'],
    assetIds: [ASSET_ID.mcpShell, ASSET_ID.agentOpsShadow],
    owner: '陈昊',
    createdHours: 5.4,
    updatedHours: 0.4,
    dueInHours: 3,
    summary: '下线 shell-mcp 公网监听，回收 ops-analyzer 主机凭据，纳管未登记 Agent。',
  },
  {
    id: 'CASE-2025-0040',
    title: '客户画像数据外传事件',
    state: 'containing',
    severity: 'critical',
    alertIds: ['ALR-2025-0318-0002'],
    assetIds: [ASSET_ID.dsUserProfile, ASSET_ID.mcpSearch],
    owner: '王萌',
    createdHours: 4.2,
    updatedHours: 0.7,
    dueInHours: 8,
    summary: '阻断外传目标域名，修复 DLP 探针，回溯并通知受影响客户。',
  },
  {
    id: 'CASE-2025-0039',
    title: '明文数据库凭据轮换',
    state: 'triaged',
    severity: 'critical',
    alertIds: ['ALR-2025-0318-0003'],
    assetIds: [ASSET_ID.credPg, ASSET_ID.mcpPostgres],
    owner: '刘燕',
    createdHours: 9.2,
    updatedHours: 2.1,
    dueInHours: 20,
    summary: '轮换 order_db 只读口令并迁移至 Vault，改造 MCP 启动参数。',
  },
  {
    id: 'CASE-2025-0038',
    title: '客服 Copilot 越狱与提示注入',
    state: 'new',
    severity: 'high',
    alertIds: ['ALR-2025-0318-0004'],
    assetIds: [ASSET_ID.agentCopilot],
    owner: '刘燕',
    createdHours: 0.7,
    updatedHours: 0.2,
    dueInHours: 4,
    summary: '收紧护栏语义检测，隔离工具返回内容，回归验证 96 条红队用例。',
  },
  {
    id: 'CASE-2025-0037',
    title: '订单工具越权读取排查',
    state: 'triaged',
    severity: 'high',
    alertIds: ['ALR-2025-0318-0005'],
    assetIds: [ASSET_ID.mcpOrder, ASSET_ID.dsOrder],
    owner: '陈昊',
    createdHours: 2.1,
    updatedHours: 1.4,
    dueInHours: 12,
    summary: '改造 list_orders_by_user 以会话身份为准，补充参数级策略。',
  },
  {
    id: 'CASE-2025-0036',
    title: 'Agent 令牌重放调查',
    state: 'recovered',
    severity: 'high',
    alertIds: ['ALR-2025-0318-0007'],
    assetIds: [ASSET_ID.agentRisk],
    owner: '孙琪',
    createdHours: 30,
    updatedHours: 6,
    dueInHours: -6,
    summary: '令牌已吊销并绑定会话指纹，跨主机使用告警已上线。',
  },
  {
    id: 'CASE-2025-0035',
    title: '数仓脱敏绕过修复',
    state: 'recovered',
    severity: 'high',
    alertIds: ['ALR-2025-0318-0008', 'ALR-2025-0318-0014'],
    assetIds: [ASSET_ID.dsOrder],
    owner: '陈昊',
    createdHours: 42,
    updatedHours: 10,
    dueInHours: -18,
    summary: '脱敏下沉至视图层，select * 列白名单已生效，回归通过。',
  },
  {
    id: 'CASE-2025-0034',
    title: '日志凭据落库清理',
    state: 'closed',
    severity: 'medium',
    alertIds: ['ALR-2025-0318-0010'],
    assetIds: [ASSET_ID.credOpenai],
    owner: '孙琪',
    createdHours: 72,
    updatedHours: 20,
    dueInHours: -48,
    summary: '解析器增加脱敏规则，历史明文记录已清理，共享 Key 已轮换。',
  },
  {
    id: 'CASE-2025-0033',
    title: '检测规则灰度异常复盘',
    state: 'closed',
    severity: 'medium',
    alertIds: ['ALR-2025-0318-0016'],
    assetIds: [ASSET_ID.epGateway],
    owner: '张伟',
    createdHours: 96,
    updatedHours: 40,
    dueInHours: -72,
    summary: '灰度变更增加审批与监控，命中量异常下降自动告警已上线。',
  },
  {
    id: 'CASE-2025-0032',
    title: '高权限 Skill 审批基线整改',
    state: 'new',
    severity: 'medium',
    alertIds: ['ALR-2025-0318-0011'],
    assetIds: [ASSET_ID.skillSql],
    owner: '王萌',
    createdHours: 3,
    updatedHours: 3,
    dueInHours: 21,
    summary: '驳回无白名单的高权限 Skill，审批流加入基线校验。',
  },
  {
    id: 'CASE-2025-0031',
    title: '内部拦截点 mTLS 加固',
    state: 'containing',
    severity: 'low',
    alertIds: ['ALR-2025-0318-0013'],
    assetIds: [ASSET_ID.epMcpProxy],
    owner: '孙琪',
    createdHours: 12,
    updatedHours: 5,
    dueInHours: 36,
    summary: '为 mcp-proxy 下发短期客户端证书，按 Agent 绑定证书身份。',
  },
];

export const demoCases: Case[] = caseSeeds.map((seed) => ({
  id: seed.id,
  title: seed.title,
  state: seed.state,
  severity: seed.severity,
  alertIds: seed.alertIds,
  assetNames: seed.assetIds.map((id) => demoAssetById.get(id)?.name ?? id),
  owner: seed.owner,
  createdAt: agoHours(seed.createdHours),
  updatedAt: agoHours(seed.updatedHours),
  dueAt: seed.dueInHours >= 0 ? aheadHours(seed.dueInHours) : agoHours(Math.abs(seed.dueInHours)),
  summary: seed.summary,
}));

import type { ReportFormat, ReportJob, ReportSchedule } from '@/types/domain';

import { agoHours } from '../../utils/time';

/* ------------------------------------------------------------------ */
/* Reports                                                             */
/* ------------------------------------------------------------------ */

interface ReportSeed {
  id: string;
  name: string;
  type: ReportJob['type'];
  format: ReportFormat;
  schedule: ReportSchedule;
  windowDays: number;
  status: ReportJob['status'];
  sizeKb: number;
  createdHours: number;
  createdBy: string;
  recipients: string[];
}

const reportSeeds: ReportSeed[] = [
  {
    id: 'rpt-0001',
    name: '2025 年 3 月管理层态势报表',
    type: 'executive',
    format: 'pdf',
    schedule: 'monthly',
    windowDays: 30,
    status: 'ready',
    sizeKb: 2_840,
    createdHours: 26,
    createdBy: '张伟',
    recipients: ['ciso@acme.example', 'ceo-office@acme.example'],
  },
  {
    id: 'rpt-0002',
    name: 'Q1 合规符合性报表（等保 + 生成式 AI 管理办法）',
    type: 'compliance',
    format: 'docx',
    schedule: 'monthly',
    windowDays: 90,
    status: 'ready',
    sizeKb: 1_460,
    createdHours: 30,
    createdBy: '王萌',
    recipients: ['compliance@acme.example'],
  },
  {
    id: 'rpt-0003',
    name: 'AI 资产盘点报表（含影子资产清单）',
    type: 'asset-inventory',
    format: 'xlsx',
    schedule: 'weekly',
    windowDays: 7,
    status: 'ready',
    sizeKb: 860,
    createdHours: 50,
    createdBy: '孙琪',
    recipients: ['asset-owners@acme.example'],
  },
  {
    id: 'rpt-0004',
    name: '2025Q1 红队评估报表',
    type: 'redteam',
    format: 'markdown',
    schedule: 'manual',
    windowDays: 30,
    status: 'ready',
    sizeKb: 320,
    createdHours: 96,
    createdBy: '张伟',
    recipients: ['security-lead@acme.example'],
  },
  {
    id: 'rpt-0005',
    name: '客户画像数据外传事件报表',
    type: 'incident',
    format: 'pdf',
    schedule: 'manual',
    windowDays: 7,
    status: 'generating',
    sizeKb: 0,
    createdHours: 0.4,
    createdBy: '王萌',
    recipients: ['ciso@acme.example', 'dpo@acme.example'],
  },
  {
    id: 'rpt-0006',
    name: '每日高危告警摘要',
    type: 'executive',
    format: 'html',
    schedule: 'daily',
    windowDays: 1,
    status: 'scheduled',
    sizeKb: 0,
    createdHours: 12,
    createdBy: '系统',
    recipients: ['ai-sec-oncall@acme.example'],
  },
  {
    id: 'rpt-0007',
    name: '上周资产变更报表',
    type: 'asset-inventory',
    format: 'xlsx',
    schedule: 'weekly',
    windowDays: 7,
    status: 'failed',
    sizeKb: 0,
    createdHours: 168,
    createdBy: '系统',
    recipients: ['asset-owners@acme.example'],
  },
];

function reportPreview(seed: ReportSeed): string {
  return [
    `# ${seed.name}`,
    '',
    `- 报表类型：${seed.type}`,
    `- 统计窗口：最近 ${seed.windowDays} 天`,
    `- 输出格式：${seed.format.toUpperCase()}`,
    `- 生成计划：${seed.schedule}`,
    '',
    '## 关键指标',
    '',
    '| 指标 | 数值 | 环比 |',
    '| --- | --- | --- |',
    '| AI 资产总数 | 37 | +5 |',
    '| 未处置告警 | 12 | -3 |',
    '| 严重发现 | 4 | +1 |',
    '| 红队成功率 | 18.9% | -2.4pt |',
    '| Token 费用 | $3,284.61 | +6.8% |',
    '',
    '## 结论与建议',
    '',
    '1. 影子 MCP 治理仍是本周期最大风险敞口，建议在两周内完成全部影子资产纳管。',
    '2. DLP 探针不可用期间数据域风险上升，需在修复前对高敏数据源启用只读兜底策略。',
    '3. 越狱护栏对编码混淆类 payload 检出率偏低，建议提升 RULE-RT-003 灰度并补充样本。',
    '',
  ].join('\n');
}

export const demoReports: ReportJob[] = reportSeeds.map((seed) => ({
  id: seed.id,
  name: seed.name,
  type: seed.type,
  format: seed.format,
  schedule: seed.schedule,
  windowDays: seed.windowDays,
  status: seed.status,
  sizeKb: seed.sizeKb,
  createdAt: agoHours(seed.createdHours),
  createdBy: seed.createdBy,
  recipients: seed.recipients,
  preview: reportPreview(seed),
}));

/* ------------------------------------------------------------------ */
/* Alerts, cases, timelines & SOAR runs (split out, re-exported here)   */
/* ------------------------------------------------------------------ */

export { SLA_MINUTES, demoAlerts } from './reports/alerts';
export { demoCases } from './reports/cases';
export { timelineForCase } from './reports/timeline';
export { demoSoarRuns, soarRunsForCase } from './reports/soar';

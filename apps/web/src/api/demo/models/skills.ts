import type { Skill, SkillStatus, ToolCapability } from '@/types/domain';

import { agoDays } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Skills                                                              */
/* ------------------------------------------------------------------ */

interface SkillSeed {
  id: string;
  name: string;
  version: string;
  publisher: string;
  status: SkillStatus;
  requestedBy: string;
  requestedDays: number;
  decidedDays: number | null;
  decidedBy: string | null;
  riskScore: number;
  capabilities: ToolCapability[];
  domains: string[];
  paths: string[];
  attachedAgents: number;
}

const skillSeeds: SkillSeed[] = [
  {
    id: 'skl-pdf-report',
    name: 'PDF 报表生成',
    version: '1.4.2',
    publisher: 'acme-internal',
    status: 'approved',
    requestedBy: '刘燕',
    requestedDays: 78,
    decidedDays: 76,
    decidedBy: '张伟',
    riskScore: 48,
    capabilities: ['write', 'filesystem'],
    domains: ['report.intra.acme', 'docs.intra.acme'],
    paths: ['/v1/render', '/v1/template'],
    attachedAgents: 3,
  },
  {
    id: 'skl-sql-direct',
    name: 'SQL 直连查询',
    version: '0.9.0',
    publisher: 'third-party/data-bridge',
    status: 'pending',
    requestedBy: '陈昊',
    requestedDays: 6,
    decidedDays: null,
    decidedBy: null,
    riskScore: 86,
    capabilities: ['execute', 'read', 'credential'],
    domains: ['dw.intra.acme'],
    paths: ['/query'],
    attachedAgents: 0,
  },
  {
    id: 'skl-web-crawl',
    name: '网页内容抓取',
    version: '2.1.0',
    publisher: 'third-party/scrape-kit',
    status: 'pending',
    requestedBy: '王萌',
    requestedDays: 3,
    decidedDays: null,
    decidedBy: null,
    riskScore: 71,
    capabilities: ['network', 'read'],
    domains: [],
    paths: [],
    attachedAgents: 0,
  },
  {
    id: 'skl-code-scan',
    name: '代码安全扫描',
    version: '1.0.7',
    publisher: 'acme-sec',
    status: 'approved',
    requestedBy: '孙琪',
    requestedDays: 120,
    decidedDays: 118,
    decidedBy: '张伟',
    riskScore: 34,
    capabilities: ['read', 'filesystem', 'execute'],
    domains: ['git.intra.acme'],
    paths: ['/api/v4/projects'],
    attachedAgents: 2,
  },
  {
    id: 'skl-email-send',
    name: '邮件批量发送',
    version: '0.5.1',
    publisher: 'third-party/mailer',
    status: 'rejected',
    requestedBy: '王萌',
    requestedDays: 42,
    decidedDays: 40,
    decidedBy: '林思远',
    riskScore: 79,
    capabilities: ['network', 'write'],
    domains: [],
    paths: [],
    attachedAgents: 0,
  },
  {
    id: 'skl-doc-parse',
    name: '文档解析（含 OCR）',
    version: '3.2.0',
    publisher: 'acme-internal',
    status: 'approved',
    requestedBy: '王萌',
    requestedDays: 200,
    decidedDays: 198,
    decidedBy: '张伟',
    riskScore: 29,
    capabilities: ['read', 'filesystem'],
    domains: ['ocr.intra.acme'],
    paths: ['/v2/parse'],
    attachedAgents: 5,
  },
  {
    id: 'skl-payment-call',
    name: '支付网关调用',
    version: '1.1.0',
    publisher: 'acme-pay',
    status: 'revoked',
    requestedBy: '陈昊',
    requestedDays: 260,
    decidedDays: 12,
    decidedBy: '林思远',
    riskScore: 93,
    capabilities: ['payment', 'network', 'credential'],
    domains: ['pay.intra.acme'],
    paths: ['/v1/charge', '/v1/refund'],
    attachedAgents: 0,
  },
  {
    id: 'skl-translate',
    name: '多语言翻译',
    version: '0.8.4',
    publisher: 'acme-internal',
    status: 'approved',
    requestedBy: '王萌',
    requestedDays: 60,
    decidedDays: 59,
    decidedBy: '张伟',
    riskScore: 22,
    capabilities: ['network', 'read'],
    domains: ['translate.intra.acme'],
    paths: ['/v1/translate'],
    attachedAgents: 4,
  },
  {
    id: 'skl-k8s-ops',
    name: 'Kubernetes 运维操作',
    version: '0.3.2',
    publisher: 'third-party/kubectl-tool',
    status: 'pending',
    requestedBy: '孙琪',
    requestedDays: 1,
    decidedDays: null,
    decidedBy: null,
    riskScore: 95,
    capabilities: ['execute', 'credential', 'network'],
    domains: ['k8s.intra.acme'],
    paths: ['/api/v1/namespaces'],
    attachedAgents: 0,
  },
  {
    id: 'skl-vector-search',
    name: '向量检索',
    version: '2.0.0',
    publisher: 'acme-internal',
    status: 'approved',
    requestedBy: '王萌',
    requestedDays: 150,
    decidedDays: 149,
    decidedBy: '张伟',
    riskScore: 31,
    capabilities: ['read'],
    domains: ['vector.intra.acme'],
    paths: ['/collections/*/query'],
    attachedAgents: 6,
  },
];

export const demoSkills: Skill[] = skillSeeds.map((seed) => ({
  id: seed.id,
  name: seed.name,
  version: seed.version,
  publisher: seed.publisher,
  status: seed.status,
  requestedBy: seed.requestedBy,
  requestedAt: agoDays(seed.requestedDays),
  decidedAt: seed.decidedDays === null ? null : agoDays(seed.decidedDays),
  decidedBy: seed.decidedBy,
  riskScore: seed.riskScore,
  capabilities: seed.capabilities,
  whitelist: { domains: seed.domains, paths: seed.paths },
  attachedAgents: seed.attachedAgents,
}));

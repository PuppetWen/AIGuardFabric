import type { AttackCategory, Campaign, Severity } from '@/types/domain';
export const CATEGORIES: [AttackCategory, string, string][] = [
  ['jailbreak','越狱','Jailbreak'], ['direct-injection','直接注入','Direct injection'],
  ['indirect-injection','间接注入','Indirect injection'], ['rag-poisoning','RAG 投毒','RAG poisoning'],
  ['tool-abuse','工具滥用','Tool abuse'], ['data-exfiltration','数据外传','Data exfiltration'],
  ['multi-turn-social','多轮社工','Multi-turn social engineering'], ['credential-theft','凭证窃取','Credential theft'],
  ['privilege-escalation','权限提升','Privilege escalation'], ['supply-chain','供应链','Supply chain'],
  ['lateral-movement','横向移动','Lateral movement'], ['resource-exhaustion','资源耗尽','Resource exhaustion'],
];
export const categoryLabel = (key: string, zh: boolean) => CATEGORIES.find(row => row[0] === key)?.[zh ? 1 : 2] ?? key;
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
export const STATUS_COLOR: Record<Campaign['status'], string> = {
  planned: '#8b93a1', running: '#3d8bfd', succeeded: '#3dd68c', failed: '#f0cc6a', aborted: '#6f7683',
};
export const terminal = (campaign: Campaign) => ['succeeded', 'failed', 'aborted'].includes(campaign.status);
export interface WizardValues {
  name: string; executionMode: 'simulator' | 'agent-http' | 'mcp-http'; categories: AttackCategory[];
  targetName: string; guardStrength: number; targetProfileId?: string; caseKeys?: string[];
  ciGateEnabled: boolean; severityThreshold: Severity; maxCases: number;
}

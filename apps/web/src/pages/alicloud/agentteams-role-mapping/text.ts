import { useTranslation } from 'react-i18next';
export function useRoleText() { const { i18n } = useTranslation(); return (cn: string, en: string) => i18n.language.startsWith('zh') ? cn : en; }
export const failure = (cause: unknown) => cause instanceof Error ? cause.message : 'Request failed / 请求失败';
export const uuid = (value: string) => /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const workerKey = (row: { assetId: string | null; teamName: string; workerName: string }) => JSON.stringify([row.assetId, row.teamName, row.workerName]);
const reasons: Record<string, [string, string]> = {
  administrator_disabled: ['管理员已停用', 'Disabled by administrator'],
  source_changed: ['来源或配置版本已改变，请重新核对并采用', 'Source or configuration revision changed; review and adopt again'],
  worker_missing_or_remapped: ['Worker 已移除或资产映射改变', 'Worker removed or its asset mapping changed'],
  membership_removed: ['成员关系已移除', 'Membership was removed'],
  cloud_role_unknown: ['当前 CloudRole 未提供，不能恢复资格', 'Current CloudRole is unavailable; qualification cannot be restored'],
  cloud_role_changed: ['真实 CloudRole 已改变', 'Observed CloudRole changed'],
  agent_governance_changed: ['Agent 身份、部门或分级改变', 'Agent identity, department or classification changed'],
  current_role_constraint_unavailable: ['当前角色约束证明不可用；核对来源、成员、Role 与 Agent', 'Current constraint proof unavailable; review source, membership, Role and Agent'],
};
export function reasonText(reason: string | null | undefined, t: (cn: string, en: string) => string) {
  const known = reason && reasons[reason]; return known ? t(...known) : reason || '—';
}

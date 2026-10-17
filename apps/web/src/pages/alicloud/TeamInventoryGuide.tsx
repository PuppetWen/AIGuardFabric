import { Collapse, List, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

/** Read-only instructions; opening the guide never dispatches a cloud operation. */
export function TeamInventoryGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const steps = zh ? [
    '先确认右上角组织。在“云连接与操作”配置 AgentTeams 实例；个人用户先使用 Mock。查看需要 alicloud:read；完整盘点需要 alicloud:write 和 assets:write，资产详情另需 assets:read。',
    '启用连接后，打开“台账同步”，点击“完整盘点并同步台账”。Live 必须自己勾选云端只读查询与本地台账更新。平台读取团队、Worker 详情与任务完整分页，不会下发编排或修改云人员。',
    '在团队表点击团队名称，分别打开 Worker 成员、云端人员与云端任务。Worker 数为“未知”时，无法确认完整名单；明确的 0 只表示该次观察为空。云人员同名也不会变成 Worker。',
    '查看关系证据：团队 WorkerNames 或完整 Worker Groups。云端角色按 Groups.Role 原文展示；未提供时是未知，不自动映射成平台权限或工具授权。',
    '任务“指派对象”只表示云端返回的名称，不保证其身份是 Worker。公开盘点接口未提供编排 DAG，成员关系与已观测调用也不能推定执行依赖。',
    '盘点失败时先检查回执中的实例、分页或关系冲突，修正后手动重新盘点。旧快照保留，刷新页面不会把旧数据变成新观察；重新绑定审计前要先得到完整关系。',
  ] : [
    'Confirm the selected organization. Configure the AgentTeams instance under Cloud connections and operations; start with Mock. Viewing needs alicloud:read; inventory needs alicloud:write and assets:write. Asset details also need assets:read.',
    'Enable the connection, open Inventory sync and click Read complete inventory and synchronize. Live requires your confirmation of cloud reads and local inventory updates. The platform reads team, Worker and task pages without publishing orchestration or changing cloud users.',
    'Select a team and inspect Worker members, Cloud users and Cloud tasks separately. Unknown counts mean the complete roster is unverified. An explicit 0 means this observation was empty. Matching user and Worker names do not establish the same identity.',
    'Check the relationship evidence: Team WorkerNames or complete Worker Groups. Cloud roles show the raw Groups.Role value. Missing roles are unknown; they do not grant platform permissions or tool authorization.',
    'Assigned to shows only the name returned by the cloud. It does not prove the assignee is a Worker. Inventory APIs do not provide an orchestration DAG; membership and observed calls do not establish execution dependencies.',
    'After an inventory failure, inspect its receipt for instance, pagination or relationship conflicts, correct the cause, and retry manually. The old snapshot is retained. Refreshing the page does not make it a new observation; obtain complete relationships before rebinding audit.',
  ];
  return <Collapse size="small" style={{ marginBottom: 12 }} items={[{
    key: 'inventory-guide', label: text('团队盘点操作指南', 'Team inventory guide'),
    children: <>
      <List size="small" dataSource={steps} renderItem={(step, index) => <List.Item>{index + 1}. {step}</List.Item>} />
      <Typography.Paragraph type="secondary">{text(
        '云人员名单来自 TeamMembers；Worker 关系来自 WorkerNames/Groups。修改云端团队后需重新盘点；本指南不提供团队写入、角色授权或任务重放。Mock 只验证流程，不能证明真实云授权或覆盖完整性。',
        'Cloud users come from TeamMembers; Worker relationships come from WorkerNames/Groups. Re-inventory after cloud changes. This guide does not perform team writes, role grants or task replay. Mock validates the flow, not live cloud authorization or complete coverage.',
      )}</Typography.Paragraph>
    </>,
  }]} />;
}

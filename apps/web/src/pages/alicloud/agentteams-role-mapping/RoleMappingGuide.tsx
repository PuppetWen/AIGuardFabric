import { Alert, Space, Typography } from 'antd';
import { useRoleText } from './text';
export function RoleMappingGuide() {
  const t = useRoleText();
  return <Space direction="vertical">
    <Alert type="warning" message={t('这是平台本地权限约束，不写云 Role/RAM，也不自动扩 Key 权限。',
      'This constrains local platform permissions; it neither writes cloud Role/RAM nor expands Key scopes.')} />
    <Typography.Paragraph>{t('1. 在“连接配置”维护 AgentTeams 来源、区域、实例和模式，启用后人工完整盘点。采用必须使用 300 秒内的完整成员证明；界面 GET 不读云、不自动盘点。',
      '1. Maintain the AgentTeams source, region, instance and mode in Connection configuration; enable it and perform a complete inventory manually. Adoption requires complete membership evidence within 300 seconds. UI GETs neither read the cloud nor start inventory.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('2. 选择盘点中的 Worker/Team/CloudRole，再选择本租户已保存的实际平台 Role UUID。没有角色时通过现有用户管理配置合法角色；本页不猜 operator，也不创建另一套角色。离线目录只有角色名称，新增映射需要数据库。',
      '2. Select the inventoried Worker/Team/CloudRole, then an actual saved tenant platform Role UUID. If missing, configure a legitimate Role through existing user management. This page neither guesses operator nor creates another Role directory. Offline roles have names only; new mappings require a database.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('3. 核对权限，确认现有采集或模型调用可能被缩小，再明确提交。Key 必须绑定同租户该 Agent，并仍具备自己的 scopes；实际权限是原 scopes 与平台 Role 权限交集。云人员姓名或 Role 字符串不作身份认证。',
      '3. Review the permissions and acknowledge that collection or model calls may narrow, then confirm submission. A Key must bind this tenant Agent and retain its own scopes. Effective permissions are their intersection with the platform Role; cloud usernames or Role strings do not authenticate identities.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('4. 网络中断、408、5xx 或无法核验的成功响应会锁定新写操作，保留原请求编号、内容和草稿 CAS。只能 GET 原回执或比较；404 不证明未提交，不能解锁。可信原回执或确定 4xx 拒绝后，明确开始新的本地操作，再人工比较/采用并重新确认。不会自动重发，也不把历史成功当当前资格。',
      '4. Network failure, HTTP 408/5xx or an unverifiable success locks new writes while retaining the original request, content and draft CAS. Only GET its receipt or compare. HTTP 404 does not prove rejection and cannot unlock. A trusted receipt or definite 4xx rejection allows an explicitly confirmed new local action, followed by manual comparison/adoption and renewed consent. No automatic redispatch or inference of current qualification from historical success.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('5. 成员移除、Role 漂移、来源或 Agent 部门/分级改变会拒绝旧约束。完整负面盘点是持续撤销，后续正面观察不自动恢复；新盘点后需管理员重新采用。停用保留永久治理身份，没有删除解锁。300 秒是人工采用门槛，不是运行权限 TTL。',
      '5. Removed members, changed cloud Roles, source changes or Agent department/classification changes invalidate old constraints. Complete negative inventory is sticky; later positive observations do not automatically restore authority. An administrator must adopt again. Disable retains permanent governance, with no delete-to-unlock. The 300-second window is an adoption threshold, not runtime authority TTL.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('本期支持已保存且定义一致的 tenant-admin/soc-analyst/redteam-engineer/auditor/viewer；superadmin、asset-owner 与未验证自定义角色不可采用。映射、永久标记、不可变意图和成功审计同事务；具体业务仍需自身提交围栏。',
      'This slice supports saved, verified tenant-admin/soc-analyst/redteam-engineer/auditor/viewer definitions. Superadmin, asset-owner and unverified custom Roles cannot be adopted. Mapping, permanent marker, immutable intent and success audit commit atomically; each business operation still needs its own publication fence.')}</Typography.Paragraph>
    <Typography.Link href="/alicloud?tab=inventory">{t('前往完整盘点（人工操作）', 'Open full inventory (manual operation)')}</Typography.Link>
  </Space>;
}

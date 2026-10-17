import { Alert, Button, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import type { RoleConstraint } from './types';
import type { RoleFlow } from './useRoleMapping';
import { reasonText, useRoleText } from './text';

export function RoleTable({ flow, canWrite }: { flow: RoleFlow; canWrite: boolean }) {
  const t = useRoleText(), state = flow.data;
  if (!state) return null;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('已提交的本地权限约束', 'Committed local permission constraints')}</Typography.Title>
    <Typography.Text>{t('当前有效映射数', 'Currently qualified mappings')}: {state.mappedCount}</Typography.Text>
    <Alert type="info" message={t('CloudRole 字符串和旧 adapter 角色提示不计为已授权映射。当前资格与原历史事实分别展示。',
      'CloudRole strings and legacy adapter hints do not count as authorized mappings. Current qualification is separate from historical facts.')} />
    <Table<RoleConstraint> rowKey="assetId" size="small" scroll={{ x: 1000 }} pagination={{ pageSize: 50, showSizeChanger: false }} dataSource={state.items} columns={[
      { title: t('Worker / Team', 'Worker / Team'), key: 'worker', render: (_, row) => <Space direction="vertical"><span>{row.proof.workerName} / {row.proof.teamName}</span><Typography.Text copyable>{row.assetId}</Typography.Text></Space> },
      { title: t('Role / 版本', 'Role / revision'), key: 'role', render: (_, row) => <Space direction="vertical"><span>{row.proof.platformRoleId}</span><span>v{row.version} · {row.proof.cloudRole}</span></Space> },
      { title: t('已存状态 / 当前资格', 'Stored state / current qualification'), key: 'state', render: (_, row) => <Space direction="vertical"><Tag color={row.currentQualified === true ? 'green' : 'orange'}>{row.eligibility}</Tag>
        <span>{t('当前资格', 'Current qualification')}: {row.currentQualified === true ? t('有效', 'eligible') : row.currentQualified === false ? t('不可用', 'unavailable') : t('未核验', 'not checked')}</span>
        <span>{reasonText(row.reason || row.currentReason, t)}</span></Space> },
      { title: t('明确停用', 'Explicit disable'), key: 'actions', render: (_, row) => <Popconfirm title={t('停用保留永久治理身份；删除映射不会恢复旧 Key 宽权限。确认？',
        'Disable retains the permanent governed identity; deleting a mapping never restores broad Key scopes. Confirm?')}
        okText={t('确认停用', 'Confirm disable')} onConfirm={() => flow.save(row.assetId, row.version, { action: 'disable' })}>
        <Button disabled={!canWrite || !state.canManage || flow.busy || flow.writeLocked || row.eligibility === 'disabled'}>{t(`停用 ${row.proof.workerName}`, `Disable ${row.proof.workerName}`)}</Button>
      </Popconfirm> },
    ]} />
  </Space>;
}

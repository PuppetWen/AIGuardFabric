import { Alert, Button, Descriptions, Input, Popconfirm, Space, Typography } from 'antd';
import type { RoleFlow } from './useRoleMapping';
import { useRoleText, uuid } from './text';

export function RoleReceipt({ flow }: { flow: RoleFlow }) {
  const t = useRoleText(), receipt = flow.receipt;
  return <div>
    <Typography.Title level={5}>{t('原角色意图回执（GET）', 'Original Role intent receipt (GET)')}</Typography.Title>
    <Space wrap>
      <Input aria-label={t('回执 Worker 资产 UUID', 'Receipt Worker asset UUID')} value={flow.intent.asset} disabled={flow.writeLocked} style={{ width: 320 }} onChange={event => flow.changeIntent({ asset: event.target.value })} />
      <Input aria-label={t('原角色请求 UUID', 'Original Role request UUID')} value={flow.intent.request} disabled={flow.writeLocked} style={{ width: 320 }} onChange={event => flow.changeIntent({ request: event.target.value })} />
      <Button loading={flow.reading} disabled={!uuid(flow.intent.asset) || !uuid(flow.intent.request) || flow.reading} onClick={() => void flow.readReceipt()}>{t('读取原角色回执（不重派）', 'Read original Role receipt (no redispatch)')}</Button>
    </Space>
    {flow.recovery && <Space direction="vertical">
      <Alert type="warning" message={t('原意图保留，新的写操作已锁定', 'Original intent retained; new writes are locked')}
        description={flow.recovery.phase === 'unknown' || flow.recovery.phase === 'in_flight'
          ? t('服务端可能已提交。仅读取原 UUID 回执或 GET 比较；404 不能证明未提交，不能解锁或另发新编号。',
            'The server may have committed. Only read the original UUID receipt or compare via GET. HTTP 404 does not prove rejection and cannot unlock or issue a new ID.')
          : t('已有可信原回执或确定的 HTTP 拒绝。核对事实后明确开始新的本地操作；仍保留旧草稿 CAS，需人工比较/采用和重新确认。',
            'A trusted receipt or definite HTTP rejection is available. Review it and explicitly start a new local action. The old draft CAS remains; compare/adopt and reconfirm manually.')} />
      <Popconfirm title={t('结束旧意图核查，明确开始新的本地操作？', 'Finish reviewing the old intent and explicitly start a new local action?')}
        okText={t('确认新的本地操作', 'Confirm new local action')} onConfirm={flow.beginNewAction}>
        <Button disabled={flow.busy || flow.reading || !['committed', 'rejected'].includes(flow.recovery.phase)}>{t('明确开始新的本地操作', 'Start new local action explicitly')}</Button>
      </Popconfirm>
    </Space>}
    {receipt && <>
      <Alert type="info" message={t('不可变原事实，未调用云端；此回执不证明当前角色资格或云权限。',
        'Immutable original fact with no cloud call; this receipt proves neither current Role qualification nor cloud permissions.')} />
      <Descriptions title={t('原角色提交事实', 'Original Role submission fact')} size="small" column={2} items={[
        { key: 'request', label: t('请求编号', 'Request ID'), children: receipt.requestId },
        { key: 'asset', label: t('Agent 资产', 'Agent asset'), children: receipt.assetId },
        { key: 'version', label: t('原版本', 'Original revision'), children: receipt.original.version },
        { key: 'state', label: t('原状态', 'Original state'), children: receipt.original.eligibility },
        { key: 'role', label: t('平台角色 UUID', 'Platform Role UUID'), children: receipt.original.proof.platformRoleId },
      ]} />
    </>}
  </div>;
}

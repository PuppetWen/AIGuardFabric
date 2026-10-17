import { useTranslation } from 'react-i18next';
import { Alert, Button, Descriptions, Space, Tag, Typography } from 'antd';
import { Panel } from '@/components/Panel';
import type { TeamOperation, TeamRecoveryAction } from '@/types/teamManagement';

interface Props {
  operation: TeamOperation;
  busy: boolean;
  canObserve: boolean;
  canPublish: boolean;
  onRecover: (action: TeamRecoveryAction) => Promise<void>;
}
export default function TeamOperationPanel({ operation, busy, canObserve, canPublish, onRecover }: Props) {
  const { t } = useTranslation();
  const actions: { value: TeamRecoveryAction; label: string; enabled: boolean }[] = [
    { value: 'read_receipt', label: t('teamManagement.refreshReceipt'), enabled: true },
    { value: 'observe', label: t('teamManagement.observe'), enabled: canObserve && !operation.busy },
    { value: 'retry_inventory', label: t('teamManagement.publish'), enabled: canPublish && !operation.busy },
  ];
  return <Panel title={t('teamManagement.receipt')}>
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Space wrap><Tag color={operation.status === 'verified' ? 'green' : 'gold'}>{t(`teamManagement.status.${operation.status}`)}</Tag>
        <Tag>{operation.mocked ? 'Mock' : 'Live'}</Tag><Typography.Text>{operation.teamName}</Typography.Text></Space>
      <Descriptions size="small" bordered column={2} items={[
        { key: 'id', label: t('teamManagement.receipt'), children: <Typography.Text copyable>{operation.id}</Typography.Text> },
        { key: 'request', label: t('teamManagement.request'), children: <Typography.Text copyable>{operation.requestId}</Typography.Text> },
        { key: 'scope', label: t('teamManagement.instance'), children: `${operation.scopeId} / ${operation.configurationVersion}` },
        { key: 'cloud', label: t('teamManagement.cloudWrite'), children: t(`teamManagement.stage.${operation.cloudWrite.status}`) },
        { key: 'readback', label: t('teamManagement.readback'), children: t(`teamManagement.stage.${operation.readback.status}`) },
        { key: 'publish', label: t('teamManagement.publication'), children: t(`teamManagement.stage.${operation.inventoryPublish.status}`) },
        { key: 'observed', label: t('teamManagement.observedAt'), children: operation.readback.observedAt ?? t('teamManagement.unknown') },
      ]} />
      {operation.recoveryConfigurationVersion !== null && operation.recoveryScopeId !== null
        && (operation.recoveryConfigurationVersion !== operation.configurationVersion || operation.recoveryScopeId !== operation.scopeId)
        && <Alert showIcon type="info" message={t('teamManagement.recoveryConfiguration', {
          scope: operation.recoveryScopeId, version: operation.recoveryConfigurationVersion,
        })} description={t('teamManagement.recoverySource')} />}
      {operation.status === 'uncertain' && <Alert showIcon type="warning" message={t('teamManagement.uncertain')} />}
      {operation.status === 'deleting' && <Alert showIcon type="info" message={t('teamManagement.deletePending')} />}
      {operation.status === 'superseded' && <Alert showIcon type="warning" message={t('teamManagement.superseded')} />}
      {operation.status !== 'verified' && <Alert showIcon type="info" message={t('teamManagement.partial')} />}
      {operation.safeError && <Alert showIcon type="error" message={operation.safeError.message} description={operation.safeError.code} />}
      {operation.readback.conflictFields.length > 0 && <Typography.Text>{operation.readback.conflictFields.join(', ')}</Typography.Text>}
      <Space wrap>{actions.filter(action => operation.allowedActions.includes(action.value))
        .filter(action => action.value === 'read_receipt' || (action.value === 'observe' ? canObserve : canPublish))
        .map(action => <Button key={action.value} disabled={busy || !action.enabled} loading={busy}
          onClick={() => void onRecover(action.value)}>{action.label}</Button>)}</Space>
    </Space>
  </Panel>;
}

import { Alert, Button, Descriptions, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { IntegrationRun } from '@/api/integrations';

export function OperationReceipt({ run, permission, canWrite, busy, onRead, onRecover }: {
  run: IntegrationRun; permission: 'alicloud:write' | 'integrations:write'; canWrite: boolean; busy: boolean;
  onRead: () => void; onRecover: () => void;
}) {
  const { t } = useTranslation();
  const stage = run.completionState ?? 'unknown';
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Descriptions size="small" column={1} items={[
      { key: 'request', label: t('receipt.request'), children: <Typography.Text copyable>{run.requestId}</Typography.Text> },
      { key: 'version', label: t('receipt.originalVersion'), children: run.configurationVersion },
      { key: 'mode', label: t('receipt.mode'), children: run.mocked ? 'Mock' : 'Live' },
      { key: 'completion', label: t('receipt.completion'), children: t(`receipt.stage.${stage}`) },
      ...(stage === 'pending_audit' ? [{ key: 'provider', label: t('receipt.provider'),
        children: `${run.providerStatus ?? 'unknown'} · ${t('receipt.providerHint')}` }] : []),
    ]} />
    {stage === 'pending_audit' && <Alert type="warning" showIcon message={t('receipt.pending')} description={t('receipt.recoveryHint')} />}
    {stage === 'running' && <Alert type="warning" showIcon message={t('receipt.running')} />}
    {run.status === 'uncertain' && stage === 'complete' && <Alert type="warning" showIcon message={t('receipt.uncertain')} />}
    <Space wrap>
      <Button disabled={busy || !canWrite} onClick={onRead}>{t('receipt.read')}</Button>
      {stage === 'pending_audit' && <Button disabled={busy || !canWrite} onClick={onRecover}>{t('receipt.recover')}</Button>}
    </Space>
    {!canWrite && <Typography.Text type="secondary">{t('receipt.inspectPermission', { permission })}</Typography.Text>}
  </Space>;
}

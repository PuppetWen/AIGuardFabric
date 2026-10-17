import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Descriptions, Space, Table, Typography } from 'antd';
import type { TeamPreview } from '@/types/teamManagement';
import { Panel } from '@/components/Panel';

interface Props {
  preview: TeamPreview;
  usable: boolean;
  canApply: boolean;
  busy: boolean;
  confirmed: boolean;
  onConfirm: (value: boolean) => void;
  onApply: () => Promise<void>;
  onRefresh: () => Promise<void>;
}
export default function TeamPreviewPanel({ preview, usable, canApply, busy, confirmed, onConfirm, onApply, onRefresh }: Props) {
  const { t } = useTranslation();
  const names = (value: string[] | null | undefined) => value === null || value === undefined
    ? t('teamManagement.unknown') : value.join(', ') || t('teamManagement.none');
  const rows = [
    { field: t('teamManagement.description'), before: preview.before.description ?? t('teamManagement.unknown'),
      after: preview.descriptionChanged ? preview.desired.description ?? '' : t('teamManagement.unchanged') },
    { field: t('teamManagement.members'), before: preview.before.memberNamesAvailable ? names(preview.before.memberNames) : t('teamManagement.unknown'),
      after: Array.isArray(preview.desired.memberNames) ? names(preview.desired.memberNames) : t('teamManagement.unchanged') },
    ...(preview.action === 'create' ? [{ field: t('teamManagement.admin'), before: '—', after: preview.desired.adminName ?? t('teamManagement.none') }] : []),
  ];
  return <Panel title={t('teamManagement.preview')}>
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Descriptions size="small" bordered column={2} items={[
        { key: 'team', label: t('teamManagement.name'), children: preview.teamName },
        { key: 'action', label: t('common.actions'), children: t(`teamManagement.${preview.action}`) },
        { key: 'instance', label: t('teamManagement.instance'), children: `${preview.instanceId} / ${preview.configurationVersion} · ${preview.mocked ? 'Mock' : 'Live'}` },
        { key: 'expires', label: t('teamManagement.expires'), children: preview.expiresAt },
      ]} />
      <Table rowKey="field" pagination={false} size="small" dataSource={rows} columns={[
        { title: t('common.name'), dataIndex: 'field' },
        { title: t('teamManagement.before'), dataIndex: 'before' },
        { title: t('teamManagement.after'), dataIndex: 'after' },
      ]} />
      <Typography.Text>{t('teamManagement.added')}: {names(preview.addedMembers)}</Typography.Text>
      <Typography.Text>{t('teamManagement.removed')}: {names(preview.removedMembers)}</Typography.Text>
      {preview.deleteImpact && <Descriptions title={t('teamManagement.deleteImpact')} size="small" bordered column={2}
        items={(['workerCount', 'humanCount', 'roomCount', 'taskCount'] as const).map((key, index) => ({
          key, label: t(`teamManagement.${['workers', 'humans', 'rooms', 'tasks'][index]}`),
          children: preview.deleteImpact![key] ?? t('teamManagement.unknown'),
        }))} />}
      {preview.action === 'delete' && <Alert type="warning" showIcon message={t('teamManagement.deleteCleanup')} />}
      {preview.action === 'create' && <Alert type="info" showIcon message={t('teamManagement.adminHint')} />}
      <Alert type="warning" showIcon message={t('teamManagement.noCas')} />
      {!usable && <Alert type="warning" showIcon message={t('teamManagement.previewInvalid')}
        description={preview.unusableReason ?? undefined} />}
      <Space wrap>
        <Button disabled={busy} onClick={() => void onRefresh()}>{t('teamManagement.refreshPreview')}</Button>
        {canApply && <>
          <Checkbox checked={confirmed} disabled={busy || !usable} onChange={event => onConfirm(event.target.checked)}>
            {t('teamManagement.confirm')}
          </Checkbox>
          <Button type="primary" danger={preview.action === 'delete'} loading={busy} disabled={busy || !usable || !confirmed}
            onClick={() => void onApply()}>{t('teamManagement.apply')}</Button>
        </>}
      </Space>
    </Space>
  </Panel>;
}

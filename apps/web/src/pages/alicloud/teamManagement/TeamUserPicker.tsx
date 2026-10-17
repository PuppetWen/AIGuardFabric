import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input, Space, Table, Typography } from 'antd';
import type { TeamUserDirectory } from '@/types/teamManagement';

interface Props {
  directory?: TeamUserDirectory | null;
  busy: boolean;
  canReadCloud: boolean;
  usable: boolean;
  onRead: (nameLike: string, cursor?: string) => Promise<void>;
}
export default function TeamUserPicker({ directory, busy, canReadCloud, usable, onRead }: Props) {
  const { t } = useTranslation();
  const [filter, setFilter] = useState('');
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text strong>{t('teamManagement.users')}</Typography.Text>
    <Space wrap>
      <Input aria-label={t('teamManagement.search')} placeholder={t('teamManagement.search')}
        value={filter} maxLength={128} disabled={busy} style={{ width: 280 }} onChange={event => setFilter(event.target.value)} />
      <Button disabled={busy || !canReadCloud} loading={busy} onClick={() => void onRead(filter)}>{t('teamManagement.loadUsers')}</Button>
      {directory?.nextCursor && <Button disabled={busy || !canReadCloud || !usable}
        onClick={() => void onRead(directory.query.nameLike ?? '', directory.nextCursor ?? undefined)}>{t('teamManagement.nextUsers')}</Button>}
    </Space>
    {directory && <>
      <Typography.Text>{t('teamManagement.userObservation')}: {directory.observedAt}</Typography.Text>
      {!usable && <Alert type="warning" showIcon message={t('teamManagement.directoryOld')} />}
      {!directory.directoryComplete && <Alert type="info" showIcon message={t('teamManagement.directoryPartial')} />}
      <Table rowKey="name" size="small" pagination={false} dataSource={directory.items} columns={[
        { title: t('teamManagement.userName'), dataIndex: 'name' },
        { title: t('common.name'), dataIndex: 'displayName', render: value => value ?? '—' },
        { title: t('teamManagement.userStatus'), dataIndex: 'status', render: value => value ?? t('teamManagement.unknown') },
      ]} />
    </>}
  </Space>;
}

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { Alert, Button, Checkbox, Descriptions, Space, Table, Tag, Typography } from 'antd';
import { teamManagementApi } from '@/api/teamManagement';
import { useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { TeamManagement } from '@/types/teamManagement';
import TeamDraft from './teamManagement/TeamDraft';
import TeamUserPicker from './teamManagement/TeamUserPicker';
import TeamPreviewPanel from './teamManagement/TeamPreviewPanel';
import TeamOperationPanel from './teamManagement/TeamOperationPanel';
import TeamManagementGuide from './teamManagement/TeamManagementGuide';
import { useTeamManagement } from './teamManagement/useTeamManagement';
import { currentTeamRecovery } from './teamManagement/teamDraftState';

export default function TeamManagementPanel() {
  const tenantId = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <TeamManagementAccess key={`${tenantId ?? 'none'}:${generation}`} />;
}
function TeamManagementAccess() {
  const { t } = useTranslation();
  const access = useSessionAccess();
  const canRead = access.has('alicloud:read');
  const [params] = useSearchParams();
  // Only use the initial recovery ID as a query key; recording a new write ID must not unmount its controller.
  const [restoreId] = useState(() => params.get('request_id') ?? undefined);
  const query = useApiQuery('agentteams-team-management', () => teamManagementApi.list(restoreId),
    { enabled: canRead, key: [restoreId] });
  const data = query.data?.data;
  const ready = !!data && !query.error && !query.isFetching;
  const canPrepare = ready && data!.enabled && data!.inventoryAvailable && data!.canPrepare
    && access.has('alicloud:write');
  const canApply = canPrepare && data!.canWrite && access.has('assets:write');
  return <DataState loading={access.isLoading} error={access.error}>
    {!canRead ? <Alert type="info" showIcon message={t('teamManagement.readAccess')} />
      : <DataState loading={query.isLoading} error={query.error} onRetry={() => void query.refetch()}>
        {data && <TeamManagementContent key={`${data.scopeId}:${data.configurationVersion}:${data.mocked}:${data.enabled}`}
          data={data} ready={ready} canPrepare={canPrepare} canApply={canApply} canWriteAccess={access.has('alicloud:write')}
          refreshing={query.isFetching} refresh={() => query.refetch()} />}
      </DataState>}
  </DataState>;
}
interface ContentProps {
  data: TeamManagement;
  ready: boolean;
  canPrepare: boolean;
  canApply: boolean;
  canWriteAccess: boolean;
  refreshing: boolean;
  refresh: () => Promise<unknown>;
}
function TeamManagementContent(props: ContentProps) {
  const { t } = useTranslation();
  const { data, canPrepare, canApply, canWriteAccess } = props;
  const state = useTeamManagement(props);
  const operationCurrent = !!state.operation && currentTeamRecovery(state.operation, data);
  return <Space direction="vertical" size={14} style={{ width: '100%' }}>
    <Panel title={t('teamManagement.title')}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Space wrap><Button disabled={state.busy} loading={props.refreshing} onClick={() => void props.refresh()}>{t('teamManagement.refresh')}</Button>
          <Tag>{data.mocked === null ? t('teamManagement.unknown') : data.mocked ? 'Mock' : 'Live'}</Tag></Space>
        <Descriptions size="small" items={[{ key: 'scope', label: t('teamManagement.instance'),
          children: `${data.instanceId ?? t('teamManagement.unknown')} / ${data.configurationVersion} · ${data.region ?? '—'}` }]} />
        {!canWriteAccess && <Alert type="info" showIcon message={t('teamManagement.readOnly')} />}
        {canWriteAccess && !canApply && <Alert type="info" showIcon message={t('teamManagement.assetsAccess')} />}
        {(!data.enabled || !data.inventoryAvailable) && <Alert type="warning" showIcon message={t('teamManagement.inventoryRequired')} />}
        {state.error && <Alert type="error" showIcon message={state.error} />}
        {data.mocked === false && canWriteAccess && <Checkbox checked={state.liveConfirmed} disabled={state.busy}
          onChange={event => state.setLiveConfirmed(event.target.checked)}>{t('teamManagement.live')}</Checkbox>}
        <TeamDraft draft={state.draft} team={state.team} teams={data.items} options={state.options}
          disabled={state.busy || !canPrepare} canChooseUsers={state.directoryUsable}
          onChange={state.changeDraft} onChooseTeam={state.chooseTeam} onAction={state.chooseAction} />
        {canWriteAccess && state.draft.action !== 'delete' && <TeamUserPicker directory={state.directory}
          busy={state.busy} canReadCloud={canPrepare && (data.mocked === true || state.liveConfirmed)} usable={state.directoryUsable}
          onRead={state.readUsers} />}
        {canWriteAccess && <Button type="primary" loading={state.busy} disabled={state.busy || !state.canPreview}
          onClick={() => void state.prepare()}>{t('teamManagement.prepare')}</Button>}
        {state.requestId && <Space wrap><Typography.Text copyable>{t('teamManagement.request')}: {state.requestId}</Typography.Text>
          <Button disabled={state.busy} onClick={() => void state.restore()}>{t('teamManagement.restore')}</Button></Space>}
        {state.requestId && !state.operation && <Alert type="warning" showIcon message={t('teamManagement.uncertain')} />}
      </Space>
    </Panel>
    {state.preview && <TeamPreviewPanel preview={state.preview} usable={state.usablePreview} canApply={canApply}
      busy={state.busy} confirmed={state.confirmed} onConfirm={state.setConfirmed} onApply={state.apply} onRefresh={state.refreshPreview} />}
    {state.operation && <TeamOperationPanel operation={state.operation} busy={state.busy}
      canObserve={canPrepare && operationCurrent && (data.mocked === true || state.liveConfirmed)}
      canPublish={canApply && operationCurrent && (data.mocked === true || state.liveConfirmed)} onRecover={state.recover} />}
    {data.operations.length > 0 && <Panel title={t('teamManagement.history')}>
      <Table rowKey="id" size="small" pagination={{ pageSize: 5 }} dataSource={data.operations} columns={[
        { title: t('teamManagement.name'), dataIndex: 'teamName' },
        { title: t('teamManagement.receipt'), dataIndex: 'status', render: value => t(`teamManagement.status.${value}`) },
        { title: t('teamManagement.request'), dataIndex: 'requestId' },
        { title: t('common.actions'), render: (_, item) => <Button disabled={state.busy} onClick={() => state.viewOperation(item)}>{t('teamManagement.viewReceipt')}</Button> },
      ]} />
    </Panel>}
    <TeamManagementGuide />
  </Space>;
}

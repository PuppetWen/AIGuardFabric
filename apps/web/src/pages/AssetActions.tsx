import { Button, Space, Tooltip } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { AssetRegistration } from './AssetRegistration';
import { AssetDailyInventory } from './AssetDailyInventory';
import { inventoryHistory } from '@/api/assetInventory';

export function AssetActions({ refresh, onRegistered }: { refresh: () => Promise<unknown>; onRegistered: (id: string) => Promise<void> }) {
  const { t, i18n } = useTranslation();
  const state = useApiQuery('asset-inventory-capabilities', () => inventoryHistory());
  return <Space wrap>
    {state.data?.data.canWrite && <AssetRegistration onSaved={onRegistered} />}
    {state.data && <AssetDailyInventory canWrite={state.data.data.canWrite} automaticEnabled={state.data.data.automaticEnabled} />}
    {state.error && <Tooltip title={String(state.error)}><Button danger onClick={() => void state.refetch()}>
      {i18n.language.startsWith('zh') ? '重试资产权限检查' : 'Retry asset permissions'}</Button></Tooltip>}
    <Button icon={<ReloadOutlined />} onClick={() => { void refresh(); void state.refetch(); }}>{t('common.refresh')}</Button>
  </Space>;
}

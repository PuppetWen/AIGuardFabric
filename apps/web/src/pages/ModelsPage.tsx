import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Form, Input, Space } from 'antd';
import { ReloadOutlined, SettingOutlined } from '@ant-design/icons';
import { api, useApiQuery } from '@/api/client';
import { modelMeterProjectionApi } from '@/api/modelMeterProjection';
import { MeterProjectionNotice } from './models/MeterProjectionNotice';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { DataState, PageHeader } from '@/components/DataState';
import type { ModelRoutePolicy } from '@/types/domain';
import { ModelEndpointsTable } from './models/ModelEndpointsTable';
import { GatewayConfiguration } from './models/GatewayConfiguration';
import { RouteEditorDrawer } from './models/RouteEditorDrawer';
import { RoutePoliciesPanel } from './models/RoutePoliciesPanel';
import { UsageByModelPanel } from './models/UsageByModelPanel';
import { UsageCharts } from './models/UsageCharts';
import { UsageRecordsPanel } from './models/UsageRecordsPanel';
import { ModelUsageGuide } from './models/ModelUsageGuide';
import { SemanticCacheProfilePanel } from './models/semantic-cache/SemanticCacheProfilePanel';
import { GatewaySettlementPanel } from './models/settlement/GatewaySettlementPanel';

export default function ModelsPage() {
  const identity = useAuthStore(state => `${state.tenant?.id}:${state.sessionGeneration}`);
  return <ModelInventory key={identity} />;
}
function ModelInventory() {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const canWrite = useSessionAccess().has('models:write');
  const [routeTarget, setRouteTarget] = useState<ModelRoutePolicy | null>(null);
  const [form] = Form.useForm<ModelRoutePolicy>();
  const [query, setQuery] = useState({ page: 1, pageSize: 12 });
  const [endpointQuery, setEndpointQuery] = useState({ page: 1, pageSize: 20, keyword: '', sort: 'name' });
  const endpoints = useApiQuery('model-endpoints', () => api.modelEndpoints(endpointQuery), { key: [endpointQuery] });
  const routes = useApiQuery('model-routes', () => api.routePolicies());
  const usage = useApiQuery('model-usage', () => api.modelUsage());
  const projection = useApiQuery('model-meter-projection-status', () => modelMeterProjectionApi.read());
  const records = useApiQuery('model-usage-records', () => api.tokenUsage(query), { key: [query] });
  const endpointList = endpoints.data?.data.items ?? [];
  const usageRows = (usage.data?.data ?? []).filter(row => !row.mocked);
  const mockedCalls = (usage.data?.data ?? []).filter(row => row.mocked).reduce((n, row) => n + row.calls, 0);
  return <>
    <PageHeader title={t('models.title')} subtitle={t('models.subtitle')} actions={<Space wrap>
      <Button icon={<ReloadOutlined />} onClick={() => {
        void endpoints.refetch(); void usage.refetch(); void records.refetch(); void routes.refetch(); void projection.refetch();
      }}>{t('common.refresh')}</Button>
      {canWrite && <Button type="primary" icon={<SettingOutlined />} onClick={() => {
        const fresh: ModelRoutePolicy = { id: '', version: 0, name: '', primaryEndpointId: '', fallbackEndpointIds: [],
          strategy: 'priority', weights: {}, budgetCnyPerDay: 0, enabled: true };
        setRouteTarget(fresh); form.resetFields(); form.setFieldsValue(fresh);
      }}>{text('新建路由策略', 'Create route policy')}</Button>}
    </Space>} />
    <ModelUsageGuide />
    <Space direction="vertical" size={14} style={{ width: '100%' }}>
      <GatewayConfiguration canWrite={canWrite} />
      <SemanticCacheProfilePanel />
      <GatewaySettlementPanel />
      <Input.Search allowClear placeholder={text('搜索模型台账名称、负责人或标签', 'Search model inventory name, owner or tag')}
        onSearch={keyword => setEndpointQuery(value => ({ ...value, page: 1, keyword }))} style={{ width: 350 }} />
      <ModelEndpointsTable loading={endpoints.isLoading} error={endpoints.error} endpoints={endpointList}
        pagination={{ current: endpointQuery.page, pageSize: endpointQuery.pageSize,
          total: endpoints.data?.data.total ?? 0 }}
        onPageChange={(page, pageSize) => setEndpointQuery(value => ({ ...value, page, pageSize }))} />
      <Alert type="info" showIcon message={text('费用汇总：已保留的真实调用估算（CNY）',
        'Cost summary: retained real-call estimates (CNY)')}
        description={text(`已排除 ${mockedCalls} 次模拟计量；明细保留模拟和缓存标记。这里不是当日账单。`,
          `Excludes ${mockedCalls} mock records. Details retain mock and cache markers. This is not a daily bill.`)} />
      <MeterProjectionNotice status={projection.data?.data} loading={projection.isLoading} failed={!!projection.error} />
      <DataState loading={usage.isLoading} error={usage.error}>
        <UsageCharts usage={usageRows} /><UsageByModelPanel usage={usageRows} />
      </DataState>
      <UsageRecordsPanel loading={records.isLoading} error={records.error} records={records.data?.data.items ?? []}
        pagination={{ current: query.page, pageSize: query.pageSize, total: records.data?.data.total ?? 0 }}
        onPageChange={(page, pageSize) => setQuery({ page, pageSize })} />
      <DataState loading={routes.isLoading} error={routes.error}>
        <RoutePoliciesPanel routes={routes.data?.data ?? []} canWrite={canWrite}
          onSaved={() => void routes.refetch()} onEdit={record => {
            setRouteTarget(record); form.resetFields(); form.setFieldsValue(record);
          }} />
      </DataState>
    </Space>
    {routeTarget && <RouteEditorDrawer key={routeTarget.id || 'new'} open routeTarget={routeTarget} form={form}
      canWrite={canWrite} onClose={() => setRouteTarget(null)} onSaved={() => {
        setRouteTarget(null); void routes.refetch();
      }} />}
  </>;
}

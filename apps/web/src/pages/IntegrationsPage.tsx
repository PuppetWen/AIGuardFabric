import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Button,
  Segmented,
  Space,
  Tag,
  Typography,
  message,
} from 'antd';
import { ApiOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { HealthTag } from '@/components/Tags';
import type { Adapter, AdapterCategory, AdapterHealth } from '@/types/domain';
import { formatDateTime } from '@/utils/format';
import { adapterCategoryKey } from '@/utils/labels';
import { integrationsApi } from '@/api/integrations';
import IntegrationEditor from './integrations/IntegrationEditor';

type HealthFilter = 'all' | AdapterHealth;

export default function IntegrationsPage() {
  const { t, i18n } = useTranslation();
  const locale = useAppLocale();
  const [category, setCategory] = useState<AdapterCategory | 'all'>('all');
  const [health, setHealth] = useState<HealthFilter>('all');
  const [selected, setSelected] = useState<Adapter | null>(null);
  const [testing, setTesting] = useState(false);

  const adapters = useApiQuery('adapters', () => api.adapters());

  const categories = useMemo(
    () => [...new Set((adapters.data?.data ?? []).map((adapter) => adapter.category))],
    [adapters.data],
  );

  const rows = useMemo(() => {
    return (adapters.data?.data ?? []).filter((adapter) => {
      if (category !== 'all' && adapter.category !== category) {
        return false;
      }
      if (health !== 'all' && adapter.health !== health) {
        return false;
      }
      return true;
    });
  }, [adapters.data, category, health]);

  const testConnection = async (adapter: Adapter): Promise<void> => {
    setTesting(true);
    try {
      const result = (await integrationsApi.probe(adapter.id)).data;
      if (result.tcpReachable === false) message.error(result.note);
      else message.info(result.note);
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <PageHeader
        title={t('integrations.title')}
        subtitle={t('integrations.subtitle')}
        actions={
          <Space wrap>
            <Segmented<HealthFilter>
              value={health}
              onChange={(value) => setHealth(value)}
              options={[
                { value: 'all', label: t('common.all') },
                { value: 'healthy', label: t('health.healthy') },
                { value: 'degraded', label: t('health.degraded') },
                { value: 'unhealthy', label: t('health.unhealthy') },
                { value: 'unknown', label: t('health.unknown') },
              ]}
            />
            <Button icon={<ReloadOutlined />} onClick={() => void adapters.refetch()}>
              {t('common.refresh')}
            </Button>
          </Space>
        }
      />

      <DataState loading={adapters.isLoading} error={adapters.error} skeletonRows={6}>
        <Space direction="vertical" size={14} style={{ width: '100%' }}>
          <Space wrap size={6}>
            <Button size="small" type={category === 'all' ? 'primary' : 'default'} onClick={() => setCategory('all')}>
              {t('common.all')} ({(adapters.data?.data ?? []).length})
            </Button>
            {categories.map((value) => (
              <Button
                key={value}
                size="small"
                type={category === value ? 'primary' : 'default'}
                onClick={() => setCategory(value)}
              >
                {t(adapterCategoryKey(value))} (
                {(adapters.data?.data ?? []).filter((adapter) => adapter.category === value).length})
              </Button>
            ))}
          </Space>

          <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
            {rows.map((adapter) => (
              <div key={adapter.id} className="agf-panel agf-panel--pad">
                <Space direction="vertical" size={10} style={{ width: '100%' }}>
                  <Space size={8} wrap style={{ justifyContent: 'space-between', width: '100%' }}>
                    <Space size={8} wrap>
                      <ApiOutlined style={{ color: 'var(--agf-accent)' }} />
                      <Typography.Text strong>{adapter.name}</Typography.Text>
                    </Space>
                    <Space size={6}>
                      {adapter.mock ? <Tag color="gold">{t('common.mock')}</Tag> : null}
                      <HealthTag health={adapter.health} />
                    </Space>
                  </Space>

                  <Space size={8} wrap className="agf-muted" style={{ fontSize: 12 }}>
                    <Tag color="geekblue">{t(adapterCategoryKey(adapter.category))}</Tag>
                    <span>{adapter.vendor}</span>
                    <Tag className="agf-mono" style={{ fontSize: 11 }}>
                      v{adapter.version}
                    </Tag>
                  </Space>

                  <Space size={8} wrap>
                    {adapter.capabilities.map((capability) => (
                      <Tag key={capability} style={{ marginInlineEnd: 0, fontSize: 11 }}>
                        {capability}
                      </Tag>
                    ))}
                  </Space>

                  <Space size={12} wrap className="agf-muted" style={{ fontSize: 12 }}>
                    <span>
                      {t('integrations.column.configured')}:{' '}
                      {adapter.configured ? t('integrations.configured.yes') : t('integrations.configured.no')}
                    </span>
                    <span>
                      {t('integrations.column.lastSync')}:{' '}
                      {adapter.lastSyncAt ? formatDateTime(adapter.lastSyncAt, locale) : '—'}
                    </span>
                    <span>
                      {t('integrations.column.latency')}: {adapter.latencyMs ?? '—'} {t('unit.msShort')}
                    </span>
                  </Space>

                  {adapter.healthNote && <Typography.Text type="secondary">{adapter.healthNote}</Typography.Text>}

                  <Space>
                    <Button size="small" onClick={() => setSelected(adapter)}>
                      {t('common.edit')}
                    </Button>
                    <Button
                      size="small"
                      icon={<ThunderboltOutlined />}
                      loading={testing}
                      onClick={() => void testConnection(adapter)}
                    >
                      {i18n.language?.startsWith('zh') ? '检查 TCP 连通性' : 'Check TCP reachability'}
                    </Button>
                  </Space>
                </Space>
              </div>
            ))}
          </div>
        </Space>
      </DataState>

      {selected && <IntegrationEditor key={selected.id} name={selected.id} title={selected.name}
        onClose={() => setSelected(null)} onSaved={() => void adapters.refetch()} />}
    </>
  );
}

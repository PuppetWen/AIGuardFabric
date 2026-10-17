import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Switch, Table, Tag, message } from 'antd';

import { api } from '@/api/client';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { ModelRoutePolicy } from '@/types/domain';
import { formatCny } from '@/utils/format';

interface RoutePoliciesPanelProps {
  routes: ModelRoutePolicy[];
  canWrite: boolean;
  onSaved: () => void;
  onEdit: (policy: ModelRoutePolicy) => void;
}

/** Routing policies, with an inline enable toggle. */
export function RoutePoliciesPanel({
  routes,
  canWrite,
  onSaved,
  onEdit,
}: RoutePoliciesPanelProps) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [pending, setPending] = useState<string>();

  return (
    <Panel title={t('models.route.title')}>
      <Table<ModelRoutePolicy>
        rowKey="id"
        size="small"
        pagination={false}
        dataSource={routes}
        scroll={{ x: 1080 }}
        columns={[
          { title: t('models.route.name'), dataIndex: 'name', width: 200 },
          {
            title: t('models.route.strategy'),
            dataIndex: 'strategy',
            width: 160,
            render: (value: ModelRoutePolicy['strategy']) => (
              <Chip color="#3d8bfd">{t(`models.route.strategy.${value}`)}</Chip>
            ),
          },
          {
            title: t('models.route.primary'),
            dataIndex: 'primaryEndpointId',
            width: 180,
            render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
          },
          {
            title: t('models.route.fallbacks'),
            dataIndex: 'fallbackEndpointIds',
            width: 320,
            render: (values: string[]) => (
              <span className="agf-inline-list">
                {values.map((value) => (
                  <Tag key={value} className="agf-mono" style={{ marginInlineEnd: 0, fontSize: 11 }}>
                    {value}
                  </Tag>
                ))}
              </span>
            ),
          },
          {
            title: t('models.route.budget'),
            dataIndex: 'budgetCnyPerDay',
            width: 130,
            align: 'right',
            render: (value: number) => <span className="agf-mono">{value === 0 ? (zh ? '不限' : 'Unlimited') : formatCny(value, 6)}</span>,
          },
          {
            title: t('common.enabled'),
            dataIndex: 'enabled',
            width: 110,
            render: (value: boolean, record) => (
              <Switch
                size="small"
                checked={value}
                disabled={!canWrite || Boolean(pending)} loading={pending === record.id}
                onChange={(checked) => {
                  if (!canWrite || pending) return;
                  setPending(record.id);
                  void api.saveRoutePolicy({ id: record.id, expectedVersion: record.version, enabled: checked }).then(() => {
                    onSaved();
                    message.success(t('models.route.saved'));
                  }).catch((error: unknown) => {
                    message.error(error instanceof Error ? error.message : (zh ? '保存失败' : 'Save failed'));
                    onSaved();
                  })
                    .finally(() => setPending(undefined));
                }}
              />
            ),
          },
          {
            title: t('common.actions'),
            key: 'actions',
            width: 100,
            render: (_value, record) => (
              <Button
                size="small"
                type="link"
                disabled={!canWrite}
                onClick={() => onEdit(record)}
              >
                {t('common.edit')}
              </Button>
            ),
          },
        ]}
      />
    </Panel>
  );
}

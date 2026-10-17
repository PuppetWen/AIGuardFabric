import { Table, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Panel } from '@/components/Panel';
import type { InterceptEvent } from '@/types/domain';
import { toolActivity24h, type ToolActivity } from './toolActivity';

export function RuntimeToolActivity({ events }: { events: readonly InterceptEvent[] }) {
  const { t } = useTranslation();
  const rows = toolActivity24h(events);
  return <Panel title={t('runtime.tools.title')}>
    <Typography.Paragraph className="agf-muted">{t('runtime.tools.scope')}</Typography.Paragraph>
    <Table<ToolActivity> rowKey="name" size="small" dataSource={rows} pagination={{ pageSize: 5 }}
      locale={{ emptyText: t('common.empty') }} columns={[
        { title: t('runtime.tools.name'), dataIndex: 'name', ellipsis: true },
        { title: t('runtime.tools.checks'), dataIndex: 'checks', width: 120, align: 'right' },
        { title: t('runtime.tools.blocked'), dataIndex: 'blocked', width: 120, align: 'right' },
      ]} />
  </Panel>;
}

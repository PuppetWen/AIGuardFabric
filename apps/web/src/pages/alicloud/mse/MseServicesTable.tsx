import { Space, Table, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import type { MseService } from '@/types/mseInventory';

export default function MseServicesTable({ items, canReadAssets }: { items: MseService[]; canReadAssets: boolean }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const unknown = text('未知', 'Unknown');
  return <Table<MseService> rowKey="key" size="small" dataSource={items} pagination={{ pageSize: 50, showSizeChanger: false }}
    scroll={{ x: 1000 }} columns={[
      { title: text('服务 / 分组', 'Service / group'), render: (_, row) => <Space direction="vertical" size={0}>
        <span>{row.name}</span><Typography.Text type="secondary">{row.groupName}</Typography.Text></Space> },
      { title: text('实例 / 健康 / 集群数', 'Instances / healthy / clusters'), render: (_, row) =>
        `${row.instanceCount ?? unknown} / ${row.healthyInstanceCount ?? unknown} / ${row.clusterCount ?? unknown}` },
      { title: text('来源', 'Source'), render: (_, row) => row.source ?? unknown },
      { title: text('地址 / 协议 / 环境 / 网络区域', 'Endpoint / protocol / runtime / network zone'), render: () => unknown },
      { title: text('人工治理', 'Manual governance'), render: (_, row) => row.assetId && canReadAssets
        ? <Link to={`/assets/${row.assetId}`}>{text('打开资产', 'Open asset')}</Link>
        : row.assetId ? <Typography.Text type="secondary">{text('查看资产需要 assets:read', 'Asset viewing requires assets:read')}</Typography.Text> : unknown },
    ]} />;
}

import { Alert, Descriptions, Space, Table, Typography } from 'antd';
import { Link } from 'react-router-dom';
import type { PrivateLinkEndpoint, PrivateLinkSecurityGroup, PrivateLinkZone } from '@/types/privatelinkInventory';
import { usePrivateLinkText } from './usePrivateLinkText';

export default function PrivateLinkEndpointDetails({ endpoint, canReadAssets }: { endpoint: PrivateLinkEndpoint; canReadAssets: boolean }) {
  const text = usePrivateLinkText(), unknown = text('未知', 'Unknown');
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('端点实际观察', 'Observed endpoint')}</Typography.Title>
    <Descriptions size="small" column={2} items={[
      { key: 'id', label: 'EndpointId', children: endpoint.endpointId },
      { key: 'name', label: text('云端名称', 'Cloud name'), children: endpoint.name ?? unknown },
      { key: 'region', label: text('接口返回地域', 'Returned region'), children: endpoint.region ?? unknown },
      { key: 'vpc', label: 'VpcId', children: endpoint.vpcId ?? unknown },
      { key: 'service', label: 'ServiceId', children: endpoint.serviceId ?? unknown },
      { key: 'serviceRegion', label: 'ServiceRegionId', children: endpoint.serviceRegionId ?? unknown },
      { key: 'domain', label: text('接口返回 DNS 域名', 'Returned DNS domain'), children: endpoint.domain ?? unknown },
      { key: 'type', label: text('云端端点类型', 'Cloud endpoint type'), children: endpoint.endpointType ?? unknown },
      { key: 'status', label: text('端点 / 连接 / 业务状态', 'Endpoint / connection / business status'),
        children: `${endpoint.endpointStatus ?? unknown} / ${endpoint.connectionStatus ?? unknown} / ${endpoint.businessStatus ?? unknown}` },
      { key: 'asset', label: text('端点平台资产', 'Endpoint platform asset'), children: endpoint.assetId === null
        ? text('平台资产未提供', 'Platform asset unavailable') : canReadAssets
        ? <Link to={`/assets/${endpoint.assetId}`}>{text('打开端点资产', 'Open endpoint asset')}</Link>
        : text('查看资产需要 assets:read', 'Asset viewing requires assets:read') },
    ]} />
    <Alert showIcon type="info" message={text('网络可达与调用授权未知。云状态和 DNS 名称不证明路由、端口、协议或实际连通性。',
      'Reachability and authorization are unknown. Cloud status and a DNS name do not establish routes, ports, protocols or connectivity.')} />
    <Typography.Title level={5}>{text('可用区', 'Zones')} · {endpoint.zonesAvailable ? endpoint.zones.length : unknown}</Typography.Title>
    {endpoint.zonesAvailable ? <Table<PrivateLinkZone> aria-label={text('PrivateLink 可用区', 'PrivateLink zones')}
      rowKey="zoneId" size="small" dataSource={endpoint.zones} pagination={{ pageSize: 50, showSizeChanger: false }} scroll={{ x: 1100 }} columns={[
        { title: 'ZoneId', dataIndex: 'zoneId' }, { title: text('返回地域', 'Returned region'), render: (_, row) => row.region ?? unknown },
        { title: text('云状态', 'Cloud status'), render: (_, row) => row.status ?? unknown },
        { title: 'ENI / VSwitch', render: (_, row) => `${row.eniId ?? unknown} / ${row.vSwitchId ?? unknown}` },
        { title: 'IPv4 / IPv6', render: (_, row) => `${row.eniIp ?? unknown} / ${row.ipv6 ?? unknown}` },
        { title: text('DNS 域名', 'DNS domain'), render: (_, row) => row.domain ?? unknown },
      ]} /> : <Typography.Text>{text('可用区名单未提供；不是0。', 'Zone list unavailable; this is not zero.')}</Typography.Text>}
    <Typography.Title level={5}>{text('安全组', 'Security groups')} · {endpoint.securityGroupsAvailable ? endpoint.securityGroups.length : unknown}</Typography.Title>
    {endpoint.securityGroupsAvailable ? <Table<PrivateLinkSecurityGroup> aria-label={text('PrivateLink 安全组', 'PrivateLink security groups')}
      rowKey="securityGroupId" size="small" dataSource={endpoint.securityGroups} pagination={{ pageSize: 50, showSizeChanger: false }} columns={[
        { title: 'SecurityGroupId', dataIndex: 'securityGroupId' }, { title: text('云状态', 'Cloud status'), render: (_, row) => row.status ?? unknown },
      ]} /> : <Typography.Text>{text('安全组名单未提供；不是0。', 'Security-group list unavailable; this is not zero.')}</Typography.Text>}
  </Space>;
}

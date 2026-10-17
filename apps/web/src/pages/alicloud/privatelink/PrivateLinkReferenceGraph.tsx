import { useState } from 'react';
import { Button, Descriptions, Input, Space, Table, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';
import type { PrivateLinkEdge, PrivateLinkGraphData, PrivateLinkNode } from '@/types/privatelinkInventory';
import { usePrivateLinkText } from './usePrivateLinkText';

export default function PrivateLinkReferenceGraph({ graph, canReadAssets }: { graph: PrivateLinkGraphData; canReadAssets: boolean }) {
  const text = usePrivateLinkText(), unknown = text('未知', 'Unknown');
  const [filter, setFilter] = useState(''), [selected, setSelected] = useState<string>();
  const nodes = graph.nodes.filter(node => `${node.cloudId} ${node.kind} ${node.region ?? ''}`.toLowerCase().includes(filter.toLowerCase()));
  const node = graph.nodes.find(item => item.id === selected);
  const adjacent = node ? graph.edges.filter(edge => edge.from === node.id || edge.to === node.id) : [];
  const byId = new Map(graph.nodes.map(item => [item.id, item]));
  const short = (id: string) => byId.get(id)?.cloudId ?? text('引用节点未提供', 'Referenced node unavailable');
  const relation = (value: PrivateLinkEdge['relation']) => ({
    has_zone: text('端点所列可用区', 'Endpoint-listed zone'), has_security_group: text('端点所列安全组', 'Endpoint-listed security group'),
    in_vpc: text('接口所述 VPC', 'Returned VPC reference'), references_service: text('接口所述服务', 'Returned service reference'),
    zone_eni: text('可用区所述 ENI', 'Zone-reported ENI'), zone_vswitch: text('可用区所述 VSwitch', 'Zone-reported VSwitch'),
  })[value];
  const preview = adjacent.slice(0, 8);
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('资源引用图', 'Resource reference graph')}</Typography.Title>
    <Typography.Text type="secondary">{text(`已提供 ${graph.nodes.length} 个节点、${graph.edges.length} 条关系；不是数据包路径。仅端点关联平台资产。`,
      `Returned ${graph.nodes.length} nodes and ${graph.edges.length} references; this is not a packet path. Only the endpoint has a platform asset.`)}</Typography.Text>
    <Input aria-label={text('筛选 PrivateLink 引用节点', 'Filter PrivateLink reference nodes')} value={filter}
      placeholder={text('标识 / 类型 / 返回地域', 'Identifier / kind / returned region')} onChange={event => setFilter(event.target.value)} />
    <Table<PrivateLinkNode> rowKey="id" size="small" dataSource={nodes} pagination={{ pageSize: 50, showSizeChanger: false }} columns={[
      { title: text('选择节点', 'Select node'), render: (_, row) => <Button type="link" onClick={() => setSelected(row.id)}>{row.cloudId}</Button> },
      { title: text('类型 / 返回地域', 'Kind / returned region'), render: (_, row) => `${row.kind} / ${row.region ?? unknown}` },
      { title: text('证据范围', 'Evidence scope'), render: (_, row) => <Tag>{row.referenceOnly ? text('资源引用；非独立平台资产', 'Reference; no separate platform asset') : text('端点观察', 'Endpoint observation')}</Tag> },
    ]} />
    {node && <Space direction="vertical" size={8} style={{ width: '100%' }} aria-label={text('所选 PrivateLink 节点证据', 'Selected PrivateLink node evidence')}>
      <Descriptions size="small" column={2} items={[
        { key: 'id', label: text('所选标识', 'Selected identifier'), children: node.cloudId },
        { key: 'region', label: text('返回地域', 'Returned region'), children: node.region ?? unknown },
        { key: 'reachability', label: text('可达 / 授权', 'Reachability / authorization'), children: `${unknown} / ${unknown}` },
        { key: 'asset', label: text('平台资产', 'Platform asset'), children: node.kind === 'endpoint' && !node.referenceOnly && node.assetId && canReadAssets
          ? <Link to={`/assets/${node.assetId}`}>{text('打开端点资产', 'Open endpoint asset')}</Link>
          : node.kind !== 'endpoint' || node.referenceOnly ? text('仅资源引用', 'Reference only') : text('查看资产需要 assets:read', 'Asset viewing requires assets:read') },
      ]} />
      <Typography.Text>{text(`相邻关系 ${adjacent.length}；示意图最多显示前8条，其余见分页证据表。`,
        `Adjacent references ${adjacent.length}; the diagram shows the first 8, with the rest in the paginated evidence table.`)}</Typography.Text>
      <svg role="img" aria-label={text('所选节点的实际引用示意', 'Observed references of selected node')} viewBox={`0 0 800 ${Math.max(90, preview.length * 70)}`} style={{ width: '100%', maxHeight: 420 }}>
        <text x="10" y="25" fontSize="14" fill="currentColor">{node.cloudId}</text>
        {preview.map((edge, index) => <g key={`${edge.from}:${edge.to}:${edge.relation}`}>
          <line x1="20" y1="35" x2="310" y2={index * 70 + 55} stroke="currentColor" strokeDasharray="4 3" />
          <text x="320" y={index * 70 + 40} fontSize="13" fill="currentColor">{short(edge.from)} → {short(edge.to)}</text>
          <text x="320" y={index * 70 + 58} fontSize="12" fill="currentColor">{relation(edge.relation)}</text>
        </g>)}
      </svg>
      <Table<PrivateLinkEdge> rowKey={edge => `${edge.from}:${edge.to}:${edge.relation}`} size="small" dataSource={adjacent}
        pagination={{ pageSize: 50, showSizeChanger: false }} scroll={{ x: 1100 }} columns={[
          { title: text('来源 / 目标', 'From / to'), render: (_, edge) => `${short(edge.from)} / ${short(edge.to)}` },
          { title: text('实际引用关系', 'Observed reference'), render: (_, edge) => relation(edge.relation) },
          { title: text('证据 API', 'Evidence API'), dataIndex: 'evidenceAction' },
          { title: text('观察时间', 'Observed at'), dataIndex: 'observedAt' },
        ]} />
    </Space>}
  </Space>;
}

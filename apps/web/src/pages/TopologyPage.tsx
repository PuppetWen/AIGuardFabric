import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Graph } from '@antv/g6';
import type { GraphData, IPointerEvent } from '@antv/g6';
import { Alert, Button, Descriptions, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { AimOutlined, HighlightOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { DataState, PageHeader } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { TopologyEdge, TopologyGraph, TopologyNode, TopologyNodeType } from '@/types/domain';
import { TOPOLOGY_NODE_HEX } from '@/utils/palette';

const NODE_TYPES: TopologyNodeType[] = ['agent', 'mcp', 'tool', 'datasource', 'model'];

/** Build the G6 graph data from the API payload. */
function toGraphData(graph: TopologyGraph): GraphData {
  return {
    nodes: graph.nodes.map((node) => ({
      id: node.id,
      data: { ...node },
      style: {
        labelText: node.label,
        labelFill: '#e8edf6',
        labelFontSize: 11,
        labelPlacement: 'bottom',
        size: node.type === 'agent' ? 34 : node.type === 'mcp' ? 28 : 22,
        fill: TOPOLOGY_NODE_HEX[node.type] ?? '#6f7683',
        stroke: node.shadow ? '#ff8b90' : 'rgba(255,255,255,0.18)',
        lineWidth: node.shadow ? 3 : 1,
        shadowColor: node.shadow ? 'rgba(255,139,144,0.6)' : 'transparent',
        shadowBlur: node.shadow ? 14 : 0,
        icon: true,
      },
    })),
    edges: graph.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      data: { ...edge },
      style: {
        stroke: edge.egress ? '#ff8b90' : 'rgba(167,179,199,0.32)',
        lineWidth: edge.egress ? 2 : 1,
        endArrow: true,
        lineDash: edge.kind === 'reads' ? [4, 4] : undefined,
      },
    })),
    combos: [],
  };
}

export default function TopologyPage() {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const graphReadyRef = useRef<Promise<void> | null>(null);
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [highlightEgress, setHighlightEgress] = useState(false);
  const [renderError, setRenderError] = useState<string | null>(null);

  const { data, isLoading, error, refetch } = useApiQuery('topology', () => api.topology());

  const graph = data?.data;

  const egressEdgeIds = useMemo(
    () => new Set(graph ? demoTobEgressEdgeIds(graph) : []),
    [graph],
  );
  const egressNodeIds = useMemo(
    () => new Set(graph ? graph.egressPaths.flat() : []),
    [graph],
  );

  const nodeById = useMemo(
    () => new Map((graph?.nodes ?? []).map((node) => [node.id, node])),
    [graph],
  );

  const edgeById = useMemo(
    () => new Map((graph?.edges ?? []).map((edge) => [edge.id, edge])),
    [graph],
  );

  /* ---------------- graph lifecycle ---------------- */

  const runGraphAction = useCallback(async (
    action: (instance: Graph) => Promise<void>,
    isActive: () => boolean = () => true,
  ) => {
    const ready = graphReadyRef.current;
    if (!ready) return;
    try {
      await ready;
      const instance = graphRef.current;
      if (!instance || graphReadyRef.current !== ready || !isActive()) return;
      await action(instance);
    } catch (caught) {
      if (graphReadyRef.current === ready && isActive()) {
        setRenderError(caught instanceof Error ? caught.message : String(caught));
      }
    }
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !graph) {
      return;
    }

    let instance: Graph | null = null;
    let disposed = false;
    // G6 rendering is asynchronous. All canvas operations share this readiness
    // promise so neither highlighting nor toolbar actions race initialization.
    const ready = Promise.resolve().then(async () => {
      if (disposed) return;
      instance = new Graph({
        container,
        autoResize: true,
        data: toGraphData(graph),
        layout: {
          type: 'dagre',
          rankdir: 'LR',
          nodesep: 26,
          ranksep: 96,
          align: 'UL',
        },
        node: { type: 'circle' },
        edge: { type: 'line' },
        behaviors: ['drag-canvas', 'zoom-canvas', 'drag-element', 'click-select'],
        plugins: [{ type: 'grid-line', size: 22 }],
        animation: false,
      });

      instance.on('node:click', (event: unknown) => {
        const target = (event as IPointerEvent).target;
        const id = typeof target === 'string' ? target : (target as { id?: string } | undefined)?.id;
        if (id && nodeById.has(id)) {
          setSelected(nodeById.get(id) ?? null);
        }
      });
      instance.on('edge:click', (event: unknown) => {
        const target = (event as IPointerEvent).target;
        const id = typeof target === 'string' ? target : (target as { id?: string } | undefined)?.id;
        const edge = id ? edgeById.get(id) : undefined;
        if (edge) {
          const source = nodeById.get(edge.source);
          if (source) {
            setSelected(source);
          }
        }
      });

      graphRef.current = instance;
      await instance.render();
      if (!disposed) setRenderError(null);
    });
    graphReadyRef.current = ready;
    void ready.catch((caught: unknown) => {
      if (!disposed) setRenderError(caught instanceof Error ? caught.message : String(caught));
    });

    return () => {
      disposed = true;
      try {
        instance?.destroy();
      } catch {
        /* the canvas may already be torn down by React strict mode */
      }
      graphRef.current = null;
      graphReadyRef.current = null;
    };
  }, [edgeById, graph, nodeById]);

  /* ---------------- egress highlighting ---------------- */

  useEffect(() => {
    if (!graph) return;
    let active = true;
    void runGraphAction(async (instance) => {
      for (const edge of graph.edges) {
        const isEgress = egressEdgeIds.has(edge.id);
        instance.updateEdgeData([
          {
            id: edge.id,
            style: {
              stroke: highlightEgress && isEgress ? '#e5484d' : isEgress ? '#ff8b90' : 'rgba(167,179,199,0.32)',
              lineWidth: highlightEgress && isEgress ? 3.4 : isEgress ? 2 : 1,
              opacity: highlightEgress && !isEgress ? 0.18 : 1,
            },
          },
        ]);
      }
      for (const node of graph.nodes) {
        const dim = highlightEgress && !egressNodeIds.has(node.id);
        instance.updateNodeData([
          {
            id: node.id,
            style: { opacity: dim ? 0.2 : 1 },
          },
        ]);
      }
      await instance.draw();
    }, () => active);
    return () => { active = false; };
  }, [egressEdgeIds, egressNodeIds, graph, highlightEgress, runGraphAction]);

  const fitView = useCallback(() => {
    void runGraphAction((instance) => instance.fitView());
  }, [runGraphAction]);

  const relayout = useCallback(() => {
    void runGraphAction((instance) => instance.layout());
  }, [runGraphAction]);

  const inbound = useMemo(
    () => (graph?.edges ?? []).filter((edge) => edge.target === selected?.id),
    [graph, selected],
  );
  const outbound = useMemo(
    () => (graph?.edges ?? []).filter((edge) => edge.source === selected?.id),
    [graph, selected],
  );

  const edgeColumns: ColumnsType<TopologyEdge> = [
    {
      title: t('topology.side.type'),
      dataIndex: 'kind',
      width: 120,
      render: (kind: string) => <Tag>{kind}</Tag>,
    },
    {
      title: t('common.name'),
      key: 'peer',
      render: (_value, record) => {
        const peerId = record.source === selected?.id ? record.target : record.source;
        const peer = nodeById.get(peerId);
        return peer ? (
          <Space size={6}>
            <span className="agf-severity-dot" style={{ background: TOPOLOGY_NODE_HEX[peer.type] }} />
            <span>{peer.label}</span>
          </Space>
        ) : (
          peerId
        );
      },
    },
    {
      title: t('topology.side.callsColumn'),
      dataIndex: 'calls24h',
      width: 140,
      align: 'right',
      render: (value: number) => value.toLocaleString(),
    },
    {
      title: t('topology.legend.egress'),
      dataIndex: 'egress',
      width: 110,
      render: (value: boolean) =>
        value ? <Tag color="red">{t('topology.legend.egress')}</Tag> : <span className="agf-tertiary">—</span>,
    },
  ];

  const stats = graph
    ? t('topology.stats', {
        nodes: graph.nodes.length,
        edges: graph.edges.length,
        shadow: graph.nodes.filter((node) => node.shadow).length,
      })
    : '';

  return (
    <>
      <PageHeader
        title={t('topology.title')}
        subtitle={t('topology.subtitle')}
        actions={
          <Space wrap>
            <Button
              type={highlightEgress ? 'primary' : 'default'}
              icon={<HighlightOutlined />}
              onClick={() => setHighlightEgress((prev) => !prev)}
            >
              {highlightEgress ? t('topology.action.clearHighlight') : t('topology.action.highlightEgress')}
            </Button>
            <Button icon={<AimOutlined />} onClick={fitView}>
              {t('topology.action.fit')}
            </Button>
            <Button icon={<ReloadOutlined />} onClick={relayout}>
              {t('topology.action.reload')}
            </Button>
            <Button onClick={() => void refetch()}>{t('common.refresh')}</Button>
          </Space>
        }
      />

      <DataState loading={isLoading} error={error} skeletonRows={8}>
        {graph ? (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <div className="agf-legend">
              {NODE_TYPES.map((type) => (
                <span className="agf-legend__item" key={type}>
                  <span
                    className="agf-legend__swatch"
                    style={{ background: TOPOLOGY_NODE_HEX[type], borderRadius: 999 }}
                  />
                  {t(`topology.legend.${type}`)}
                </span>
              ))}
              <span className="agf-legend__item">
                <span
                  className="agf-legend__swatch"
                  style={{ background: 'transparent', border: '2px solid #ff8b90', borderRadius: 999 }}
                />
                {t('topology.legend.shadow')}
              </span>
              <span className="agf-legend__item">
                <span className="agf-legend__swatch" style={{ background: '#e5484d', height: 3, borderRadius: 2 }} />
                {t('topology.legend.egress')}
              </span>
              <span className="agf-header__spacer" />
              <span className="agf-tertiary agf-mono">{stats}</span>
            </div>

            {renderError ? (
              <Alert type="warning" showIcon message={t('topology.renderError')} description={renderError} />
            ) : null}

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 340px', gap: 14 }}>
              <div className="agf-topology" ref={containerRef} data-testid="topology-canvas" />
              <div className="agf-topology-panel">
                <Typography.Title level={5} style={{ marginTop: 0 }}>
                  {t('topology.side.title')}
                </Typography.Title>
                {selected ? (
                  <Space direction="vertical" size={10} style={{ width: '100%' }}>
                    <Descriptions size="small" column={1} bordered>
                      <Descriptions.Item label={t('common.name')}>{selected.label}</Descriptions.Item>
                      <Descriptions.Item label={t('topology.side.type')}>
                        <Chip color={TOPOLOGY_NODE_HEX[selected.type]}>{t(`topology.legend.${selected.type}`)}</Chip>
                      </Descriptions.Item>
                      <Descriptions.Item label={t('topology.side.risk')}>{selected.riskScore ?? t('common.unknown')}</Descriptions.Item>
                      {selected.classification ? (
                        <Descriptions.Item label={t('topology.side.classification')}>
                          {t(`assets.classification.${selected.classification}`)}
                        </Descriptions.Item>
                      ) : null}
                      <Descriptions.Item label={t('topology.side.shadow')}>
                        {selected.shadow ? (
                          <Tag color="red">{t('topology.legend.shadow')}</Tag>
                        ) : (
                          <Tag color="green">{t('mcps.shadow.no')}</Tag>
                        )}
                      </Descriptions.Item>
                    </Descriptions>
                    <Typography.Paragraph className="agf-muted" style={{ fontSize: 13, marginBottom: 0 }}>
                      {selected.detail}
                    </Typography.Paragraph>

                    <div>
                      <div className="agf-drawer-section__title">
                        {t('topology.side.inbound')} ({inbound.length})
                      </div>
                      <Table<TopologyEdge>
                        rowKey="id"
                        size="small"
                        pagination={false}
                        columns={edgeColumns}
                        dataSource={inbound}
                        scroll={{ x: 280 }}
                      />
                    </div>
                    <div>
                      <div className="agf-drawer-section__title">
                        {t('topology.side.outbound')} ({outbound.length})
                      </div>
                      <Table<TopologyEdge>
                        rowKey="id"
                        size="small"
                        pagination={false}
                        columns={edgeColumns}
                        dataSource={outbound}
                        scroll={{ x: 280 }}
                      />
                    </div>
                  </Space>
                ) : (
                  <Typography.Paragraph className="agf-tertiary">{t('topology.side.empty')}</Typography.Paragraph>
                )}
              </div>
            </div>

            <Panel
              title={t('topology.egress.title')}
              extra={
                <Tooltip title={t('topology.action.highlightEgress')}>
                  <span className="agf-muted">{t('topology.egress.count', { count: graph.egressPaths.length })}</span>
                </Tooltip>
              }
            >
              {graph.egressPaths.length === 0 ? (
                <Typography.Text className="agf-tertiary">{t('topology.egress.none')}</Typography.Text>
              ) : (
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  {graph.egressPaths.map((path, index) => (
                    <div
                      key={path.join('>')}
                      style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}
                    >
                      <Tag color="red">{t('topology.egress.path', { index: index + 1 })}</Tag>
                      {path.map((nodeId, position) => {
                        const node = nodeById.get(nodeId);
                        return (
                          <span key={`${nodeId}-${position}`} style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                            {position > 0 ? <span className="agf-tertiary">→</span> : null}
                            <Chip color={node ? TOPOLOGY_NODE_HEX[node.type] : '#6f7683'}>
                              {node?.label ?? nodeId}
                            </Chip>
                          </span>
                        );
                      })}
                    </div>
                  ))}
                </Space>
              )}
            </Panel>
          </Space>
        ) : null}
      </DataState>
    </>
  );
}

/** Local re-implementation of the demo helper to keep the page bundle free of demo imports. */
function demoTobEgressEdgeIds(graph: TopologyGraph): string[] {
  const pairs = new Set<string>();
  for (const path of graph.egressPaths) {
    for (let index = 0; index < path.length - 1; index += 1) {
      pairs.add(`${path[index]}->${path[index + 1]}`);
    }
  }
  return graph.edges.filter((edge) => pairs.has(`${edge.source}->${edge.target}`)).map((edge) => edge.id);
}

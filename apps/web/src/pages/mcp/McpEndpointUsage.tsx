import { Alert, Button, Space, Table, Typography } from 'antd';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';

interface ToolUsage {
  name: string;
  attempts: number;
  succeeded: number;
  failed: number;
  unknown: number;
  inflight: number;
  latencyMsTotal: number;
}
interface UsageResponse { endpointId?: string; source?: string; items: ToolUsage[] }

type Props = { id: string; zh: boolean; runtimeCheck?: false; redteamProfile?: boolean }
  | { runtimeCheck: true; zh: boolean; id?: never; redteamProfile?: never };

export function McpEndpointUsage({ id, zh, runtimeCheck = false, redteamProfile = false }: Props) {
  const encodedId = encodeURIComponent(id ?? '');
  const path = runtimeCheck ? '/api/v1/runtime/mcp/usage'
    : redteamProfile ? `/api/v1/redteam/mcp-targets/${encodedId}/usage`
      : `/api/v1/mcp/endpoints/${encodedId}/usage`;
  const usage = useApiQuery('mcp-tool-usage', () => callApi<UsageResponse>(
    path, () => { throw new Error('MCP usage API unavailable'); }, { noFallback: true },
  ), { key: [path] });
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Space><Typography.Title level={5} style={{ margin: 0 }}>{runtimeCheck
      ? (zh ? 'Agent / stdio MCP 代理工具用量' : 'Agent / stdio MCP proxy tool usage')
      : redteamProfile ? (zh ? '红队目标工具用量' : 'Red-team target tool usage')
        : (zh ? '此端点的工具用量' : 'Tool usage for this endpoint')}</Typography.Title>
      <Button size="small" loading={usage.isFetching} onClick={() => void usage.refetch()}>{zh ? '刷新用量' : 'Refresh usage'}</Button></Space>
    <Typography.Text className="agf-muted">{runtimeCheck
      ? (zh ? '远程 MCP 检查入口（含本地 stdio 代理）经策略允许的工具调用累计数。结果由调用方回报；退出或结果未确认计为未知。允许转发不证明服务已执行，也不是账单。'
        : 'Cumulative tool calls admitted by the remote MCP check, including local stdio proxies. Callers report results; exit or an unconfirmed result is unknown. Allowed forwarding does not prove execution or billing.')
      : redteamProfile ? (zh ? '仅统计该红队目标的直接只读工具请求；列举工具不计入。失败和未知分别显示，收到结果不等于业务动作成功或费用。'
        : 'Direct read-only tool calls for this red-team target only; tool discovery is excluded. Failed and unknown outcomes are separate. A checked result does not prove a business action or bill.')
      : (zh ? '从平台开始计量后的累计转发尝试。未知表示连接中断或结果未确认；成功只代表收到并检查了上游结果，不代表业务动作成功或费用。'
        : 'Cumulative forwarded attempts since metering began. Unknown means the result was not confirmed. Success means an upstream result passed inspection, not that a business action succeeded or a bill was issued.')}</Typography.Text>
    {usage.error && <Alert type="error" showIcon message={String(usage.error)} />}
    <Table<ToolUsage> rowKey="name" size="small" loading={usage.isLoading} dataSource={usage.data?.data.items ?? []}
      scroll={{ x: 760 }} pagination={{ pageSize: 5 }} locale={{ emptyText: zh ? '暂无已转发工具调用' : 'No forwarded tool calls yet' }}
      columns={[
        { title: zh ? '工具' : 'Tool', dataIndex: 'name', width: 190, ellipsis: true },
        { title: zh ? '尝试' : 'Attempts', dataIndex: 'attempts', width: 90, align: 'right' },
        { title: zh ? '收到结果' : 'Result received', dataIndex: 'succeeded', width: 110, align: 'right' },
        { title: zh ? '失败' : 'Failed', dataIndex: 'failed', width: 90, align: 'right' },
        { title: zh ? '未知' : 'Unknown', dataIndex: 'unknown', width: 90, align: 'right' },
        { title: zh ? '进行中' : 'In flight', dataIndex: 'inflight', width: 90, align: 'right' },
        { title: zh ? '平均耗时' : 'Avg latency', key: 'latency', width: 100, align: 'right',
          render: (_, row) => row.succeeded + row.failed > 0
            ? `${(row.latencyMsTotal / (row.succeeded + row.failed)).toFixed(0)} ms` : '—' },
      ]} />
  </Space>;
}

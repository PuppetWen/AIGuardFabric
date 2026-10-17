import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Space, Table, Tag, Typography } from 'antd';
import type { Paged, Policy } from '@/types/domain';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { publicationApi } from './api';
import { usePublicationText } from './text';
import type { PolicyRevision } from './types';

export default function PublicationPolicies({ selected, onSelected, maximum, disabled }: {
  selected: PolicyRevision[]; onSelected: (rows: PolicyRevision[]) => void; maximum: number; disabled: boolean;
}) {
  const text = usePublicationText(), scope = useOperationScope(), sequence = useRef(0);
  const [page, setPage] = useState(1), [data, setData] = useState<Paged<Policy> | null>(null);
  const [loading, setLoading] = useState(true), [error, setError] = useState(''), [reload, setReload] = useState(0);
  useEffect(() => {
    const id = ++sequence.current, controller = new AbortController();
    void publicationApi.policies(page, controller.signal).then(response => {
      if (!controller.signal.aborted && scope.current() && id === sequence.current) { setData(response.data); setError(''); }
    }).catch(cause => { if (!controller.signal.aborted && scope.current() && id === sequence.current)
      setError(cause instanceof Error ? cause.message : '政策读取失败 / Policy read failed'); })
      .finally(() => { if (!controller.signal.aborted && scope.current() && id === sequence.current) setLoading(false); });
    return () => controller.abort();
  }, [page, reload, scope]);
  const eligible = (row: Policy) => row.enabled && row.signature.status === 'signed'
    && Number.isInteger(row.version) && row.version! > 0 && row.version! <= 0xffffffff;
  const choose = (row: Policy, checked: boolean) => {
    if (disabled || loading || !scope.current() || (checked && !eligible(row))) return;
    const kept = selected.filter(item => item.policyId !== row.id);
    if (checked && kept.length >= maximum) { setError(text('已达到政策数量上限；不会截断选择。', 'The policy limit is reached; selections will not be truncated.')); return; }
    onSelected((checked ? [...kept, { policyId: row.id, version: row.version! }] : kept).sort((a, b) => a.policyId.localeCompare(b.policyId)));
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" message={text('只选择真实已启用且带签名的政策版本；服务端仍会检查签名、编译与全部依赖。', 'Select actual enabled, signed policy revisions; the server still verifies signatures, compilation and every dependency.')}
      description={text('刷新列表不会自动替换已选版本。若政策变版，明确取消并重新选择该政策；409 不自动重发。', 'Refreshing the list does not replace selected revisions. Deselect and reselect a changed policy explicitly; HTTP 409 never triggers an automatic retry.')} />
    <Typography.Text>{text('已选版本（可明确移除尚未加载的选择）', 'Selected revisions (remove unloaded selections explicitly)')}</Typography.Text>
    <Space wrap>{selected.map(row => <Space key={row.policyId}><Tag>{row.policyId} @ v{row.version}</Tag>
      <Button size="small" type="link" disabled={disabled} aria-label={`${text('移除所选政策', 'Remove selected policy')} ${row.policyId}`}
        onClick={() => { if (!disabled && scope.current()) onSelected(selected.filter(item => item.policyId !== row.policyId)); }}>{text('移除', 'Remove')}</Button>
    </Space>)}</Space>
    {error && <Alert type="error" message={error} />}
    <Button loading={loading} onClick={() => { setLoading(true); setReload(value => value + 1); }}>{text('刷新真实政策列表', 'Refresh actual policy list')}</Button>
    <Table<Policy> size="small" rowKey="id" dataSource={data?.items ?? []} loading={loading} pagination={{ current: page, pageSize: 50, total: data?.total ?? 0,
      showSizeChanger: false, onChange: next => { setLoading(true); setPage(next); } }}
      rowSelection={{ selectedRowKeys: selected.map(row => row.policyId), preserveSelectedRowKeys: true, hideSelectAll: true,
        getCheckboxProps: row => ({ disabled: disabled || loading || (!selected.some(item => item.policyId === row.id) && (!eligible(row) || selected.length >= maximum)) }),
        onSelect: choose }} columns={[
        { title: text('政策 / ID', 'Policy / ID'), dataIndex: 'name', render: (name: string, row) => <><a href="/policies" target="_blank" rel="noreferrer">{name}</a><br />{row.id}</> },
        { title: text('真实版本', 'Actual revision'), dataIndex: 'version', render: (version: number | undefined, row) => {
          const chosen = selected.find(item => item.policyId === row.id);
          return <>{version ?? text('未知，不可选', 'Unknown, unavailable')}{chosen && chosen.version !== version && <Tag color="orange">{text('仍选择', 'Still selected')} v{chosen.version}</Tag>}</>;
        } },
        { title: text('启用 / 签名', 'Enabled / signature'), render: (_, row) => `${row.enabled} / ${row.signature.status}` },
      ]} />
  </Space>;
}

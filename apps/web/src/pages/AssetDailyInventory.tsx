import { useState } from 'react';
import { Alert, Button, Drawer, Pagination, Space, Table, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { callApi, useApiQuery } from '@/api/client';
import { DataState } from '@/components/DataState';

import { inventoryHistory, type InventoryRun } from '@/api/assetInventory';

type Change = { id: string; assetId: string; assetName?: string; changeKind: string; field?: string; oldValue?: unknown; newValue?: unknown; risky: boolean; riskNote?: string };

export function AssetDailyInventory({ canWrite, automaticEnabled }: { canWrite: boolean; automaticEnabled: boolean }) {
  const { i18n } = useTranslation();
  const text = (zh: string, en: string) => i18n.language.startsWith('zh') ? zh : en;
  const fieldLabels: Record<string, string> = { endpoint: text('端点', 'Endpoint'), protocol: text('协议', 'Protocol'),
    version: text('版本', 'Version'), vendor: text('厂商', 'Vendor'), data_class: text('数据分级', 'Classification'),
    lifecycle: text('生命周期', 'Lifecycle'), exposure_score: text('暴露分', 'Exposure score'),
    dependencies: text('依赖', 'Dependencies'), content_sha256: text('文件内容哈希', 'File content hash'),
    skill_package_sha256: text('Skill 目录内容哈希', 'Skill directory content hash'),
    skill_package_observation: text('Skill 目录观察状态', 'Skill directory observation'),
    added: text('新增', 'Added'), removed: text('消失', 'Removed'), modified: text('修改', 'Modified') };
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<InventoryRun>();
  const [changePage, setChangePage] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const history = useApiQuery('asset-daily-history', () => inventoryHistory(page), { enabled: open, key: [page] });
  const changes = useApiQuery('asset-daily-changes', () => callApi(`/api/v1/assets/inventory/${selected?.id}/changes`,
    () => ({ items: [] as Change[], total: 0 }), { noFallback: true, query: { page: changePage } }),
    { enabled: open && !!selected, key: [selected?.id, changePage] });
  const run = async () => {
    setBusy(true); setError('');
    try {
      const result = await callApi<InventoryRun>('/api/v1/assets/inventory', () => { throw new Error('No fallback'); },
        { method: 'POST', noFallback: true, timeoutMs: 130000 });
      setSelected(result.data); setChangePage(1); setPage(1); await history.refetch();
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const stale = page === 1 && history.data?.data.items[0]?.date !== new Date().toISOString().slice(0, 10);
  return <>
    <Button onClick={() => setOpen(true)}>{text('每日资产检测', 'Daily inventory')}</Button>
    <Drawer open={open} onClose={() => setOpen(false)} width={1000} title={text('每日资产检测', 'Daily inventory')}>
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Alert type={automaticEnabled ? 'info' : 'warning'} showIcon message={automaticEnabled
          ? text('按 UTC 每日检测；服务恢复后补做当日检测。首次仅建立基线，同一天重复运行返回原记录。',
            'Daily in UTC, with catch-up after restart. The first run establishes a baseline. Repeating today returns its existing record.')
          : text('当前为离线模式。每日检测需要 PostgreSQL。', 'Offline mode. Daily inventory requires PostgreSQL.')} />
        <Typography.Paragraph>{text('检测对比上一次成功快照，包含新增未评审资产、端点替换和已上报的内容哈希变化。哈希变化代表需核对，不代表已经确认篡改；未上报内容哈希时无法判断文件内容。',
          'Compare against the last successful snapshot: new unreviewed assets, endpoint changes and reported content hashes. A changed hash requires review; it does not prove tampering. File content cannot be checked without a reported hash.')}</Typography.Paragraph>
        <Space><Button onClick={() => void history.refetch()}>{text('刷新记录', 'Refresh records')}</Button>
          {canWrite && automaticEnabled && <Button loading={busy} onClick={() => void run()}>{text('获取当日检测', 'Complete today’s inventory')}</Button>}</Space>
        {error && <Alert type="error" message={error} showIcon />}
        {automaticEnabled && stale && !history.isLoading && !history.error && <Alert type="warning" showIcon
          message={text('尚无当日检测记录，可获取当日检测；若持续失败，请检查服务日志中的 Daily asset inventory。',
            'No completed run for today. Complete today’s inventory; if it keeps failing, check server logs for Daily asset inventory.')} />}
        <DataState loading={history.isLoading} error={history.error} onRetry={() => void history.refetch()}>
          <Table<InventoryRun> rowKey="id" dataSource={history.data?.data.items ?? []} pagination={false} size="small"
            columns={[
              { title: text('日期 (UTC)', 'Date (UTC)'), dataIndex: 'date', render: (date: string, row) =>
                <Button type="link" onClick={() => { setSelected(row); setChangePage(1); }}>{date}</Button> },
              { title: text('基线', 'Baseline'), render: (_, row) => row.initialBaseline ? text('首次建立', 'Initial baseline') : row.baselineDate },
              { title: text('资产数', 'Assets'), dataIndex: 'snapshotCount' },
              { title: text('变更条目', 'Changes'), render: (_, row) => row.summary.total },
              { title: text('需核对条目', 'Needs review'), render: (_, row) => row.summary.risky },
            ]} />
          <Pagination current={page} pageSize={20} total={history.data?.data.total ?? 0} onChange={setPage} showSizeChanger={false} />
        </DataState>
        {selected && <>
          <Typography.Title level={5}>{selected.date} · {text('变更明细', 'Change details')}</Typography.Title>
          {selected.initialBaseline && <Typography.Text>{text('首次基线不生成漂移告警。', 'The initial baseline does not flag drift.')}</Typography.Text>}
          <DataState loading={changes.isLoading} error={changes.error} onRetry={() => void changes.refetch()}>
            <Space direction="vertical" style={{ width: '100%' }}>{changes.data?.data.items.map(change => <div key={change.id}>
              <Link to={`/assets/${change.assetId}`} onClick={() => setOpen(false)}>{change.assetName ?? change.assetId}</Link>{' '}
              <Tag color={change.risky ? 'orange' : undefined}>{fieldLabels[change.field ?? change.changeKind] ?? change.field ?? change.changeKind}</Tag>
              {change.risky && <Typography.Paragraph>{text(change.riskNote ?? '请核对变更是否经过授权。', 'Review whether this change was authorized.')}</Typography.Paragraph>}
              <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 180, overflowY: 'auto' }}>
                {JSON.stringify(change.oldValue ?? null, null, 2)}{' → '}{JSON.stringify(change.newValue ?? null, null, 2)}</pre>
            </div>)}</Space>
            <Pagination current={changePage} pageSize={50} total={changes.data?.data.total ?? 0} onChange={setChangePage} showSizeChanger={false} />
          </DataState>
        </>}
      </Space>
    </Drawer>
  </>;
}

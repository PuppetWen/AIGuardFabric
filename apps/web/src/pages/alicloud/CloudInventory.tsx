import { newRequestId } from '@/utils/requestId';
import { useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Space } from 'antd';
import { cloudApi, type CloudConfig } from '@/api/cloud';

export function CloudInventory({ snapshot }: { snapshot: CloudConfig }) {
  const { i18n } = useTranslation();
  const cache = useQueryClient();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState('');
  const active = useRef(false);
  const mocked = snapshot.mock || snapshot.environmentMock;
  const run = async () => {
    if (active.current || !snapshot.enabled || (!mocked && !confirmed)) return;
    active.current = true;
    setBusy(true); setError(''); setResult('');
    try {
      const { data } = await cloudApi.syncTeams({ request_id: newRequestId(), configuration_version: snapshot.version, confirm_live: confirmed });
      setResult(`${data.mocked ? 'Mock' : 'Live'} · ${text('团队', 'Teams')} ${data.teams} · Worker ${data.workers} · ${text('资产', 'Assets')} ${data.assets} · ${text('任务', 'Tasks')} ${data.tasks}`);
      await cache.invalidateQueries();
    } catch (cause) { setError(String(cause)); }
    finally { active.current = false; setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert showIcon type="info" message={text('同步团队与资产台账', 'Synchronize teams and asset inventory')}
      description={text('读取完整团队、Worker 详情和任务分页，并更新当前租户台账。保留人工归属、分级及生命周期；不会删除未返回的旧资产。模拟资产单独标记。每次最多 200 个团队及 Worker、每项最多 20 页。', 'Reads complete team, Worker and task pages into this tenant. Keeps manual ownership, classification and lifecycle, and retains missing assets. Mock assets are labeled separately. Maximum 200 teams and Workers, 20 pages per list.')} />
    {!mocked && <Checkbox checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)}>{text('确认云端只读查询与本地台账更新', 'Confirm cloud reads and local inventory updates')}</Checkbox>}
    <Button loading={busy} disabled={busy || !snapshot.enabled || (!mocked && !confirmed)} onClick={() => void run()}>{text('完整盘点并同步台账', 'Read complete inventory and synchronize')}</Button>
    {error && <Alert type="error" message={error} description={text('请查看操作回执并修正失败原因，再手动重新盘点。新的请求编号会重新读取完整列表；不会自动重发。', 'Inspect operation receipts and correct the failure, then start inventory again. A new request ID reads the complete lists again; no automatic retry is sent.')} />}
    {result && <Alert type="success" message={result} />}
  </Space>;
}

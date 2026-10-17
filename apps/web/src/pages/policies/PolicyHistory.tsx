import { useState } from 'react';
import { Alert, Button, Drawer, Input, Popconfirm, Space, Table, Typography, message } from 'antd';
import { useApiQuery } from '@/api/client';
import { policiesApi, validPolicyVersion } from '@/api/policies';
import { isPolicyAction } from '@/api/policyActions';
import { DataState } from '@/components/DataState';
import { useAuthStore } from '@/stores/authStore';
import type { Policy } from '@/types/domain';
import { PolicyVersionComparison } from './PolicyVersionComparison';
import { usePolicyOperation } from './usePolicyOperation';
import { usePolicyText } from './usePolicyText';

interface Props { policy: Policy; canWrite: boolean; onClose: () => void; onChanged: () => void }
export function PolicyHistory(props: Props) {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <HistoryContent key={`${tenant?.id}:${tenant?.slug}:${generation}:${props.policy.id}`} {...props} />;
}
function HistoryContent({ policy, canWrite, onClose, onChanged }: Props) {
  const text = usePolicyText(), operation = usePolicyOperation(), { busy } = operation;
  const [base, setBase] = useState(policy), [latest, setLatest] = useState<Policy>();
  const history = useApiQuery(`policy-history-${policy.id}`, () => policiesApi.history(policy.id));
  const [sample, setSample] = useState(JSON.stringify({ intercept_point: 'mcp-proxy', tool_name: 'query', command: 'example-command', payload: {} }, null, 2));
  const [decision, setDecision] = useState('');
  return <Drawer title={`${policy.name} · ${text('版本与模拟', 'Versions and simulation')}`} open width={1000}
    closable={!busy} maskClosable={!busy} keyboard={!busy} onClose={() => { if (!busy) onClose(); }}>
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Alert showIcon type="warning" message={text('恢复会创建新的签名版本，保留历史的启用状态并在平台生效。不会将外部 MSE/API 网关或其他调用方热加载。',
        'Restore creates a new signed revision, retains the historical enabled setting and applies on the platform. It does not reload external MSE/API gateways or other consumers.')} />
      <Typography.Text>{text(`恢复基于当前版本 v${base.version ?? '未知'}`, `Restore uses current revision v${base.version ?? 'unknown'}`)}</Typography.Text>
      {operation.error && <Alert showIcon type="error" message={operation.error} description={operation.conflict ? text('当前版本已变更，未恢复。样本和所选历史仍保留；先读取最新版本比较并明确采纳。',
        'The current revision changed; nothing was restored. The sample and history remain. Compare and explicitly adopt the latest revision first.') : undefined} />}
      <Button disabled={busy} onClick={() => void operation.run(async isCurrent => {
        setLatest(undefined);
        const id = policy.id, result = await policiesApi.get(id);
        if (isCurrent() && result.data.id === id) setLatest(result.data);
      })}>{text('读取最新版本并比较', 'Load latest revision to compare')}</Button>
      {latest && <PolicyVersionComparison draft={base} latest={latest} busy={busy} canAdopt={canWrite} onAdopt={() => {
        if (!busy && operation.isCurrent() && latest.id === policy.id && validPolicyVersion(latest.version) && isPolicyAction(latest.action)) {
          setBase(latest); setLatest(undefined); setDecision(''); operation.clearError();
        }
      }} />}
      {(!isPolicyAction(base.action) || history.data?.data.versions.some(row => !isPolicyAction(row.action))) && <Alert type="warning" message={text(
        '当前或历史策略包含未知动作，相应恢复已阻止；请核对服务端与客户端版本。',
        'A current or historical policy has an unknown action; the affected restore is blocked. Verify server and client versions.',
      )} />}
      <DataState loading={history.isLoading} error={history.error}>
        <Table<Policy> rowKey={row => String(row.version)} size="small" pagination={{ pageSize: 5 }} dataSource={history.data?.data.versions ?? []} columns={[
          { title: text('版本', 'Revision'), dataIndex: 'version' }, { title: text('动作', 'Action'), dataIndex: 'action' },
          { title: text('启用', 'Enabled'), render: (_, row) => row.enabled ? text('是', 'Yes') : text('否', 'No') },
          { title: text('修改时间', 'Updated'), dataIndex: 'updatedAt' },
          { title: text('操作', 'Actions'), render: (_, row) => <Popconfirm title={text(`恢复历史版本 ${row.version}？`, `Restore historical revision ${row.version}?`)}
            description={text(`以核对过的当前版本 ${base.version ?? '未知'} 为条件，发布所选历史为新版本。`,
              `Publish selected history as a new revision only if the reviewed current revision is still ${base.version ?? 'unknown'}.`)}
            okText={text('确认发布恢复版本', 'Confirm restored publication')} onConfirm={() => operation.run(async isCurrent => {
              if (!canWrite || !validPolicyVersion(base.version) || !validPolicyVersion(row.version)
                || !isPolicyAction(base.action) || !isPolicyAction(row.action)) return;
              const id = policy.id, version = row.version, expectedVersion = base.version;
              const result = await policiesApi.restore(id, version, expectedVersion);
              if (!isCurrent()) return;
              if (result.data.id !== id || !validPolicyVersion(result.data.version)) throw new Error(text('服务端恢复版本无效。', 'The server returned an invalid restored revision.'));
              setBase(result.data); setLatest(undefined); setDecision('');
              message.success(text('已发布新的恢复版本', 'New restored revision published')); void history.refetch(); onChanged();
            })}>
            <Button size="small" disabled={busy || !canWrite || !validPolicyVersion(base.version) || !validPolicyVersion(row.version)
              || !isPolicyAction(base.action) || !isPolicyAction(row.action)}>{text('恢复为新版本', 'Restore as new revision')}</Button>
          </Popconfirm> },
        ]} expandable={{ expandedRowRender: row => <pre className="agf-code" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{row.code}</pre> }} />
      </DataState>
      <Typography.Title level={5}>{text('模拟当前服务端策略', 'Simulate current server policy')}</Typography.Title>
      <Typography.Text type="secondary">{text('模拟不保存样本或未发布草稿，也不确认外部云调用方的状态。', 'Simulation neither saves the sample or draft nor verifies external cloud consumers.')}</Typography.Text>
      <Input.TextArea aria-label={text('策略模拟样本', 'Policy simulation sample')} value={sample} disabled={busy} onChange={event => { setSample(event.target.value); setDecision(''); }} rows={8} />
      <Button loading={busy} aria-label={text('模拟当前策略', 'Simulate current policy')} onClick={() => void operation.run(async isCurrent => {
        const id = policy.id, snapshot = JSON.parse(sample) as unknown; setDecision('');
        const result = await policiesApi.simulate(id, snapshot); if (isCurrent()) setDecision(JSON.stringify(result.data, null, 2));
      })}>{text('模拟当前策略', 'Simulate current policy')}</Button>
      {decision && <pre className="agf-code" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{decision}</pre>}
    </Space>
  </Drawer>;
}

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Collapse, Popconfirm, Select, Space, Tag, Typography } from 'antd';
import { agentTeamsQuotasApi } from '@/api/agentTeamsQuotas';
import { useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { useAuthStore } from '@/stores/authStore';
import { newRequestId } from '@/utils/requestId';
import type { WorkerQuotaObserveRequest } from '@/types/agentTeamsQuotas';
import WorkerQuotaActions from './WorkerQuotaActions';
import WorkerQuotaGuide from './WorkerQuotaGuide';
import WorkerQuotaStatus from './WorkerQuotaStatus';
import { compatibleWorkerQuota, currentWorkerBinding, currentWorkerPreview, usableWorkerPreview } from './workerQuotaState';

export default function WorkerQuotasPanel() {
  const tenantId = useAuthStore(state => state.tenant?.id);
  const session = useAuthStore(state => state.sessionGeneration);
  return <QuotaContent key={`${tenantId ?? 'none'}:${session}`} />;
}

function QuotaContent() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess();
  const canRead = access.has('alicloud:read') && access.has('quotas:read');
  const query = useApiQuery('agentteams-worker-quotas', agentTeamsQuotasApi.list, { enabled: canRead });
  const [selected, setSelected] = useState<string>();
  const [selectedQuota, setSelectedQuota] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ error: boolean; message: string }>();
  const [blockedPreviews, setBlockedPreviews] = useState<string[]>([]);
  const [now, setNow] = useState(Date.now);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    const timer = setInterval(() => setNow(Date.now()), 10_000);
    return () => { alive.current = false; clearInterval(timer); };
  }, []);
  const data = query.data?.data;
  const workerChoices = [
    ...(data?.workers.map(worker => ({ value: worker.assetId, label: worker.name })) ?? []),
    ...(data?.items.filter(item => !data.workers.some(worker => worker.assetId === item.assetId))
      .map(item => ({ value: item.assetId, label: `${item.workerName} · ${text('历史绑定', 'Historical binding')}` })) ?? []),
  ];
  const workerId = selected ?? workerChoices[0]?.value;
  const binding = data?.items.find(item => item.assetId === workerId);
  const options = data?.quotas.filter(rule => workerId && compatibleWorkerQuota(rule, workerId)) ?? [];
  const selectedRuleId = selectedQuota ?? options.find(rule => rule.id === binding?.quotaId)?.id ?? options[0]?.id;
  const selectedRule = options.find(rule => rule.id === selectedRuleId);
  const boundRule = data?.quotas.find(rule => rule.id === binding?.quotaId);
  const ready = !!data && !query.error && !query.isFetching;
  const canWrite = ready && data.canWrite && access.has('alicloud:write') && access.has('quotas:write');
  const current = !!binding && !!data && currentWorkerBinding(binding, data);
  const inventoried = data?.inventoryAvailable && data.workers.some(worker => worker.assetId === workerId);
  const canObserve = ready && current && access.has('alicloud:write') && access.has('quotas:read');
  const previewUsable = !!binding && !!data && usableWorkerPreview(binding, data, now)
    && !blockedPreviews.includes(binding.observation?.id ?? '');
  const canSync = canWrite && previewUsable;
  const blockOldPreview = () => {
    const id = binding?.observation?.id;
    if (id) setBlockedPreviews(values => [...values, id]);
  };
  const run = async (perform: () => Promise<unknown>, success: string, cloudWrite = false, refreshOnError = cloudWrite) => {
    if (busy) return;
    const starting = useAuthStore.getState();
    const isCurrent = () => alive.current && useAuthStore.getState().tenant?.id === starting.tenant?.id
      && useAuthStore.getState().sessionGeneration === starting.sessionGeneration;
    setBusy(true); setResult(undefined);
    try {
      await perform();
      if (!isCurrent()) return;
      setResult({ error: false, message: success });
      await query.refetch();
    } catch (cause) {
      if (!isCurrent()) return;
      const detail = cause instanceof Error ? cause.message : String(cause);
      setResult({ error: true, message: cloudWrite
        ? `${detail} ${text('请刷新查看操作回执，再重新读取云端；不要直接重发。', 'Refresh the operation receipt, then read cloud state again. Do not resend directly.')}` : detail });
      if (refreshOnError) await query.refetch();
    } finally { if (isCurrent()) setBusy(false); }
  };
  const bind = async (enabled: boolean) => {
    if (!canWrite || !workerId || binding?.busy) return;
    if (enabled && (!selectedRule || !inventoried)) return;
    if (!enabled && !binding) return;
    blockOldPreview();
    await run(() => agentTeamsQuotasApi.bind(workerId, { expected_version: binding?.version ?? 0,
      quota_id: enabled ? selectedRule!.id : binding!.quotaId,
      quota_version: enabled ? selectedRule!.version : boundRule?.version ?? binding!.quotaVersion ?? 0, enabled }), enabled
      ? text('绑定已保存；请读取云端并检查差异。', 'Binding saved. Read cloud state and review the difference.')
      : text('同步绑定已停用；云端限制保持当前配置。', 'Synchronization binding disabled. Cloud limits remain as configured.'));
  };
  const request = (): WorkerQuotaObserveRequest => ({ request_id: newRequestId(),
    expected_binding_version: binding!.version, expected_quota_version: boundRule!.version,
    configuration_version: data!.cloudVersion, confirm_live: !data!.mocked });
  const observe = async () => {
    if (!canObserve || !binding?.canObserve || binding.busy || !boundRule) return;
    blockOldPreview();
    await run(() => agentTeamsQuotasApi.observe(binding.assetId, request()),
      text('云端读取已完成；请检查观察值和平台目标。', 'Cloud read completed. Review the observation and platform target.'), false, true);
  };
  const sync = async () => {
    if (!canSync || !binding?.observation || !boundRule || !data
      || !currentWorkerPreview(binding, data)) return;
    const previewId = binding.observation.id;
    blockOldPreview();
    await run(async () => {
      const response = await agentTeamsQuotasApi.sync(binding.assetId, { ...request(), preview_id: previewId });
      if (response.data.operation.status !== 'verified') throw new Error(response.data.operation.error
        ?? text('操作尚未验证，请查看操作回执。', 'The operation is not verified. Inspect the operation receipt.'));
      return response;
    },
      text('操作回执已收到；请查看回读状态确认结果。', 'Operation receipt received. Inspect readback status for the result.'), true);
  };
  return <DataState loading={access.isLoading} error={access.error}>
    {!canRead ? <Alert type="info" showIcon message={text('查看 Worker 配额需要 alicloud:read 和 quotas:read 权限。', 'Viewing Worker quotas requires alicloud:read and quotas:read.')} />
      : <Panel title={text('Worker Token 配额绑定与同步', 'Worker token quota binding and synchronization')}>
        <Space direction="vertical" size={14} style={{ width: '100%' }}>
          <Space wrap><Button aria-label={text('刷新配额', 'Refresh quotas')} disabled={busy} loading={query.isFetching} onClick={() => void query.refetch()}>{text('刷新配额', 'Refresh quotas')}</Button>
            {data?.mocked && <Tag color="blue">Mock</Tag>}
            <Select aria-label={text('盘点 Worker', 'Inventoried Worker')} value={workerId} disabled={busy} style={{ minWidth: 260 }}
              placeholder={text('选择盘点 Worker', 'Select an inventoried Worker')} onChange={id => { setSelected(id); setSelectedQuota(undefined); setResult(undefined); }}
              options={workerChoices} />
          </Space>
          {result && <Alert showIcon type={result.error ? 'error' : 'success'} message={result.message} />}
          <DataState loading={query.isLoading} error={query.error} onRetry={() => void query.refetch()}>
            {data && !data.inventoryAvailable && <Alert type="info" showIcon message={text('请先完成当前实例完整盘点，再绑定 Worker 配额。', 'Complete inventory for the current instance before binding Worker quotas.')} />}
            {data?.inventoryAvailable && data.workers.length === 0 && <Alert type="info" showIcon message={text('完整盘点中没有可绑定的 Worker。', 'The complete inventory contains no bindable Worker.')} />}
            {workerId && <Typography.Text copyable>{workerId}</Typography.Text>}
            {canWrite && <Space wrap style={{ marginBlock: 12 }}>
              <Select aria-label={text('Worker 专属配额规则', 'Worker quota rule')} value={selectedRuleId} style={{ minWidth: 320 }} disabled={busy}
                placeholder={text('选择匹配规则', 'Select a compatible rule')} onChange={setSelectedQuota}
                options={options.map(rule => ({ value: rule.id, label: `${rule.name} · ${rule.limit} tokens/day · v${rule.version}` }))} />
              <Button type="primary" disabled={busy || !selectedRule || !inventoried || binding?.busy} onClick={() => void bind(true)}>{text('保存绑定', 'Save binding')}</Button>
              {binding?.enabled && <Popconfirm title={text('停用平台同步绑定？', 'Disable platform synchronization binding?')}
                description={text('此操作不撤销云端现有限制。', 'This does not remove existing cloud limits.')}
                onConfirm={() => bind(false)}><Button danger disabled={busy || binding.busy}>{text('停用绑定', 'Disable binding')}</Button></Popconfirm>}
            </Space>}
            {workerId && options.length === 0 && <Alert type="info" showIcon message={text('没有匹配的启用规则；请按下方指南先创建该 Worker 专属 tokens/day/deny 正限额规则。', 'No compatible enabled rule. Create a positive tokens/day/deny quota targeted to this Worker using the guide below.')} />}
            {workerId && !binding && <Alert type="info" showIcon message={text('该 Worker 尚未绑定平台配额；云端状态未验证。', 'This Worker has no platform quota binding. Cloud state is unverified.')} />}
            {binding && <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <WorkerQuotaStatus binding={binding} rule={boundRule} previewUsable={previewUsable} canReadAlerts={access.has('alerts:read')} zh={zh} />
              <WorkerQuotaActions key={`${binding.assetId}:${binding.version}:${binding.observation?.id ?? 'none'}`} binding={binding} rule={boundRule}
                mocked={data!.mocked === true} canObserve={canObserve} canSync={canSync} busy={busy} zh={zh} onObserve={observe} onSync={sync} />
            </Space>}
          </DataState>
          <Collapse defaultActiveKey={['guide']} items={[{ key: 'guide', label: text('配额接入与同步指南', 'Quota onboarding and synchronization guide'),
            children: <WorkerQuotaGuide zh={zh} assetId={workerId} /> }]} />
        </Space>
      </Panel>}
  </DataState>;
}

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Descriptions, Input, Select, Space, Table, Typography } from 'antd';
import { Panel } from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import ProvisioningForm from './ProvisioningForm';
import ProvisioningGuide from './ProvisioningGuide';
import { useProvisioning } from './useProvisioning';
import type { Receipt } from './types';

export default function PrivateLinkProvisioningPanel() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <Content key={`${tenant ?? 'none'}:${generation}`} />;
}

function Content() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess();
  const read = access.has('alicloud:read');
  const write = read && access.has('alicloud:write');
  const hook = useProvisioning(read);
  const state = hook.queue;
  const [selected, setSelected] = useState<string>();
  const [consent, setConsent] = useState<string[]>([]);
  const [seed, setSeed] = useState<string>();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const row = state?.requests.find(item => item.requestId === selected)
    ?? (hook.receipt?.requestId === selected ? hook.receipt : undefined);
  const preview = row?.purpose === 'preview' && row.result?.kind === 'preview' ? row : undefined;
  const sourceKey = state?.source
    ? `${state.source.configurationId}:${state.source.configurationVersion}` : 'none';
  const consentKey = `${sourceKey}:${preview?.requestId ?? ''}`;
  const check = (kind: string) => consent.includes(`${consentKey}:${kind}`);
  const locked = hook.busy || Boolean(hook.pending) || !write;
  const live = state?.source?.transportMode === 'live';
  const canApply = preview?.sourceCurrent && !preview.archived
    && preview.result?.kind === 'preview' && Date.parse(preview.result.expiresAt) > now
    && state?.generation === preview.result.baseGeneration;
  const observed = state?.requests.filter(item => item.result?.kind === 'observation'
    && !item.archived && item.phase === 'complete') ?? [];
  const confirmations = [
    ['cost', text('确认资源与费用', 'Confirm resources and cost')],
    ['role', text('确认当前配置为本动作消费方或提供方来源', 'Confirm the current consumer or provider source for this action')],
    ['boundary', text('理解观察不证明网络或业务可达', 'Understand observation does not prove network or business reachability')],
    ...(live ? [['live', text('确认真实云调用', 'Confirm Live cloud operation')]] : []),
  ];

  function apply() {
    if (!state || !preview || preview.result?.kind !== 'preview'
      || !(Date.parse(preview.result.expiresAt) > Date.now())) return;
    void hook.write({
      kind: 'apply',
      body: {
        request_id: crypto.randomUUID(),
        preview_id: preview.requestId,
        expected_generation: state.generation,
        confirm_resources_and_cost: check('cost'),
        confirm_current_role: check('role'),
        confirm_no_connectivity_proof: check('boundary'),
        confirm_live: check('live'),
        initialize_mock_fixture: seed === consentKey,
      },
    });
  }

  return <Panel title={text('PrivateLink 创建与独立接纳', 'PrivateLink creation and independent acceptance')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <ProvisioningGuide zh={zh} />
      {!read ? <Alert type="warning" message="Requires alicloud:read" /> : <>
        {hook.error && <Alert type="error" message={text(
          '结果未确认，保留原 UUID 与草稿，先读取原回执。',
          'Result is not confirmed. Retain the original UUID and draft, then read its receipt.',
        )} />}
        <Button disabled={hook.busy} onClick={() => void hook.refresh()}>
          {text('纯读取刷新', 'Refresh by reading')}
        </Button>
        <Typography.Text>
          {text('代次', 'Generation')}: {state?.generation ?? '—'} /{' '}
          {text('未决写入', 'Unresolved writes')}: {state?.unresolvedWriteCount ?? '—'}
        </Typography.Text>
        {state?.source ? <ProvisioningForm disabled={locked} zh={zh} region={state.source.region}
          onPreview={target => {
            if (state.source) void hook.write({
              kind: 'preview',
              body: {
                request_id: crypto.randomUUID(),
                configuration_version: state.source.configurationVersion,
                expected_generation: state.generation,
                selection: { action: 'create', target },
              },
            });
          }} /> : <Alert type="info" message={text(
          '先保存启用的 PrivateLink 连接。原历史仍可读取。',
          'Save an enabled PrivateLink connection first. Original history remains readable.',
        )} />}

        {state?.inventorySelection && <Button disabled={locked || !state.source} onClick={() => {
          if (state.source && state.inventorySelection) void hook.write({
            kind: 'observe',
            body: {
              request_id: crypto.randomUUID(),
              configuration_version: state.source.configurationVersion,
              original_create_request_id: null,
              inventory_scope_id: state.inventorySelection.scopeId,
              confirm_live: check('live'),
            },
          });
        }}>
          {text('导入完整既有端点盘点', 'Import complete existing endpoint inventory')}: {state.inventorySelection.endpointId}
        </Button>}

        <Space>
          <Select aria-label={text('接纳的完整观察', 'Complete observation for acceptance')}
            disabled={locked} style={{ minWidth: 280 }}
            value={selected && observed.some(item => item.requestId === selected) ? selected : undefined}
            options={observed.map(item => ({
              value: item.requestId,
              label: `${item.result?.kind === 'observation' ? item.result.endpointId : ''} / ${item.requestId}`,
            }))}
            onChange={value => { setSelected(value); setConsent([]); }} />
          <Button disabled={locked || !state?.source || row?.result?.kind !== 'observation'} onClick={() => {
            if (state?.source && row?.result?.kind === 'observation') void hook.write({
              kind: 'preview',
              body: {
                request_id: crypto.randomUUID(),
                configuration_version: state.source.configurationVersion,
                expected_generation: state.generation,
                selection: { action: 'accept', observation_request_id: row.requestId },
              },
            });
          }}>
            {text('当前提供方来源预览接纳', 'Preview accept with the current provider source')}
          </Button>
        </Space>

        <Table<Receipt> rowKey="requestId" pagination={false} dataSource={state?.requests ?? []}
          rowSelection={{
            type: 'radio',
            selectedRowKeys: selected ? [selected] : [],
            onChange: keys => { setSelected(String(keys[0] ?? '')); setConsent([]); setSeed(undefined); },
          }}
          columns={[
            { title: 'UUID', dataIndex: 'requestId' },
            { title: text('意图', 'Intent'), dataIndex: 'purpose' },
            { title: text('结果', 'Result'), render: (_, item) => item.result?.kind === 'write'
              ? item.result.delivery : item.result?.kind ?? item.completionState },
            { title: text('原来源版本', 'Original source version'), render: (_, item) => item.originalSource?.configurationVersion ?? '—' },
          ]} />
        <Space>
          <Button disabled={hook.busy || !state || state.page <= 1}
            onClick={() => void hook.refresh((state?.page ?? 1) - 1)}>{text('上一页', 'Previous')}</Button>
          <Button disabled={hook.busy || !state || state.page * state.pageSize >= state.total}
            onClick={() => void hook.refresh((state?.page ?? 1) + 1)}>{text('下一页', 'Next')}</Button>
        </Space>

        {preview?.resourceSummary && <Descriptions title={text('原预览资源', 'Original preview resources')} items={[
          { key: 'service', label: 'Service / VPC', children: `${preview.resourceSummary.serviceId} / ${preview.resourceSummary.vpcId}` },
          { key: 'zones', label: text('可用区及交换机', 'Zones and switches'),
            children: preview.resourceSummary.zones.map(zone => `${zone.zoneId}:${zone.vSwitchId}`).join(', ') },
          { key: 'sg', label: text('安全组', 'Security groups'), children: preview.resourceSummary.securityGroupIds.join(', ') },
          { key: 'role', label: text('当前配置身份须人工确认', 'Current configuration role requires explicit confirmation'),
            children: preview.action === 'EnableVpcEndpointConnection' ? 'provider' : 'consumer' },
        ]} />}

        {confirmations.map(([kind, label]) => <Checkbox key={`${consentKey}:${kind}`}
          disabled={locked} checked={check(kind)} onChange={event => setConsent(old => event.target.checked
            ? [...old, `${consentKey}:${kind}`] : old.filter(value => value !== `${consentKey}:${kind}`))}>
          {label}
        </Checkbox>)}
        {state?.source?.mocked && <Checkbox checked={seed === consentKey} disabled={locked}
          onChange={event => setSeed(event.target.checked ? consentKey : undefined)}>
          {text('首次显式初始化精确演示资源', 'Explicitly initialize the exact demo resources on first use')}
        </Checkbox>}

        <Space>
          <Button disabled={locked || !canApply || !check('cost') || !check('role') || !check('boundary')
            || (live && !check('live'))} onClick={apply}>{text('一次明确 Apply', 'One explicit Apply')}</Button>
          <Button disabled={locked || !state?.source || row?.result?.kind !== 'write'
            || row.result.delivery !== 'acknowledged' || row.archived || (live && !check('live'))}
            onClick={() => {
              if (state?.source && row) void hook.write({
                kind: 'observe',
                body: {
                  request_id: crypto.randomUUID(),
                  configuration_version: state.source.configurationVersion,
                  original_create_request_id: row.requestId,
                  inventory_scope_id: null,
                  confirm_live: check('live'),
                },
              });
            }}>{text('新 UUID 独立完整观察', 'Independent full observation with a new UUID')}</Button>
          <Button disabled={locked || !row?.canRecoverLocal} onClick={() => row && void hook.recover(row.requestId)}>
            {text('仅本地结算', 'Settle locally only')}
          </Button>
          <Button disabled={locked || !row?.canArchive} onClick={() => {
            if (state && row) void hook.write({
              kind: 'archive',
              body: { request_id: crypto.randomUUID(), expected_generation: state.generation, request_ids: [row.requestId] },
            });
          }}>{text('归档正文', 'Archive content')}</Button>
        </Space>

        <Space key="original-receipt">
          <Input aria-label={text('原 PrivateLink 请求 UUID', 'Original PrivateLink request UUID')}
            value={hook.recoverId} disabled={hook.busy || Boolean(hook.pending)}
            onChange={event => hook.setRecoverId(event.target.value)} />
          <Button disabled={hook.busy} onClick={() => void hook.readOriginal()}>{text('读取原回执', 'Read original receipt')}</Button>
          <Button disabled={hook.busy || !hook.confirmed} onClick={() => {
            hook.newIntent(); setConsent([]); setSeed(undefined);
            if (hook.receipt) setSelected(hook.receipt.requestId);
          }}>{text('已核对；允许新的明确操作', 'Reviewed; allow a new explicit operation')}</Button>
        </Space>
        {hook.receipt && <Descriptions title={text('原 PrivateLink 请求回执', 'Original PrivateLink request receipt')} items={[
          { key: 'id', label: 'UUID', children: hook.receipt.requestId },
          { key: 'result', label: text('原结果', 'Original result'), children: hook.receipt.result?.kind === 'write'
            ? hook.receipt.result.delivery : hook.receipt.result?.kind ?? hook.receipt.completionState },
          { key: 'audit', label: text('本地发布', 'Local publication'), children: hook.receipt.completionState },
          { key: 'connectivity', label: text('网络验证', 'Connectivity verification'), children: 'false' },
        ]} />}
      </>}
    </Space>
  </Panel>;
}

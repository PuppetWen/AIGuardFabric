import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Descriptions, Input, Space, Table, Typography } from 'antd';
import { Panel } from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import CmsQueueForm from './CmsQueueForm';
import CmsQueueGuide from './CmsQueueGuide';
import { useCmsQueue } from './useCmsQueue';
import type { Item } from './types';
export default function CmsQueuePanel() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <Content key={`${tenant ?? 'none'}:${generation}`} />;
}
function Content() {
  const { i18n } = useTranslation(); const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess(); const canRead = access.has('alicloud:read');
  const canWrite = canRead && access.has('alicloud:write');
  const state = useCmsQueue(canRead); const queue = state.queue;
  const [selectedId, setSelected] = useState<string>(); const [liveSource, setLiveSource] = useState<string>();
  const selected = queue?.items.find(item => item.id === selectedId);
  const locked = state.busy || Boolean(state.pending) || !canWrite;
  const sourceKey = queue?.source ? `${queue.source.configurationId}:${queue.source.configurationVersion}` : 'none';
  const live = liveSource === sourceKey;
  const status = (item: Item) => item.lastAttempt?.outcome?.delivery ?? item.lastAttempt?.completionState ?? 'queued';
  return <Panel title={text('CMS 持久补传队列', 'CMS durable delivery queue')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <CmsQueueGuide zh={zh} />
      {!canRead ? <Alert type="warning" message={text('需要 alicloud:read', 'Requires alicloud:read')} /> : <>
        {state.error && <Alert type="error" message={text('操作未确认。保留原 UUID 和草稿，读取原回执；不会自动重派。', 'Operation was not confirmed. Retain the original UUID and draft, then read the receipt. Nothing is automatically redispatched.')} />}
        <Button disabled={state.busy} onClick={() => void state.refresh()}>{text('纯读取刷新', 'Refresh by reading')}</Button>
        <Typography.Text>{text('代次', 'Generation')}: {queue?.generation ?? '—'} / {text('正文字节', 'Content bytes')}: {queue?.storedContentBytes ?? '—'}</Typography.Text>
        {!queue?.source && <Alert type="info" message={text('先在上方保存启用的 CMS 连接和 GroupId；历史仍可读取。', 'Save an enabled CMS connection and GroupId above first. History remains readable.')} />}
        <CmsQueueForm source={queue?.source ?? null} disabled={locked} zh={zh} onSubmit={(body, seed) => {
          if (!queue?.source) return;
          void state.write({ kind: 'enqueue', body: { request_id: crypto.randomUUID(), configuration_version: queue.source.configurationVersion,
            expected_generation: queue.generation, items: [body], initialize_mock_fixture: seed } });
        }} />
        <Table<Item> rowKey="id" dataSource={queue?.items ?? []} pagination={false}
          rowSelection={{ type: 'radio', selectedRowKeys: selectedId ? [selectedId] : [], onChange: keys => { setSelected(String(keys[0] ?? '')); setLiveSource(undefined); } }}
          columns={[{ title: text('名称', 'Name'), dataIndex: 'name' }, { title: text('状态', 'Status'), render: (_, item) => status(item) },
            { title: text('发送次数', 'Attempts'), dataIndex: 'attemptCount' }, { title: 'UUID', dataIndex: 'id' }]} />
        <Space>
          <Button disabled={state.busy || !queue || queue.page <= 1} onClick={() => void state.refresh((queue?.page ?? 1) - 1)}>{text('上一页', 'Previous')}</Button>
          <Button disabled={state.busy || !queue || queue.page * queue.pageSize >= queue.total} onClick={() => void state.refresh((queue?.page ?? 1) + 1)}>{text('下一页', 'Next')}</Button>
        </Space>
        {queue?.source?.transportMode === 'live' && <Checkbox key={sourceKey} checked={live} onChange={event => setLiveSource(event.target.checked ? sourceKey : undefined)} disabled={locked}>
          {text('确认此次真实 CMS 发送', 'Confirm this Live CMS delivery')}</Checkbox>}
        <Space>
          <Button disabled={locked || !selected?.canSend || (queue?.source?.transportMode === 'live' && !live)} onClick={() => {
            if (queue && selected) void state.write({ kind: 'send', body: { request_id: crypto.randomUUID(), expected_generation: queue.generation, item_ids: [selected.id], confirm_live: live } });
          }}>{text('新明确补传意图', 'New explicit delivery intent')}</Button>
          <Button disabled={locked || !selected?.canRecoverLocal} onClick={() => selected && void state.recover(selected.id)}>{text('仅本地结算', 'Settle locally only')}</Button>
          <Button disabled={locked || !selected?.canArchive} onClick={() => {
            if (queue && selected) void state.write({ kind: 'archive', body: { request_id: crypto.randomUUID(), expected_generation: queue.generation, item_ids: [selected.id] } });
          }}>{text('归档正文', 'Archive content')}</Button>
        </Space>
        <Space key="original-request">
          <Input aria-label={text('原 CMS 请求 UUID', 'Original CMS request UUID')} value={state.recoverId}
            disabled={state.busy || Boolean(state.pending)} onChange={event => state.setRecoverId(event.target.value)} />
          <Button disabled={state.busy} onClick={() => void state.readOriginal()}>{text('读取原回执', 'Read original receipt')}</Button>
          <Button disabled={state.busy || !state.confirmed} onClick={() => { state.newIntent(); setLiveSource(undefined); }}>{text('已核对；允许新的明确操作', 'Reviewed; allow a new explicit operation')}</Button>
        </Space>
        {state.receipt && <Descriptions title={text('原 CMS 请求回执', 'Original CMS request receipt')} items={[
          { key: 'uuid', label: 'UUID', children: state.receipt.id }, { key: 'purpose', label: text('意图', 'Intent'), children: state.receipt.purpose },
          { key: 'accepted', label: text('原发送结果', 'Original delivery results'), children: state.receipt.originalAttempts.map(attempt => `${attempt.id}: ${attempt.outcome?.delivery ?? attempt.completionState}`).join('; ') },
        ]} />}
      </>}
    </Space>
  </Panel>;
}

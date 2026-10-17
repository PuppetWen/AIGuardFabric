import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Collapse, Input, Space, Spin, Typography } from 'antd';
import { Panel } from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { PolicyRevision } from '@/types/apigPolicyPublication';
import ApigBinding from './ApigBinding';
import ApigObservation from './ApigObservation';
import ApigCandidate from './ApigCandidate';
import ApigPreview from './ApigPreview';
import ApigReceipt from './ApigReceipt';
import ApigHistory from './ApigHistory';
import ApigGuide from './ApigGuide';
import { useApigPublication } from './useApigPublication';
import { useApigText, uuid } from './text';

export default function ApigPolicyPublicationPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration), cache = useQueryClient();
  return <Content key={`${tenant?.id}:${tenant?.slug}:${generation}`} onConfigurationSaved={() => {
    void cache.invalidateQueries({ queryKey: ['agf', 'cloud-connections', tenant?.id, generation], exact: true });
  }} />;
}
function Content({ onConfigurationSaved }: { onConfigurationSaved: () => void }) {
  const text = useApigText(), access = useSessionAccess();
  const canRead = access.has('alicloud:read') && access.has('policies:read'), canWrite = canRead && access.has('alicloud:write');
  const query = useApigPublication(canRead, canWrite), data = query.data;
  const [selected, setSelected] = useState<PolicyRevision | null>(null), [rollbackId, setRollbackId] = useState<string | null>(null);
  const targetKey = data?.binding ? `${data.binding.targetScopeId}:${data.binding.configurationVersion}` : 'unbound';
  return <Panel title={text('APIG 独立限流策略发布', 'APIG independent rate-limit policy publication')}>
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Collapse items={[{ key: 'guide', label: text('APIG 发布、Unknown 恢复、阈值回滚与归档指南', 'APIG publication, Unknown recovery, threshold rollback and archive guide'), children: <ApigGuide /> }]} />
      {access.isLoading ? <Spin /> : !canRead ? <Alert type="info" message={text('查看需 alicloud:read 与 policies:read。', 'Viewing requires alicloud:read and policies:read.')} /> : <>
        {!canWrite && <Alert type="info" message={text('只读账号可明确观察；预览/发送/恢复/归档另需 alicloud:write。', 'Read-only users can explicitly observe; previews, sending, recovery and archive also require alicloud:write.')} />}
        {canWrite && <Collapse items={[{ key: 'binding', label: text('既有五 ID 绑定', 'Existing five-ID binding'), children: <ApigBinding onSaved={() => {
          query.invalidatePreview(); void query.refresh(); onConfigurationSaved();
        }} /> }]} />}
        <Button loading={query.loading} onClick={() => void query.refresh()}>{text('刷新 APIG 本地状态比较（仅 GET）', 'Refresh APIG local state to compare (GET only)')}</Button>
        {query.error && <Alert type="error" message={query.error} description={text('草稿与原编号保留。先核对、比较、读取原回执或恢复本地；不会自动换版本、初始化或重发云写。',
          'The draft and original ID remain. Inspect, compare, read the original receipt or recover locally; no automatic revision change, initialization or repeated cloud write.')} />}
        {!data && !query.error && <Spin />}
        {data && <>
          <ApigObservation key={targetKey} data={data} baseline={query.baseline} busy={query.busy}
            onObserve={(live, initialize) => void query.observe(live, initialize)} onAdopt={query.adopt} />
          {data.bindingReason && <Alert type="warning" message={data.bindingReason} />}
          {data.busy && <Alert type="warning" message={text('目标操作仍占用租约。关闭标签页不会停止已派发请求；读取原 UUID。', 'The target operation holds a lease. Closing the tab does not stop a dispatched request; read its original UUID.')} />}
          <ApigCandidate key={`${targetKey}:${query.baseline?.observation.id}:${data.unresolvedOperationId}`} data={data} baseline={query.baseline}
            operation={query.operation} selected={selected} rollbackId={rollbackId} canWrite={canWrite} busy={query.busy} loading={query.loading}
            eligibleOnly={query.eligibleOnly} onSourcePage={query.changeSources}
            onSelect={row => { if (!query.busy) { setSelected(row); query.invalidatePreview(); } }}
            onPublishMode={() => { if (!query.busy) { setRollbackId(null); query.invalidatePreview(); } }}
            onPrepare={(change, acknowledge) => void query.prepare(change, acknowledge)} onRead={id => void query.readReceipt(id)} />
          {query.preview && <ApigPreview key={query.preview.id} preview={query.preview} data={data} attempted={query.attempted}
            canWrite={canWrite} busy={query.busy} onApply={confirm => void query.apply(confirm)} />}
        </>}
        <Typography.Text key="original-request-heading">{text('原请求恢复；URL 只预填，首次不自动查询。', 'Original request recovery; the URL only prefills, without automatic querying.')}</Typography.Text>
        <Space key="original-request-controls" wrap><Input style={{ width: 370 }} aria-label={text('APIG 发布原请求 UUID', 'APIG publication original request UUID')} value={query.requestId}
          disabled={query.busy} onChange={event => query.changeRequest(event.target.value)} />
          <Button loading={query.reading} disabled={!uuid(query.requestId)} onClick={() => void query.readReceipt()}>{text('读取 APIG 原回执（仅 GET）', 'Read original APIG receipt (GET only)')}</Button></Space>
        {query.operation && <ApigReceipt key={`${query.operation.requestId}:${targetKey}`} operation={query.operation} data={data} canWrite={canWrite} busy={query.busy}
          onObserve={live => void query.observeOriginal(live)} onRecover={() => void query.recover()} onArchive={(id, generation) => query.archive([id], generation)} />}
        {data && <ApigHistory data={data} canWrite={canWrite} busy={query.busy} onRead={id => void query.readReceipt(id)}
          onRollback={id => { if (!query.busy) { setRollbackId(id); query.invalidatePreview(); } }} onArchive={query.archive} />}
      </>}
    </Space>
  </Panel>;
}

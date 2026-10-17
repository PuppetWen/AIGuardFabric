import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Collapse, Input, Space, Spin, Typography } from 'antd';
import { Panel } from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import PublicationBinding from './PublicationBinding';
import PublicationObservation from './PublicationObservation';
import PublicationCandidate from './PublicationCandidate';
import PublicationPreview from './PublicationPreview';
import PublicationReceipt from './PublicationReceipt';
import PublicationHistory from './PublicationHistory';
import PublicationGuide from './PublicationGuide';
import { usePublication } from './usePublication';
import { usePublicationText, uuid } from './text';
import type { PolicyRevision } from './types';

export default function MseConfigPublicationPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  const cache = useQueryClient();
  return <PublicationContent key={`${tenant?.id}:${tenant?.slug}:${generation}`} onConfigurationSaved={() => {
    void cache.invalidateQueries({ queryKey: ['agf', 'cloud-connections', tenant?.id, generation], exact: true });
  }} />;
}
function PublicationContent({ onConfigurationSaved }: { onConfigurationSaved: () => void }) {
  const text = usePublicationText(), access = useSessionAccess();
  const canRead = access.has('alicloud:read') && access.has('policies:read');
  const canWrite = canRead && access.has('alicloud:write');
  const query = usePublication(canRead, canWrite), data = query.data;
  const [selected, setSelected] = useState<PolicyRevision[]>([]), [rollbackId, setRollbackId] = useState<string | null>(null);
  const targetKey = data?.binding ? `${data.binding.targetScopeId}:${data.binding.configurationVersion}` : 'unbound';
  const select = (rows: PolicyRevision[]) => { if (!query.busy) { setSelected(rows); query.invalidatePreview(); } };
  return <Panel title={text('MSE 专用配置发布', 'MSE dedicated configuration publication')}>
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Collapse items={[{ key: 'guide', label: text('配置发布、恢复、回滚与归档指南', 'Configuration publication, recovery, rollback and archive guide'), children: <PublicationGuide /> }]} />
      {access.isLoading ? <Spin /> : !canRead ? <Alert type="info" message={text('查看需 alicloud:read 与 policies:read。', 'Viewing requires alicloud:read and policies:read.')} /> : <>
        {!canWrite && <Alert type="info" message={text('只读账号可以明确观察云内容；生成预览、发布、恢复与归档另需 alicloud:write。', 'Read access permits explicit observation of cloud content; previews, publication, recovery and archive also require alicloud:write.')} />}
        {canWrite && <Collapse items={[{ key: 'binding', label: text('专用 Data ID 目标绑定', 'Dedicated Data ID target binding'), children: <PublicationBinding onSaved={() => { query.invalidatePreview(); void query.refresh(); onConfigurationSaved(); }} /> }]} />}
        <Button loading={query.loading} onClick={() => void query.refresh()}>{text('刷新本地状态比较（仅 GET）', 'Refresh local state to compare (GET only)')}</Button>
        {query.error && <Alert showIcon type="error" message={query.error} description={text('草稿与已保存原回执保留。先核对原因和原编号，再明确比较、观察或本地恢复；不会重发云写。', 'The draft and saved original receipt remain. Inspect the cause and original ID, then explicitly compare, observe or recover locally; no cloud write is resent.')} />}
        {!data && !query.error && <Spin />}
        {data && <>
          <PublicationObservation key={targetKey} data={data} baseline={query.baseline} canRead={canRead} busy={query.busy}
            onObserve={live => void query.observe(live)} onAdopt={query.adopt} />
          {data.bindingReason && <Alert type="warning" message={data.bindingReason} />}
          {data.busy && <Alert type="warning" message={text('当前目标有进行中的操作。关闭页面或超时不会取消已发送请求；读取原回执。', 'The target has an active operation. Closing the page or a timeout cannot cancel a sent request; read the original receipt.')} />}
          <PublicationCandidate key={`${targetKey}:${query.baseline?.observation.id}:${data.unresolvedOperationId}`} data={data} baseline={query.baseline}
            operation={query.operation} selected={selected} onSelected={select} rollbackId={rollbackId} canWrite={canWrite} busy={query.busy}
            onPublishMode={() => { setRollbackId(null); query.invalidatePreview(); }}
            onPrepare={(change, acknowledge) => void query.prepare(change, acknowledge)} onRead={id => void query.readReceipt(id)} />
          {query.preview && <PublicationPreview key={query.preview.id} preview={query.preview} data={data} attempted={query.attempted}
            canWrite={canWrite} busy={query.busy} onApply={input => void query.apply(input)} onRead={id => void query.readReceipt(id)} />}
        </>}
        <Typography.Text>{text('原请求恢复入口；URL 参数只预填，不自动查询。', 'Original request recovery; the URL parameter only prefills without querying.')}</Typography.Text>
        <Space wrap><Input aria-label={text('配置发布原请求 UUID', 'Configuration publication original request UUID')} value={query.requestId}
          style={{ width: 370 }} disabled={query.busy} onChange={event => query.changeRequest(event.target.value)} />
          <Button loading={query.reading} disabled={!uuid(query.requestId)} onClick={() => void query.readReceipt()}>{text('读取发布原回执（仅 GET）', 'Read original publication receipt (GET only)')}</Button></Space>
        {query.operation && <PublicationReceipt key={`${query.operation.requestId}:${targetKey}`} operation={query.operation} data={data}
          canRead={canRead} canWrite={canWrite} busy={query.busy} onObserve={live => void query.observeOriginal(live)} onRecover={() => void query.recover()} />}
        {data && <PublicationHistory data={data} canWrite={canWrite} busy={query.busy} onRollback={id => { setRollbackId(id); query.invalidatePreview(); }}
          onRead={id => void query.readReceipt(id)} onArchive={(ids, generation) => void query.archive(ids, generation)} />}
      </>}
    </Space>
  </Panel>;
}

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Collapse, Input, Space, Spin, Typography } from 'antd';
import { Panel } from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import ConfigurationBinding from './ConfigurationBinding';
import ConfigurationObservation from './ConfigurationObservation';
import ConfigurationCandidate from './ConfigurationCandidate';
import ConfigurationPreview from './ConfigurationPreview';
import ConfigurationReceipt from './ConfigurationReceipt';
import ConfigurationHistory from './ConfigurationHistory';
import ConfigurationGuide from './ConfigurationGuide';
import { useConfigurationPublication } from './useConfigurationPublication';
import { useApigText, uuid } from './text';

export default function ApigConfigurationPublicationPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration), cache = useQueryClient();
  return <Content key={`${tenant?.id}:${tenant?.slug}:${generation}`} onConfigurationSaved={() => {
    void cache.invalidateQueries({ queryKey: ['agf', 'cloud-connections', tenant?.id, generation], exact: true });
  }} />;
}
function Content({ onConfigurationSaved }: { onConfigurationSaved: () => void }) {
  const text = useApigText(), access = useSessionAccess(), canRead = access.has('alicloud:read'), canWrite = canRead && access.has('alicloud:write');
  const query = useConfigurationPublication(canRead, canWrite), data = query.data, [rollbackId, setRollbackId] = useState<string | null>(null);
  const targetKey = data?.binding ? `${data.binding.targetScopeId}:${data.binding.configurationVersion}` : 'unbound';
  return <Panel title={text('APIG 内容安全与 Model API 配置管理', 'APIG content security and Model API configuration management')}>
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Collapse items={[{ key: 'guide', label: text('APIG 配置、Unknown 恢复、回滚与归档指南', 'APIG configuration, Unknown recovery, rollback and archive guide'), children: <ConfigurationGuide /> }]} />
      {access.isLoading ? <Spin /> : !canRead ? <Alert type="info" message={text('查看需 alicloud:read。', 'Viewing requires alicloud:read.')} /> : <>
        {!canWrite && <Alert type="info" message={text('只读用户可明确观察；初始化、配置保存、预览/发送/恢复/归档另需 alicloud:write。',
          'Read-only users can explicitly observe; initialization, saving configuration, previews, sending, recovery and archive also require alicloud:write.')} />}
        {canWrite && <Collapse items={[{ key: 'binding', label: text('既有配置目标绑定', 'Existing configuration target binding'), children: <ConfigurationBinding onSaved={() => {
          query.invalidatePreview(); void query.refresh(); onConfigurationSaved();
        }} /> }]} />}
        <Button loading={query.loading} onClick={() => void query.refresh()}>{text('刷新 APIG 配置本地状态（仅 GET）', 'Refresh APIG configuration local state (GET only)')}</Button>
        {query.error && <Alert type="error" message={query.error} description={text('草稿、旧版本和原编号保留；先比较或读原回执，不自动重发云写。',
          'The draft, old revision and original ID remain; compare or read the original receipt, without automatic repeated cloud writes.')} />}
        {!data && !query.error && <Spin />}
        {data && <>
          <ConfigurationObservation key={targetKey} data={data} baseline={query.baseline} busy={query.busy} canWrite={canWrite}
            onObserve={(live, initialize) => void query.observe(live, initialize)} onAdopt={query.adopt} />
          {data.bindingReason && <Alert type="warning" message={data.bindingReason} />}
          {data.busy && <Alert type="warning" message={text('请求仍占用租约；关闭页面不能停止派发，请读取原 UUID。', 'A request still holds the lease; closing the page cannot stop dispatch. Read its original UUID.')} />}
          <ConfigurationCandidate key={query.baseline?.id ?? 'no-baseline'} data={data} baseline={query.baseline} operation={query.operation}
            rollbackId={rollbackId} busy={query.busy} held={!!query.heldId} canWrite={canWrite}
            onPublishMode={() => { if (!query.busy) { setRollbackId(null); query.invalidatePreview(); } }}
            onPrepare={(change, acknowledge) => void query.prepare(change, acknowledge)} onChange={query.invalidatePreview} onRead={id => void query.readReceipt(id)} />
          {query.preview && <ConfigurationPreview key={query.preview.id} preview={query.preview} data={data} held={!!query.heldId} busy={query.busy}
            canWrite={canWrite} onApply={confirm => void query.apply(confirm)} />}
        </>}
        <div key="configuration-recovery-controls">
          <Typography.Paragraph>{text('原配置请求恢复；URL 仅预填，不自动查询。', 'Original configuration request recovery; the URL only prefills and does not query automatically.')}</Typography.Paragraph>
          <Space wrap><Input style={{ width: 370 }} aria-label={text('APIG 配置原请求 UUID', 'APIG configuration original request UUID')} value={query.requestId}
            onChange={event => query.changeRequest(event.target.value)} />
            <Button loading={query.reading} disabled={!uuid(query.requestId)} onClick={() => void query.readReceipt()}>{text('读取原配置回执（仅 GET）', 'Read original configuration receipt (GET only)')}</Button></Space>
        </div>
        {query.heldId && <>
          <Alert type="warning" message={text(`保留当前不可变意图 ${query.heldId}。未知回包或原回执 404 不解锁；其它历史回执也不解锁此意图。`,
            `Retained immutable intent ${query.heldId}. Unknown responses or original-receipt 404 do not unlock it; other historical receipts do not unlock it either.`)} />
          <Button onClick={() => void query.readReceipt(query.heldId!)}>{text('读取当前保留意图原回执', 'Read the retained current intent receipt')}</Button>
          <Button disabled={!query.canNewIntent} onClick={query.newIntent}>{text('原意图已完成或明确拒绝；明确准备新意图', 'Original intent completed or explicitly rejected; explicitly prepare a new intent')}</Button>
        </>}
        {query.operation && <ConfigurationReceipt key={`${query.operation.requestId}:${targetKey}`} operation={query.operation} data={data}
          canWrite={canWrite} busy={query.busy} onObserve={live => void query.observeOriginal(live)} onRecover={() => void query.recover()}
          onArchive={(id, generation) => query.archive([id], generation)} />}
        {data && <ConfigurationHistory data={data} canWrite={canWrite} busy={query.busy} held={!!query.heldId} onRead={id => void query.readReceipt(id)}
          onRollback={id => { if (!query.busy && !query.heldId) { setRollbackId(id); query.invalidatePreview(); } }} onArchive={query.archive} />}
      </>}
    </Space>
  </Panel>;
}

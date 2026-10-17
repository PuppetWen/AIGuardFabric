import { Alert, Button, Checkbox, Collapse, Descriptions, Input, Space, Spin, Tag } from 'antd';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { Panel } from '@/components/Panel';
import { usePrivateLinkInventory } from './usePrivateLinkInventory';
import { usePrivateLinkText } from './usePrivateLinkText';
import PrivateLinkInventoryGuide from './PrivateLinkInventoryGuide';
import PrivateLinkEndpointDetails from './PrivateLinkEndpointDetails';
import PrivateLinkReferenceGraph from './PrivateLinkReferenceGraph';
import PrivateLinkOperations from './PrivateLinkOperations';
import PrivateLinkOperationReceipt from './PrivateLinkOperationReceipt';

export default function PrivateLinkInventoryPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <InventoryContent key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}
function InventoryContent() {
  const text = usePrivateLinkText(), access = useSessionAccess();
  const canRead = access.has('alicloud:read'), canWrite = canRead && access.has('alicloud:write') && access.has('assets:write');
  const query = usePrivateLinkInventory(canRead, canWrite), data = query.data, busy = query.syncBusy || query.actionBusy;
  return <Panel title={text('PrivateLink 端点盘点', 'PrivateLink endpoint inventory')}>
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Collapse items={[{ key: 'guide', label: text('PrivateLink 盘点、恢复与归档指南', 'PrivateLink inventory, recovery and archive guide'), children: <PrivateLinkInventoryGuide /> }]} />
      {access.isLoading ? <Spin /> : !canRead ? <Alert type="info" message={text('查看需 alicloud:read。', 'Viewing requires alicloud:read.')} /> : <>
        {!canWrite && <Alert showIcon type="info" message={text('仅可读取。盘点、取消和归档需 alicloud:read、alicloud:write、assets:write。',
          'Read access only. Inventory, cancellation and archive require alicloud:read, alicloud:write and assets:write.')} />}
        <Button loading={query.loading} onClick={() => void query.refresh(true)}>{text('刷新本地观察与回执', 'Refresh local observations and receipts')}</Button>
        {query.error && <Alert showIcon type="error" message={query.error} description={text('保留原编号和已保存观察。先读原回执，409时刷新并核对范围；不会自动重发盘点。',
          'The original ID and saved observation remain. Read the original receipt; on HTTP 409 refresh and check scope. Inventory never resends automatically.')} />}
        {!data && !query.error && <Spin />}
        {data && <>
          <Descriptions size="small" column={2} items={[
            { key: 'scope', label: text('配置范围 / 版本', 'Configured scope / version'), children: `${data.scopeId ?? '—'} / ${data.configurationVersion ?? '—'}` },
            { key: 'target', label: text('配置地域 / 端点', 'Configured region / endpoint'), children: `${data.region ?? '—'} / ${data.endpointId ?? '—'}` },
            { key: 'mode', label: text('模式', 'Mode'), children: data.mocked === null ? text('未知', 'Unknown') : <Tag color={data.mocked ? 'blue' : 'orange'}>{data.mocked ? 'Mock' : 'Live'}</Tag> },
            { key: 'checked', label: text('最近完整观察', 'Last complete observation'), children: data.checkedAt ?? text('尚未观察', 'Unobserved') },
            { key: 'pages', label: text('子列表页 / 完整分页', 'Child-list pages / complete pagination'), children: `${data.pagesRead ?? text('未知', 'Unknown')} / ${data.listingComplete ? text('是；非强一致', 'Yes; not strongly consistent') : text('尚未完整观察', 'Unobserved')}` },
            { key: 'reachability', label: text('网络可达 / 调用授权', 'Network reachability / authorization'), children: text('未知 / 未知', 'Unknown / Unknown') },
          ]} />
          {!data.configured && <Alert showIcon type="info" message={text('连接停用或未明确目标。先配置地域和已有端点 ID；历史回执仍可读、取消和归档。',
            'The connection is disabled or has no explicit target. Configure region and an existing endpoint ID. Historical receipts remain readable, cancellable and archivable.')} />}
          {!data.topologyAvailable && <Alert showIcon type="info" message={text('当前范围尚无完整观察；数量和关系未知。旧范围不会当作当前拓扑。',
            'The current scope has no complete observation; counts and references are unknown. An old scope is not shown as current topology.')} />}
          {data.configured && data.mocked !== true && <Checkbox checked={query.confirmed} disabled={busy || !!query.requestId}
            onChange={event => query.setConfirmed(event.target.checked)}>{text('确认当前端点范围的真实只读云请求和本地资产发布', 'Confirm live read-only cloud requests and local asset publication for this endpoint scope')}</Checkbox>}
          <Space wrap><Button type="primary" loading={query.syncBusy} disabled={!query.canSync} onClick={() => void query.sync()}>{text('读取端点并发布观察', 'Read endpoint and publish observations')}</Button>
            {!!query.requestId && <Button disabled={!query.canPrepare} onClick={query.prepare}>{text('准备新盘点', 'Prepare new inventory')}</Button>}</Space>
          {data.topologyAvailable && data.endpoint && <>
            <PrivateLinkEndpointDetails endpoint={data.endpoint} canReadAssets={access.has('assets:read')} />
            <PrivateLinkReferenceGraph key={`${data.scopeId}:${data.checkedAt}`} graph={data.graph} canReadAssets={access.has('assets:read')} />
          </>}
        </>}
        <Space wrap><Input aria-label={text('PrivateLink 原请求 UUID', 'PrivateLink original request UUID')} value={query.requestId} style={{ width: 360 }} disabled={busy}
          placeholder={text('输入原请求 UUID 恢复', 'Enter the original request UUID to restore')} onChange={event => query.changeRequest(event.target.value)} />
          <Button loading={query.receiptBusy} disabled={!query.canReadReceipt || query.actionBusy} onClick={() => void query.read()}>{text('读取原请求回执', 'Read original request receipt')}</Button></Space>
        {query.syncBusy && <Alert showIcon type="info" message={text('可读取当前原编号并显式取消。关闭页面不是取消；已发送的云读取不可撤回。',
          'Read the original ID and cancel explicitly. Closing this page does not cancel; already-sent cloud reads cannot be recalled.')} />}
        {query.operation && <PrivateLinkOperationReceipt operation={query.operation} canWrite={canWrite} busy={query.actionBusy} cancel={() => void query.cancel()} />}
        {data && <PrivateLinkOperations data={data} selected={query.selected} onSelected={query.setSelected} busy={busy} canWrite={canWrite}
          onRead={id => void query.read(id)} onArchive={() => void query.archive()} />}
      </>}
    </Space>
  </Panel>;
}

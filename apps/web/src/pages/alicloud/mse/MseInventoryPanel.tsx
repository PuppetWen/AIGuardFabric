import { Alert, Button, Checkbox, Collapse, Descriptions, Input, Space, Spin, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { Panel } from '@/components/Panel';
import { useMseInventory } from './useMseInventory';
import MseInventoryGuide from './MseInventoryGuide';
import MseServicesTable from './MseServicesTable';
import MseOperations from './MseOperations';
import MseOperationReceipt from './MseOperationReceipt';

export default function MseInventoryPanel() {
  const tenant = useAuthStore(state => state.tenant);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <MseContent key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}
function MseContent() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess();
  const canRead = access.has('alicloud:read');
  const canWrite = canRead && access.has('alicloud:write') && access.has('assets:write');
  const query = useMseInventory(canRead, canWrite), data = query.data;
  const busy = query.syncBusy || query.actionBusy;
  return <Panel title={text('MSE 服务盘点', 'MSE service inventory')}>
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Collapse items={[{ key: 'guide', label: text('MSE 盘点、恢复与归档指南', 'MSE inventory, recovery and archive guide'), children: <MseInventoryGuide /> }]} />
      {access.isLoading ? <Spin /> : !canRead ? <Alert type="info" message={text('查看需 alicloud:read。', 'Viewing requires alicloud:read.')} /> : <>
        {!canWrite && <Alert showIcon type="info" message={text('当前仅可读取；盘点、取消和归档需 alicloud:read、alicloud:write、assets:write。',
          'Read access only; inventory, cancellation and archive require alicloud:read, alicloud:write and assets:write.')} />}
        <Button loading={query.loading} onClick={() => void query.refresh(true)}>{text('刷新本地清单与回执', 'Refresh local inventory and receipts')}</Button>
        {query.error && <Alert type="error" showIcon message={query.error} description={text('原编号和已保存结果保留。先读取原请求回执；409时刷新本地清单并核对范围，不会自动重新盘点。',
          'The original ID and saved result remain. Read the original receipt first. On HTTP 409 refresh local inventory and verify the scope; no inventory is dispatched automatically.')} />}
        {!data && !query.error && <Spin />}
        {data && <>
          <Descriptions size="small" column={2} items={[
            { key: 'scope', label: text('当前范围 / 配置版本', 'Current scope / configuration version'), children: `${data.scopeId ?? '—'} / ${data.configurationVersion ?? '—'}` },
            { key: 'instance', label: text('地域 / 实例', 'Region / instance'), children: `${data.region ?? '—'} / ${data.instanceId ?? '—'}` },
            { key: 'namespace', label: text('命名空间', 'Namespace'), children: data.namespaceId === '' ? text('默认（空字符串）', 'Default (empty string)') : data.namespaceId ?? text('未配置', 'Not configured') },
            { key: 'mode', label: text('模式', 'Mode'), children: data.mocked === null ? text('未知', 'Unknown') : <Tag color={data.mocked ? 'blue' : 'orange'}>{data.mocked ? 'Mock' : 'Live'}</Tag> },
            { key: 'total', label: text('完整观察服务数', 'Observed service count'), children: data.totalServices ?? text('未知（尚未观察当前范围）', 'Unknown (current scope unobserved)') },
            { key: 'checked', label: text('最近完整观察', 'Last complete observation'), children: data.checkedAt ?? '—' },
          ]} />
          {!data.configured && <Alert showIcon type="info" message={text('当前连接停用或范围未配置；历史原回执仍可读取、取消和归档。新盘点先明确实例和命名空间、保存启用连接。',
            'The connection is disabled or its scope is unconfigured. Historical receipts remain readable, cancellable and archivable. Configure an explicit instance/namespace and enable the connection before new inventory.')} />}
          {!data.inventoryAvailable && <Alert showIcon type="info" message={text('当前范围没有有效快照，数量未知；旧范围不会冒充当前清单。',
            'The current scope has no valid snapshot; its count is unknown. An old scope is not shown as current inventory.')} />}
          {!data.mocked && data.configured && <Checkbox checked={query.confirmed} disabled={busy || !!query.requestId}
            onChange={event => query.setConfirmed(event.target.checked)}>{text('确认当前范围的真实只读云请求和本地资产发布', 'Confirm live read-only cloud requests and local asset publication for this scope')}</Checkbox>}
          <Space wrap><Button type="primary" loading={query.syncBusy} disabled={!query.canSync} onClick={() => void query.sync()}>{text('读取完整服务并发布台账', 'Read complete services and publish inventory')}</Button>
            {!!query.requestId && <Button disabled={!query.canPrepare} onClick={query.prepare}>{text('准备新盘点', 'Prepare new inventory')}</Button>}</Space>
          <Typography.Text type="secondary">{text('列表完整表示完成本次分页，非云端强一致快照；地址、协议、环境、网络区域和授权未知。人工治理保留。',
            'Complete listing means completed pagination, not a strongly consistent cloud snapshot. Endpoint, protocol, runtime, network zone and authorization are unknown. Manual governance is preserved.')}</Typography.Text>
          <MseServicesTable items={data.items} canReadAssets={access.has('assets:read')} />
        </>}
        <Space wrap><Input aria-label={text('MSE 原请求 UUID', 'MSE original request UUID')} value={query.requestId} style={{ width: 360 }}
          disabled={busy} placeholder={text('输入原请求 UUID 恢复', 'Enter the original request UUID to restore')}
          onChange={event => query.changeRequest(event.target.value)} />
          <Button loading={query.receiptBusy} disabled={!query.canReadReceipt || query.actionBusy} onClick={() => void query.read()}>{text('读取原请求回执', 'Read original request receipt')}</Button></Space>
        {query.syncBusy && <Alert showIcon type="info" message={text('只读盘点正在运行，可读取当前原编号并显式取消；关闭页面不是取消。',
          'Read-only inventory is running. Read this original ID and cancel explicitly; closing the page does not cancel it.')} />}
        {query.operation && <MseOperationReceipt operation={query.operation} canWrite={canWrite} busy={query.actionBusy}
          cancel={() => void query.cancel()} />}
        {data && <MseOperations data={data} selected={query.selected} onSelected={query.setSelected} busy={busy}
          canWrite={canWrite} onRead={id => void query.read(id)} onArchive={() => void query.archive()} />}
      </>}
    </Space>
  </Panel>;
}

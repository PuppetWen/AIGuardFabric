import { Alert, Button, Descriptions, Popconfirm, Space, Typography } from 'antd';
import { useText } from './text';
import type { OrchestrationFlow } from './useOrchestration';

export function OrchestrationPreview({ flow }: { flow: OrchestrationFlow }) {
  const t = useText(), value = flow.prepared;
  if (!value) return null;
  const allowed = value.body.confirm_application_owned && (value.body.change.action !== 'sync' || value.body.confirm_mock_sync);
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('候选差异', 'Candidate differences')}</Typography.Title>
    <Descriptions column={1} items={[
      { key: 'request', label: 'Request UUID', children: value.body.request_id },
      { key: 'version', label: t('比较基线', 'Comparison baseline'), children: `${value.body.expected_version} → ${value.preview.result.version}` },
      { key: 'add', label: t('新增节点', 'Added nodes'), children: value.preview.difference.added.join(', ') || '—' },
      { key: 'remove', label: t('移除节点', 'Removed nodes'), children: value.preview.difference.removed.join(', ') || '—' },
      { key: 'change', label: t('变化节点', 'Changed nodes'), children: value.preview.difference.changed.join(', ') || '—' },
      { key: 'receiver', label: t('候选 Mock 接收端', 'Candidate Mock receiver'), children: value.preview.result.receiverAvailable ? t('已知', 'Known') : t('未知', 'Unknown') },
    ]} />
    <Alert type="warning" message={t('预览不写入。确认后只提交这一份 UUID / 基线 / 内容；失败不会自动重发。',
      'Preview does not write. Confirmation submits this UUID, baseline and content once; failures will not trigger automatic resubmission.')} />
    <Popconfirm title={t('提交已审阅的候选？', 'Commit the reviewed candidate?')} okText={t('确认提交本地事实', 'Confirm committing the local fact')}
      disabled={!allowed || flow.busy || flow.writeLocked} onConfirm={() => flow.apply()}>
      <Button type="primary" disabled={!allowed || flow.busy || flow.writeLocked}>{t('提交已审阅候选', 'Commit the reviewed candidate')}</Button>
    </Popconfirm>
  </Space>;
}

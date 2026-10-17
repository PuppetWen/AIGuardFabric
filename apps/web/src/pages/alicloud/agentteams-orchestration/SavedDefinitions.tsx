import { Alert, Input, Space, Table, Typography } from 'antd';
import { useText } from './text';
import type { RecordView } from './types';

export function SavedDefinitions({ records }: { records: RecordView[] }) {
  const t = useText();
  return <Table rowKey="teamName" size="small" dataSource={records} pagination={{ pageSize: 20, showSizeChanger: false }} columns={[
    { title: 'Team', dataIndex: 'teamName' }, { title: t('保存版本', 'Saved revision'), dataIndex: 'version' },
    { title: t('本地节点', 'Local nodes'), render: (_, row) => row.local?.nodes.length ?? t('未知', 'Unknown') },
    { title: t('Mock 接收端节点', 'Mock receiver nodes'), render: (_, row) => row.receiverAvailable ? row.receiver?.nodes.length ?? t('未知', 'Unknown') : t('未知', 'Unknown') },
  ]} expandable={{ expandedRowRender: row => <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" message={t('原保存定义可读；不代表当前来源合格或消费者已生效。', 'The saved definition is readable; it does not prove current source qualification or consumer application.')} />
    <Typography.Text>{t('本地声明 JSON', 'Local declaration JSON')}</Typography.Text><Input.TextArea readOnly aria-label={t('已保存本地 JSON', 'Saved local JSON')} value={JSON.stringify(row.local, null, 2)} rows={8} />
    <Typography.Text>{t('接收端声明 JSON', 'Receiver declaration JSON')}</Typography.Text><Input.TextArea readOnly aria-label={t('已保存接收端 JSON', 'Saved receiver JSON')} value={row.receiverAvailable ? JSON.stringify(row.receiver, null, 2) : t('未知', 'Unknown')} rows={8} />
  </Space> }} />;
}

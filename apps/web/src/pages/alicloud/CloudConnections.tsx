import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Space, Table, Tag } from 'antd';
import { useApiQuery } from '@/api/client';
import { cloudApi, type CloudSummary } from '@/api/cloud';
import { Panel } from '@/components/Panel';
import { DataState } from '@/components/DataState';
import CloudEditor from './CloudEditor';

export default function CloudConnections() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const query = useApiQuery('cloud-connections', cloudApi.list);
  const [editing, setEditing] = useState<string>();
  return <Panel title={text('云服务接入与操作', 'Cloud connections and operations')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Alert type="info" showIcon message={text('先配置云账号和实例，再运行只读自检', 'Configure cloud credentials and instances, then run a read-only check')}
        description={text('每个服务独立启用。模拟调用不会访问云端；真实调用、权限检查和结果均有记录。', 'Enable services independently. Mock calls stay offline; actual calls, checks and results are recorded.')} />
      <DataState loading={query.isLoading} error={query.error}>
        <Table<CloudSummary> rowKey="name" pagination={false} dataSource={query.data?.data.items ?? []} columns={[
          { title: text('服务', 'Service'), dataIndex: 'displayName' },
          { title: text('状态', 'Status'), render: (_, row) => <Tag color={row.enabled ? 'blue' : 'default'}>{row.enabled ? text('已启用', 'Enabled') : text('未启用', 'Disabled')}</Tag> },
          { title: text('调用方式', 'Mode'), render: (_, row) => row.mock ? text('模拟', 'Mock') : text('真实云 API', 'Live cloud API') },
          { title: text('配置版本', 'Version'), dataIndex: 'version' },
          { title: text('操作', 'Action'), render: (_, row) => <Button onClick={() => setEditing(row.name)}>{text('配置与接入', 'Configure')}</Button> },
        ]} />
      </DataState>
    </Space>
    {editing && <CloudEditor name={editing} onClose={() => setEditing(undefined)} onSaved={() => { void query.refetch(); }} />}
  </Panel>;
}

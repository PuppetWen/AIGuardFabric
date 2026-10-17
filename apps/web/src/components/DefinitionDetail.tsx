import { useTranslation } from 'react-i18next';
import { Alert, Descriptions, Drawer, Input, Space, Typography } from 'antd';
import { DataState } from './DataState';
import { useDetailLink } from './useDetailLink';

interface Definition { key?: string; title?: string; name?: string; yaml?: string; description?: string; category?: string; severity?: string; tags?: string[]; turns?: unknown[]; rule?: { name: string } }
/** Read-only detail. Viewing a test case never launches it or writes a rule. */
export function DefinitionDetail({ kind }: { kind: 'rule' | 'testCase' }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const { id, detail, value, select } = useDetailLink<Definition>(kind, kind === 'rule' ? '/api/v1/rules' : '/api/v1/redteam/cases');
  const title = kind === 'rule' ? (zh ? '检测规则详情' : 'Detection rule detail') : (zh ? '红队用例详情' : 'Red-team test case');
  return <Drawer width={820} title={`${title} · ${id}`} open={Boolean(id)} onClose={() => select(null)}>
    <DataState loading={detail.isLoading} error={detail.error} onRetry={() => void detail.refetch()}>
      {value && <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Typography.Title level={4}>{value.title ?? value.name ?? value.rule?.name}</Typography.Title>
        {kind === 'testCase' && <>
          <Alert type="info" showIcon message={zh ? '这里只查看用例。执行测试需在红队中心选择已获授权的目标并发起战役。' : 'This is a read-only preview. To run it, launch a campaign against an authorized target.'} />
          <Typography.Paragraph>{value.description}</Typography.Paragraph>
          <Descriptions column={1} items={[
            { key: 'category', label: zh ? '类别' : 'Category', children: value.category },
            { key: 'severity', label: zh ? '严重等级' : 'Severity', children: value.severity },
            { key: 'tags', label: zh ? '标签' : 'Tags', children: value.tags?.join(' · ') },
          ]} />
        </>}
        <Input.TextArea aria-label={zh ? '完整定义（只读）' : 'Full definition (read only)'} readOnly
          value={value.yaml ?? JSON.stringify(value, null, 2)} autoSize={{ minRows: 15, maxRows: 30 }} style={{ fontFamily: 'monospace' }} />
      </Space>}
    </DataState>
  </Drawer>;
}

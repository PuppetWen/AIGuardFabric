import { useState } from 'react';
import { Alert, Button, Divider, Drawer, Popconfirm, Select, Space, Switch, Table, Tag, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { useApiQuery } from '@/api/client';
import { correlationApi, correlationRequest, type Definition, type RuleRow } from './correlationApi';
import { CorrelationGuide } from './CorrelationGuide';
import { CorrelationEditor } from './CorrelationEditor';

export function CorrelationConsole() {
  const { i18n } = useTranslation();
  const tenant = useAuthStore(state => state.tenant);
  const [open, setOpen] = useState(false);
  const zh = i18n.language.startsWith('zh');
  return <><Button onClick={() => setOpen(true)}>{zh ? '关联分析' : 'Correlation'}</Button>
    <Drawer open={open} width={1100} destroyOnClose title={zh ? '关联规则与操作指南' : 'Correlation rules and guide'} onClose={() => setOpen(false)}>
      {open && <Content key={tenant?.id} zh={zh} />}
    </Drawer></>;
}

function Content({ zh }: { zh: boolean }) {
  const data = useApiQuery('correlation-rules', () => correlationRequest<{ items: RuleRow[]; automatic: boolean }>('rules'));
  const examples = useApiQuery('correlation-examples', () => correlationRequest<{ items: { definition: Definition }[] }>('examples'));
  const [draft, setDraft] = useState<{ definition: Definition; row?: RuleRow; key: number }>();
  const [busy, setBusy] = useState(false);
  const edit = (definition: Definition, row?: RuleRow) => setDraft({ definition, row, key: Date.now() });
  const update = async (row: RuleRow, enabled: boolean, deleted = false) => {
    setBusy(true);
    try {
      await correlationApi('rules', { definition: { ...row.current.definition, enabled }, expected_version: row.current.version, deleted });
      await data.refetch();
    } catch (error) { void message.error(String(error)); }
    finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }} size="middle">
    <CorrelationGuide zh={zh} />
    {data.data && !data.data.data.automatic && <Alert showIcon type="info" message={zh ? '当前仅支持样本试跑，自动分析需要 SQL 事件库' : 'Sample previews are available; automatic analysis requires SQL'} />}
    {(data.error || examples.error) && <Alert showIcon type="error" message={String(data.error ?? examples.error)} />}
    <Space><Select<number> aria-label="Correlation example" placeholder={zh ? '选择样例创建规则' : 'Create from an example'} style={{ width: 270 }} value={undefined}
      loading={examples.isLoading} options={examples.data?.data.items.map((item, index) => ({ value: index, label: ({ temporal: zh ? '时序关联' : 'Temporal sequence', graph: zh ? '图路径关联' : 'Graph path', baseline: zh ? '历史基线' : 'Historical baseline', match: zh ? '检测规则关联' : 'Detection rule match' } as Record<string, string>)[item.definition.rule.kind] }))}
      onChange={index => { const example = examples.data?.data.items[index]; if (example) edit(example.definition); }} />
      <Button loading={data.isLoading} onClick={() => void data.refetch()}>{zh ? '刷新' : 'Refresh'}</Button>
    </Space>
    <Table<RuleRow> size="small" loading={data.isLoading || busy} rowKey={row => row.current.definition.rule.key} dataSource={data.data?.data.items ?? []}
      pagination={{ pageSize: 8 }} columns={[
        { title: zh ? '名称 / 标识' : 'Name / key', render: (_, row) => <><div>{row.current.definition.rule.name}</div><code>{row.current.definition.rule.key}</code></> },
        { title: zh ? '类型' : 'Type', render: (_, row) => row.current.definition.rule.kind },
        { title: zh ? '版本' : 'Version', render: (_, row) => row.current.version },
        { title: zh ? '启用' : 'Enabled', render: (_, row) => row.current.deleted ? <Tag>{zh ? '已删除' : 'Deleted'}</Tag>
          : <Switch checked={row.current.definition.enabled} onChange={enabled => void update(row, enabled)} /> },
        { title: zh ? '操作' : 'Actions', render: (_, row) => <Space>
          <Button onClick={() => edit(row.current.definition, row)}>{zh ? '编辑 / 历史' : 'Edit / history'}</Button>
          {!row.current.deleted && <Popconfirm title={zh ? '停用并删除此规则？历史记录将保留。' : 'Disable and delete this rule? History will be retained.'}
            onConfirm={() => update(row, false, true)}><Button danger>{zh ? '删除' : 'Delete'}</Button></Popconfirm>}
        </Space> },
      ]} />
    {draft && <><Divider>{draft.row ? (zh ? '编辑规则' : 'Edit rule') : (zh ? '新建规则' : 'New rule')}</Divider>
      <CorrelationEditor key={draft.key} definition={draft.definition} row={draft.row} zh={zh} onSaved={() => { setDraft(undefined); void data.refetch(); }} />
    </>}
  </Space>;
}

import { Alert, Button, Checkbox, Space, Table, Typography } from 'antd';
import type { ApigPublicationState, EligibleSource, PolicyRevision } from '@/types/apigPolicyPublication';
import { revisions, useApigText } from './text';

export default function ApigSources({ data, selected, onSelect, disabled, loading, eligibleOnly, onPage }: {
  data: ApigPublicationState; selected: PolicyRevision | null; onSelect: (row: PolicyRevision | null) => void; disabled: boolean;
  loading: boolean; eligibleOnly: boolean; onPage: (page: number, onlyEligible: boolean) => void;
}) {
  const text = useApigText(), loaded = selected ? data.sources.items.find(row => row.policyId === selected.policyId) : undefined;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" message={text('只选择服务端核验可投射的当前签名策略版本；每次只修改一个已有 Global minute slot。',
      'Select a current signed policy revision verified as projectable by the server; each operation changes one existing Global minute slot.')}
      description={text('创建通用配额：Tenant、Requests/Token、Minute、Deny、正 int32 上限、软阈值明确 0；策略用 Structured、源码 {}、Quota、仅 ai-gateway、无条件/范围/dry-run。原通用策略默认值不改变。',
        'Prepare a generic quota: Tenant, Requests/Tokens, Minute, Deny, a positive int32 limit and explicit soft threshold 0. Use a Structured policy with {}, Quota, only ai-gateway and no conditions, narrowed scopes or dry-run. Generic policy defaults are unchanged.')} />
    <Space><a href="/runtime#quota-rules" target="_blank" rel="noreferrer">{text('打开配额规则并复制真实 UUID', 'Open quota rules and copy the actual UUID')}</a>
      <a href="/policies" target="_blank" rel="noreferrer">{text('打开策略中心准备真实来源', 'Open Policies to prepare an actual source')}</a></Space>
    <Typography.Text>{text('保留所选来源版本', 'Retained selected source revision')}: {revisions(selected ? [selected] : [])}</Typography.Text>
    {selected && !loaded && <Alert type="info" message={text('此页未加载所选版本，不代表已删除。确切版本保留，生成预览时服务端重新检查全部来源。',
      'The selected revision is not loaded on this page; that does not mean it was deleted. Its exact revision remains, and the server rechecks all sources when preparing.')} />}
    {selected && loaded && (loaded.version !== selected.version || !loaded.eligible) && <Alert type="warning" message={text('所选版本与当前可用来源不同；草稿保留。先核对原因，再明确重新选择；刷新不会自动换版。',
      'The selected revision differs from the currently eligible source; the draft remains. Inspect the reason, then reselect explicitly; refresh does not replace revisions.')} />}
    {data.sources.reason && <Alert type="info" message={data.sources.reason} />}
    <Typography.Text>{text(`可信策略 ${data.sources.policyCount}，可投射 ${data.sources.eligibleCount}；当前筛选共 ${data.sources.total} 条。`,
      `${data.sources.policyCount} trusted policies, ${data.sources.eligibleCount} projectable; ${data.sources.total} in the current filter.`)}</Typography.Text>
    <Checkbox checked={eligibleOnly} disabled={disabled || loading} onChange={event => onPage(1, event.target.checked)}>{text('只显示服务端可投射来源', 'Show only server-eligible sources')}</Checkbox>
    <Table<EligibleSource> rowKey="policyId" size="small" loading={loading} pagination={{ current: data.sources.page, pageSize: data.sources.pageSize,
      total: data.sources.total, showSizeChanger: false, onChange: page => onPage(page, eligibleOnly) }} dataSource={data.sources.items} columns={[
      { title: text('真实策略 / 版本', 'Actual policy / revision'), render: (_, row) => `${row.name} · ${row.policyId} @ v${row.version}` },
      { title: text('配额 / 阈值', 'Quota / threshold'), render: (_, row) => row.source
        ? `${row.source.quotaId} @ v${row.source.quotaVersion} / ${row.source.managedLimit} = ${row.source.limit}` : '—' },
      { title: text('当前可用 / 原因', 'Currently eligible / reason'), render: (_, row) => `${row.eligible} / ${row.reason ?? '—'}` },
      { title: text('明确选择', 'Explicit choice'), render: (_, row) => <Button size="small" disabled={disabled || loading || !row.eligible || !row.source}
        aria-label={`${text('选择平台策略', 'Choose platform policy')} ${row.name} v${row.version}`}
        onClick={() => onSelect({ policyId: row.policyId, version: row.version })}>{text('选择此版本', 'Choose this revision')}</Button> },
    ]} />
    {selected && <Button disabled={disabled} onClick={() => onSelect(null)}>{text('明确清空来源选择', 'Explicitly clear the source selection')}</Button>}
  </Space>;
}

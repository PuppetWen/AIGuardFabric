import { Alert, Button, Input, Select, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { selectableQuota, usePolicyQuotaOptions } from './usePolicyQuotaOptions';

interface SelectionProps { value?: string; onChange?: (value: string) => void; disabled?: boolean; id?: string }

export function PolicyQuotaSelection(props: SelectionProps) {
  const access = useSessionAccess(), tenant = useAuthStore(state => state.tenant);
  const generation = useAuthStore(state => state.sessionGeneration);
  const zh = useTranslation().i18n.language.startsWith('zh');
  if (!access.has('quotas:read')) return <Space direction="vertical" style={{ width: '100%' }}>
    <Input aria-label={zh ? '当前配额 ID' : 'Current quota ID'} value={props.value ?? ''} readOnly />
    <Alert type="info" message={access.isLoading ? (zh ? '正在读取配额查看权限' : 'Checking quota read permission')
      : (zh ? '选择配额需要 quotas:read；当前草稿 ID 保持不变。' : 'Selecting a quota requires quotas:read; the current draft ID is unchanged.')} />
  </Space>;
  return <QuotaOptions key={`${tenant?.id}:${tenant?.slug}:${generation}`} {...props} />;
}

function QuotaOptions({ value, onChange, disabled, id }: SelectionProps) {
  const zh = useTranslation().i18n.language.startsWith('zh'), scope = useOperationScope();
  const text = (cn: string, en: string) => zh ? cn : en;
  const list = usePolicyQuotaOptions(), current = list.rows.find(row => row.id === value);
  const retained = !!value && !current;
  const options = list.rows.map(row => ({ value: row.id, disabled: !selectableQuota(row),
    label: `${row.name} · ${row.id} · ${Number.isSafeInteger(row.version) && row.version > 0 ? `v${row.version}` : text('版本未知', 'Revision unknown')} · ${row.scope}/${row.dimension}/${row.window}${row.enabled ? '' : text('（停用）', ' (disabled)')}` }));
  if (value && !current) options.unshift({ value, disabled: true, label: `${value} · ${text('原有 ID，未验证', 'Existing ID, unverified')}` });
  return <Space direction="vertical" size={8} style={{ width: '100%' }}>
    <Select id={id} aria-label={text('选择当前租户配额', 'Select current tenant quota')} style={{ width: '100%' }}
      value={value || undefined} options={options} showSearch optionFilterProp="label" allowClear
      placeholder={text('明确选择已启用配额，或留空保持原语义', 'Explicitly select an enabled quota, or leave empty to retain existing semantics')}
      loading={list.loading} disabled={disabled || list.loading || !!list.error}
      onChange={(next: string | undefined) => {
        if (!disabled && !list.loading && !list.error && scope.current()
          && (!next || list.rows.some(row => row.id === next && selectableQuota(row)))) onChange?.(next ?? '');
      }} />
    {value && <Input aria-label={text('当前配额 ID', 'Current quota ID')} value={value} readOnly />}
    {list.error && <Alert type="error" message={text('真实配额列表读取失败；不会使用示例或更改草稿。', 'The actual quota list could not be read; no examples are used and the draft is unchanged.')}
      description={list.error} />}
    {!list.error && retained && <Alert type="warning" message={list.complete
      ? text('当前租户列表未返回此 ID，可能已删除或不可用。请选择已启用配额，或明确清空；原草稿仍保留。',
        'This ID was not returned by the current tenant list and may be deleted or unavailable. Select an enabled quota or explicitly clear it; the original draft is retained.')
      : text('原有 ID 尚未在已加载页中验证。继续加载或刷新核对，不会自动替换或清空。',
        'The existing ID is not verified in the loaded pages. Load more or refresh to verify it; it will not be replaced or cleared automatically.')} />}
    {current && !selectableQuota(current) && <Alert type="warning" message={text('关联配额已停用或身份/版本无效；保存时服务端会重新检查依赖。原 ID 保持不变，请明确选择有效规则。',
      'The linked quota is disabled or has an invalid identity/revision. The server rechecks dependencies on save. The original ID remains; explicitly select a valid rule.')} />}
    <Typography.Text type="secondary">{text(`已加载 ${list.rows.length} 条${list.total === null ? '' : `，当前响应共 ${list.total} 条`}；版本来自实际列表，分页不构成一致快照。`,
      `Loaded ${list.rows.length}${list.total === null ? '' : ` of ${list.total}`} actual quotas; revisions come from the list, and pagination is not a consistent snapshot.`)}</Typography.Text>
    {list.bounded && <Alert type="info" message={text('已达到 2,000 条浏览上限；未加载的 ID 状态未知。请到运行时配额规则核对。',
      'The 2,000-row browsing limit is reached; unloaded IDs remain unknown. Inspect them in Runtime quota rules.')} />}
    <Space wrap>
      <Button disabled={list.loading} onClick={list.refresh}>{text('刷新真实配额列表', 'Refresh actual quota list')}</Button>
      {list.canLoadMore && <Button disabled={list.loading || !!list.error} onClick={list.loadMore}>{text('加载更多配额', 'Load more quotas')}</Button>}
      <a href="/runtime#quota-rules" target="_blank" rel="noreferrer">{text('打开运行时配额规则（新标签页）', 'Open Runtime quota rules (new tab)')}</a>
    </Space>
  </Space>;
}

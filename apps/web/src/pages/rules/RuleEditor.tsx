import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Drawer, Input, Popconfirm, Space, Table, Tabs, message } from 'antd';
import { callApi } from '@/api/transport';
import { useScopedOperation } from '@/components/useScopedOperation';
import { newRequestId } from '@/utils/requestId';
import { formatDateTime } from '@/utils/format';
import { useAppLocale } from '@/app/AppLocaleProvider';

const TEMPLATE = `key: CUSTOM-UNIQUE
name: Custom sensitive marker
description: Replace the marker and samples with your organization policy.
domain: credential-leak
severity: high
kind: keyword
target: prompt
action: deny
enabled: true
rollout_percent: 0
detection:
  type: keyword
  any: ["INTERNAL_SECRET_MARKER"]
samples:
  positive: ["token=INTERNAL_SECRET_MARKER"]
  negative: ["hello world"]
author: tenant-admin
version: 1
`;
interface Revision { version: number; actor: string; changedAt: string; yaml: string }
interface CurrentRule { yaml: string; rule: { version: number }; canWrite: boolean }

export function RuleEditor({ ruleKey, canWrite, onClose, onSaved }: {
  ruleKey: string; canWrite: boolean; onClose: () => void; onSaved: () => void;
}) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const locale = useAppLocale();
  const [yaml, setYaml] = useState(() => TEMPLATE.replace('CUSTOM-UNIQUE', `CUSTOM-${newRequestId()}`));
  const [history, setHistory] = useState<Revision[]>([]);
  const [version, setVersion] = useState(0);
  const [serverWrite, setServerWrite] = useState(!ruleKey);
  const [loaded, setLoaded] = useState(!ruleKey);
  const [reload, setReload] = useState(0);
  const [tab, setTab] = useState('source');
  const [error, setError] = useState('');
  const operation = useScopedOperation();
  const writable = canWrite && serverWrite && loaded && !operation.busy;
  useEffect(() => {
    if (!ruleKey) return;
    let active = true;
    void Promise.all([
      callApi<CurrentRule>(`/api/v1/rules/${encodeURIComponent(ruleKey)}`, () => null as never, { noFallback: true }),
      callApi<{ items: Revision[] }>(`/api/v1/rules/${encodeURIComponent(ruleKey)}/versions`, () => ({ items: [] }), { noFallback: true }),
    ]).then(([current, revisions]) => {
      if (active) {
        setYaml(current.data.yaml); setVersion(current.data.rule.version); setServerWrite(current.data.canWrite === true);
        setHistory(revisions.data.items); setLoaded(true); setError('');
      }
    }).catch(e => { if (active) setError(String(e)); });
    return () => { active = false; };
  }, [ruleKey, reload]);

  const save = (restoreVersion?: number) => {
    if (!writable) return;
    void operation.run(async current => {
      setError('');
      try {
        if (restoreVersion === undefined) {
          await callApi('/api/v1/rules', () => null, {
            method: 'POST', noFallback: true,
            body: { yaml, expectedVersion: version, ...(ruleKey ? { sourceKey: ruleKey } : {}) },
          });
        } else {
          await callApi(`/api/v1/rules/${encodeURIComponent(ruleKey)}/versions/${restoreVersion}/restore?expectedVersion=${version}`,
            () => null, { method: 'POST', noFallback: true });
        }
        if (!current()) return;
        void message.success(zh ? '样本校验通过，规则新版本已保存。按启用状态和灰度比例生效。' : 'Samples passed and a new revision was saved. Enablement and rollout determine where it applies.');
        onSaved(); onClose();
      } catch (e) { if (current()) setError(String(e)); }
    });
  };
  const loadLatest = () => { setLoaded(false); setReload(value => value + 1); };
  return <Drawer open width={820} title={ruleKey
    ? `${zh ? '规则定义与版本' : 'Rule definition and revisions'}: ${ruleKey} · v${version}`
    : zh ? '新建检测规则' : 'New detection rule'} onClose={onClose}
    extra={<Space>
      {ruleKey && (loaded
        ? <Popconfirm title={zh ? '替换草稿为最新内容？请先复制需要保留的内容。' : 'Replace this draft with the latest revision? Copy any edits you need first.'} onConfirm={loadLatest}>
          <Button disabled={operation.busy}>{zh ? '加载最新版本' : 'Load latest revision'}</Button>
        </Popconfirm>
        : <Button disabled={operation.busy} onClick={loadLatest}>{zh ? '重新加载' : 'Retry loading'}</Button>)}
      <Button type="primary" aria-label={zh ? '校验样本并发布' : 'Validate and publish'}
        loading={operation.busy} disabled={!writable} onClick={() => save()}>{zh ? '校验样本并发布' : 'Validate and publish'}</Button>
    </Space>}>
    <Space direction="vertical" style={{ width: '100%' }} size="middle">
      <Alert type="info" showIcon message={zh ? '规则在当前租户内生效，发布与恢复均重新执行正负样本。' : 'Rules apply to the current tenant. Publishing and restoring rerun positive and negative samples.'}
        description={zh
          ? '已有规则的 key 不可修改。新规则默认灰度 0%；保存后运行样本，再按 5% → 25% → 100% 放量。版本冲突会保留草稿，请复制内容、加载最新版本并合并。'
          : 'Existing keys cannot change. New rules start at 0% rollout; run samples, then expand through 5%, 25% and 100%. Conflicts preserve your draft: copy it, load the latest revision and merge.'} />
      {(!canWrite || (loaded && !serverWrite)) && <Alert type="info" showIcon message={zh ? '当前账号只读：可查看定义和历史，发布、恢复及执行样本需要 rules:write 权限。' : 'Read-only access: inspect definitions and revisions. Publishing, restoring and running samples require rules:write.'} />}
      {error && <Alert type="error" showIcon message={zh ? '操作未完成，草稿已保留' : 'Operation failed; your draft is preserved'} description={error} />}
      <Tabs activeKey={tab} onChange={setTab} items={[
        { key: 'source', label: zh ? 'YAML 定义' : 'YAML definition', children: <Input.TextArea aria-label="Rule YAML" value={yaml}
          readOnly={!writable} disabled={!loaded} onChange={e => setYaml(e.target.value)}
          autoSize={{ minRows: 22, maxRows: 35 }} style={{ fontFamily: 'monospace' }} /> },
        { key: 'history', label: zh ? '版本历史' : 'Revision history', children: <Table rowKey="version" dataSource={[...history].reverse()} columns={[
          { title: zh ? '版本' : 'Version', dataIndex: 'version' }, { title: zh ? '操作人' : 'Actor', dataIndex: 'actor' },
          { title: zh ? '时间' : 'Time', dataIndex: 'changedAt', width: 178, render: value => formatDateTime(value, locale) },
          { title: zh ? '操作' : 'Actions', render: (_, row: Revision) => <Space>
            <Button disabled={operation.busy} onClick={() => { setYaml(row.yaml); setTab('source'); }}>{zh ? '查看内容' : 'View contents'}</Button>
            <Popconfirm title={zh ? '重新校验样本并从此内容发布新版本？' : 'Rerun samples and publish a new revision from these contents?'} onConfirm={() => save(row.version)} disabled={!writable}>
              <Button disabled={!writable}>{zh ? '恢复' : 'Restore'}</Button>
            </Popconfirm>
          </Space> },
        ]} /> },
      ]} />
    </Space>
  </Drawer>;
}

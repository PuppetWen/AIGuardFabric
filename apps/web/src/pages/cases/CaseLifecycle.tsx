import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Form, Input, Modal, Select, Space } from 'antd';
import { api, useApiQuery } from '@/api/client';
import { casesApi } from '@/api/cases';
import type { Case, Finding } from '@/types/domain';

export function CreateCase({ onChange, canWrite, prefillFinding, onClearPrefill, onCreated }: {
  onChange: () => void; canWrite: boolean; prefillFinding?: Finding; onClearPrefill?: () => void;
  onCreated?: (id: string) => void;
}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [error, setError] = useState('');
  const [form] = Form.useForm();
  const handledFinding = useRef<string | undefined>(undefined);
  const assets = useApiQuery('case-create-assets', () => api.assets({}, { keyword, pageSize: 100 }), { key: [keyword], enabled: open });
  useEffect(() => {
    if (!prefillFinding) { handledFinding.current = undefined; return; }
    if (!canWrite || handledFinding.current === prefillFinding.id) return;
    handledFinding.current = prefillFinding.id;
    form.setFieldsValue({ title: prefillFinding.title.slice(0, 200), summary: prefillFinding.summary.slice(0, 10000),
      severity: prefillFinding.severity,
      asset_ids: prefillFinding.canReadAsset && prefillFinding.assetId ? [prefillFinding.assetId] : [] });
    setOpen(true);
  }, [canWrite, form, prefillFinding]);
  return <>
    <Button type="primary" disabled={!canWrite} onClick={() => { form.resetFields(); setOpen(true); }}>{zh ? '新建案件' : 'New case'}</Button>
    <Modal open={open} title={zh ? '新建案件' : 'New case'} onCancel={() => { if (!busy) { setOpen(false); onClearPrefill?.(); } }} confirmLoading={busy}
      onOk={async () => { setBusy(true); setError(''); try {
        const values = await form.validateFields();
        const created = await casesApi.create({ ...values, finding_ids: prefillFinding ? [prefillFinding.id] : [] });
        setOpen(false); form.resetFields(); onClearPrefill?.(); onChange(); onCreated?.(created.data.case.id);
      } catch (cause) { if (cause instanceof Error) setError(cause.message); } finally { setBusy(false); } }}>
      {prefillFinding && <Alert type="info" showIcon style={{ marginBottom: 16 }}
        message={zh ? '已关联待复核发现；确认后才会创建案件' : 'Linked finding: review before creating the case'}
        description={`${prefillFinding.title} · ${prefillFinding.id}`} />}
      <Form form={form} layout="vertical" initialValues={{ severity: 'medium' }}>
        <Form.Item name="title" label={zh ? '标题' : 'Title'} rules={[{ required: true, whitespace: true, max: 200 }]}><Input /></Form.Item>
        <Form.Item name="summary" label={zh ? '摘要' : 'Summary'} rules={[{ max: 10000 }]}><Input.TextArea rows={3} /></Form.Item>
        <Form.Item name="severity" label={zh ? '严重等级' : 'Severity'}><Select options={['critical', 'high', 'medium', 'low', 'info'].map((value) => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="asset_ids" label={zh ? '关联资产' : 'Linked assets'}><Select mode="multiple" showSearch filterOption={false} onSearch={setKeyword}
          loading={assets.isLoading} options={assets.data?.data.items.map((asset) => ({ value: asset.id, label: asset.name }))} /></Form.Item>
        <Form.Item name="owner" label={zh ? '负责人' : 'Owner'}><Input /></Form.Item>
      </Form>
      {(error || assets.error) && <Alert type="error" message={error || String(assets.error)} />}
    </Modal>
  </>;
}

const transitions: Record<string, string[]> = { new: ['investigating'], triaged: ['containing', 'resolved'], containing: ['resolved'], recovered: ['investigating', 'closed'], closed: [] };
export function CaseLifecycle({ item, onChange, canWrite }: {item: Case; onChange: () => void; canWrite: boolean}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [form] = Form.useForm();
  const states = transitions[item.state] ?? [];
  const names: Record<string, string> = { investigating: '调查中', containing: '处置中', resolved: '已解决', closed: '关闭归档' };
  return <Space direction="vertical">
    <Button disabled={!canWrite || !states.length} onClick={() => { form.resetFields(); setOpen(true); }}>{zh ? '流转案件状态' : 'Change case state'}</Button>
    <Modal open={open} title={zh ? '流转案件状态' : 'Change case state'} onCancel={() => !busy && setOpen(false)} confirmLoading={busy}
      onOk={async () => { setBusy(true); setError(''); try { const values = await form.validateFields();
        await casesApi.state(item.id, values.state, values.resolution); setOpen(false); onChange();
      } catch (cause) { if (cause instanceof Error) setError(cause.message); } finally { setBusy(false); } }}>
      <Form form={form} layout="vertical"><Form.Item name="state" label={zh ? '目标状态' : 'Next state'} rules={[{ required: true }]}>
        <Select options={states.map((value) => ({ value, label: zh ? names[value] : value }))} /></Form.Item>
        <Form.Item name="resolution" label={zh ? '处置说明 / 结论' : 'Notes / resolution'} rules={[{ required: true, whitespace: true, max: 10000 }]}><Input.TextArea rows={4} /></Form.Item>
      </Form>{error && <Alert type="error" message={error} />}
    </Modal>
  </Space>;
}

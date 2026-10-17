import { useState } from 'react';
import { Alert, Button, Form, Input, Modal, Popconfirm, Select, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/transport';
import type { Skill } from '@/types/domain';

import { skillLifecycleLabel } from './skillLifecycle';
interface Values { to?: string; owner?: string; department?: string; dataClass?: string; note?: string;
  domains?: string[]; paths?: string[] }
interface Props { skill: Skill; mode: 'review' | 'allowlist'; canWrite: boolean; onClose: () => void; onSaved: () => void }

export function SkillReviewModal({ skill, mode, canWrite, onClose, onSaved }: Props) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [current, setCurrent] = useState(skill);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [form] = Form.useForm<Values>();
  const review = current.review;
  const archived = review?.lifecycle === 'archived' || review?.lifecycle === 'rejected';
  const writable = canWrite && Boolean(review?.updatedAt) && !archived
    && (mode === 'allowlist' || Boolean(review?.allowedNext.length));
  const values = (row: Skill): Values => ({
    to: row.review?.allowedNext[0], owner: row.review?.owner ?? '', department: row.review?.department ?? '',
    dataClass: row.review?.dataClass ?? 'internal', note: '', domains: row.whitelist.domains, paths: row.whitelist.paths,
  });
  const reload = async () => {
    setBusy(true);
    try {
      const result = await callApi<{ skill: Skill }>(`/api/v1/skills/${current.id}`, () => null as never, { noFallback: true });
      setCurrent(result.data.skill); form.setFieldsValue(values(result.data.skill));
      setError(''); setConflict(false);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const save = async (fields: Values) => {
    if (!writable || !review) return;
    setBusy(true); setError(''); setConflict(false);
    try {
      await callApi(`/api/v1/skills/${current.id}/${mode === 'review' ? 'status' : 'whitelist'}`, () => null, {
        method: mode === 'review' ? 'POST' : 'PUT', noFallback: true,
        body: mode === 'review' ? { to: fields.to, owner: fields.owner?.trim(), department: fields.department?.trim(),
          data_class: fields.dataClass, note: fields.note?.trim(), expected_updated_at: review.updatedAt }
          : { domains: fields.domains ?? [], paths: fields.paths ?? [], expected_updated_at: review.updatedAt },
      });
      onSaved(); onClose();
    } catch (cause) {
      setConflict(cause instanceof ApiRequestError && cause.status === 409);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };
  return <Modal open width={620} title={`${text(mode === 'review' ? 'Skill 评审' : '声明白名单',
    mode === 'review' ? 'Review Skill' : 'Declared allowlist')} · ${current.name}`}
    onCancel={() => { if (!busy) onClose(); }} maskClosable={!busy} confirmLoading={busy}
    okButtonProps={{ disabled: !writable || conflict }} onOk={() => form.submit()}
    okText={text('保存', 'Save')} cancelText={text('关闭', 'Close')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Text>{text('当前生命周期：', 'Current lifecycle: ')}
        {review ? skillLifecycleLabel(review.lifecycle, zh) : text('未知，请刷新', 'Unknown; refresh required')}</Typography.Text>
      {!writable && <Alert type="info" showIcon message={text('当前记录只读。请检查写权限、生命周期和服务版本。',
        'This record is read-only. Check write access, lifecycle and server version.')} />}
      {error && <Alert type="error" showIcon message={error} description={text('草稿已保留。核对当前记录后再保存。',
        'Your draft is retained. Compare the current record before saving again.')} />}
      {conflict && <Popconfirm title={text('丢弃当前草稿并加载最新内容？', 'Discard this draft and load the latest values?')}
        onConfirm={() => void reload()}>
        <Button disabled={busy}>{text('加载最新版本', 'Load latest version')}</Button>
      </Popconfirm>}
      <Alert type="info" showIcon message={text('评审和白名单维护台账声明，不会自动安装、停止应用或执行出网拦截。',
        'Reviews and allowlists update inventory declarations. They do not install or stop applications or automatically enforce egress controls.')} />
    </Space>
    <Form form={form} layout="vertical" initialValues={values(skill)} onFinish={fields => void save(fields)}
      disabled={!writable || busy || conflict} style={{ marginTop: 16 }}>
      {mode === 'review' ? <>
        <Form.Item name="to" label={text('目标状态', 'Target state')} rules={[{ required: true }]}>
          <Select options={review?.allowedNext.map(value => ({ value, label: skillLifecycleLabel(value, zh) }))} /></Form.Item>
        <Form.Item name="owner" label={text('负责人', 'Owner')} rules={[{ required: true, whitespace: true }]}>
          <Input maxLength={80} /></Form.Item>
        <Form.Item name="department" label={text('部门', 'Department')}><Input maxLength={80} /></Form.Item>
        <Form.Item name="dataClass" label={text('数据分级', 'Data classification')} rules={[{ required: true }]}>
          <Select options={['public', 'internal', 'confidential', 'restricted'].map((value, i) => ({
            value, label: zh ? ['公开', '内部', '机密', '严格受限'][i] : value,
          }))} /></Form.Item>
        <Form.Item name="note" label={text('评审说明', 'Review note')} rules={[{ required: true, whitespace: true }]}>
          <Input.TextArea rows={3} maxLength={600} /></Form.Item>
      </> : <>
        <Form.Item name="domains" label={text('域名（回车添加）', 'Domains (press Enter to add)')}>
          <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="api.example.com, *.example.com" /></Form.Item>
        <Form.Item name="paths" label={text('绝对路径（回车添加，保留空格）', 'Absolute paths (press Enter; spaces are preserved)')}>
          <Select mode="tags" placeholder="C:\Program Files\Tools\* /srv/data" /></Form.Item>
        <Typography.Paragraph type="secondary">{text('每类最多 100 条；域名不含协议、端口或路径，支持前缀 *.。路径须为绝对路径且不含 ..。保存两个空列表会清空声明。',
          'Up to 100 entries per list. Domains have no scheme, port or path; a leading *. is supported. Paths must be absolute without .. segments. Saving two empty lists clears the declaration.')}</Typography.Paragraph>
      </>}
    </Form>
  </Modal>;
}

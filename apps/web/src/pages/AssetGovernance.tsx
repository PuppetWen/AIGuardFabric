import { useState } from 'react';
import { Alert, Button, Collapse, Form, Input, Modal, Select, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/transport';
import type { AssetProfile } from '@/types/domain';
import { AssetPackageObservation } from './AssetPackageObservation';
import { AssetEdrBinding } from './AssetEdrBinding';
import { AssetIamBinding } from './AssetIamBinding';
import { AssetMetadataEditor } from './AssetMetadataEditor';
import { AssetRemoval } from './AssetRemoval';

interface Review { to: string; owner: string; department: string; dataClass: string; note: string }
const STATES: Record<string, [string, string]> = {
  requested: ['申请中', 'Requested'], 'under-review': ['评审中', 'Under review'], trial: ['试用', 'Trial'],
  production: ['生产', 'Production'], changing: ['变更中', 'Changing'], archived: ['归档', 'Archived'], rejected: ['拒绝', 'Rejected'],
};

export function AssetGovernance({ profile, onSaved, onRemoved }: {
  profile: AssetProfile; onSaved: () => Promise<void>; onRemoved: () => Promise<void>
}) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const stateLabel = (state: string) => STATES[state]?.[zh ? 0 : 1] ?? state;
  const fieldLabels: Record<string, string> = {
    skill_package_sha256: text('Skill 目录内容变化', 'Skill directory content changed'),
    skill_package_observation: text('Skill 目录观察状态', 'Skill directory observation'),
  };
  const hashStatuses: Record<string, string> = {
    unreadable: text('读取失败', 'Read failed'), 'too-large': text('超过 4 MiB', 'Over 4 MiB'),
    'not-regular-file': text('不是普通文件', 'Not a regular file'),
    'changed-during-read': text('读取期间文件变化', 'File changed during reading'),
  };
  const [form] = Form.useForm<Review>();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [expected, setExpected] = useState('');
  const governance = profile.governance;
  const begin = () => {
    if (!governance) return;
    setExpected(governance.updatedAt);
    form.setFieldsValue({to: governance.allowedNext[0], owner: governance.owner ?? '',
      department: governance.department ?? '', dataClass: governance.dataClass, note: ''});
    setError(''); setOpen(true);
  };
  const save = async (values: Review) => {
    setBusy(true); setError('');
    try {
      await callApi(`/api/v1/assets/${profile.asset.id}/transition`, () => null, {method: 'POST', noFallback: true,
        body: {to: values.to, owner: values.owner.trim(), department: values.department.trim(),
          data_class: values.dataClass, note: values.note.trim(), expected_updated_at: expected}});
      setOpen(false);
      await onSaved();
    } catch (cause) {
      setError(cause instanceof ApiRequestError && cause.status === 409
        ? text('资产已被更新，请核对最新内容后重新评审。', 'This asset has changed. Review the latest values before saving again.')
        : cause instanceof Error ? cause.message : String(cause));
    }
    finally { setBusy(false); }
  };
  return <div className="agf-drawer-section">
    <Space direction="vertical" style={{width: '100%'}}>
      <Typography.Title level={5}>{text('资产治理与变更记录', 'Governance and change history')}</Typography.Title>
      {governance && <Typography.Text>{text('实际生命周期：', 'Lifecycle: ')}{stateLabel(governance.lifecycle)}</Typography.Text>}
      {profile.contentObservation?.receivedAt && <div>
        <Typography.Text strong>{text('最近文件内容观察', 'Latest file content observation')}</Typography.Text>
        <div>{text('平台接收时间：', 'Received: ')}{new Date(profile.contentObservation.receivedAt).toLocaleString(zh ? 'zh-CN' : 'en-US')}</div>
        {profile.contentObservation.sha256
          ? <Typography.Paragraph copyable style={{ overflowWrap: 'anywhere' }}>SHA-256: {profile.contentObservation.sha256}</Typography.Paragraph>
          : <Typography.Paragraph type="warning">{text('本次未取得内容哈希：', 'Content hash unavailable: ')}{hashStatuses[profile.contentObservation.status ?? ''] ?? profile.contentObservation.status}</Typography.Paragraph>}
        <Typography.Text type="secondary">{text('这是最近一次上报的观察结果，不能证明文件此刻未发生变化。',
          'This is the latest reported observation; it does not prove the file is unchanged now.')}</Typography.Text>
      </div>}
      <AssetPackageObservation observation={profile.packageObservation} />
      <AssetMetadataEditor profile={profile} onSaved={onSaved} />
      <AssetEdrBinding profile={profile} onSaved={onSaved} />
      <AssetIamBinding profile={profile} onSaved={onSaved} />
      <AssetRemoval profile={profile} onRemoved={onRemoved} />
      {governance?.canWrite && governance.allowedNext.length > 0 &&
        <Button onClick={begin}>{text('评审与生命周期', 'Review lifecycle')}</Button>}
      <Typography.Paragraph type="secondary">{text('归档和拒绝是台账终态；不会停止外部应用或撤销凭据。需要阻断时使用运行时防护，停用对应端点或撤销 API Key。',
        'Archived and rejected are final inventory states. They do not stop external applications or revoke credentials. Use runtime controls, disable the endpoint or revoke its API key when access must stop.')}</Typography.Paragraph>
      <Collapse items={[{key:'history', label:text(`最近变更（${profile.changes?.length ?? 0}）`, `Recent changes (${profile.changes?.length ?? 0})`), children:
        <Space direction="vertical" style={{width:'100%'}}>{(profile.changes ?? []).map(change => <div key={change.id}>
          <Typography.Text strong>{change.field === 'lifecycle' ? text('生命周期','Lifecycle')
            : change.changeKind === 'added' ? text('发现登记','Discovered') : fieldLabels[change.field ?? ''] ?? change.field ?? change.changeKind}</Typography.Text>{' '}
          <Typography.Text type="secondary">{new Date(change.detectedAt).toLocaleString(zh ? 'zh-CN' : 'en-US')}</Typography.Text>
          {change.oldValue !== undefined && <div>{typeof change.oldValue === 'string' ? stateLabel(change.oldValue) : JSON.stringify(change.oldValue)}
            {' → '}{typeof change.newValue === 'string' ? stateLabel(change.newValue) : JSON.stringify(change.newValue)}</div>}
          {change.riskNote && <Typography.Paragraph>{change.riskNote}</Typography.Paragraph>}
        </div>)}</Space>}]} />
    </Space>
    <Modal open={open} title={text('评审与生命周期', 'Review lifecycle')} confirmLoading={busy}
      onCancel={() => {if (!busy) setOpen(false);}} onOk={() => form.submit()}
      okText={text('保存评审', 'Save review')} cancelText={text('取消', 'Cancel')} maskClosable={!busy}>
      {error && <Alert type="error" showIcon message={error} description={text('输入已保留。关闭表单后刷新详情，比较最新值再重新打开评审。',
        'Your draft is retained. Close the form, refresh the detail, compare current values and open the review again.')} />}
      <Form name="asset-governance" form={form} layout="vertical" onFinish={values => void save(values)} disabled={busy}>
        <Form.Item name="to" label={text('目标状态', 'Target state')} rules={[{required:true}]}>
          <Select options={governance?.allowedNext.map(value => ({value,label:stateLabel(value)}))} /></Form.Item>
        <Form.Item name="owner" label={text('负责人', 'Owner')} rules={[{required:true,whitespace:true}]}>
          <Input maxLength={80}/></Form.Item>
        <Form.Item name="department" label={text('部门', 'Department')}><Input maxLength={80}/></Form.Item>
        <Form.Item name="dataClass" label={text('数据分级', 'Data classification')} rules={[{required:true}]}>
          <Select options={['public','internal','confidential','restricted'].map((value,index)=>({value,
            label:zh ? ['公开','内部','机密','严格受限'][index] : value}))}/></Form.Item>
        <Form.Item name="note" label={text('评审说明', 'Review note')} rules={[{required:true,whitespace:true}]}>
          <Input.TextArea rows={3} maxLength={600}/></Form.Item>
      </Form>
    </Modal>
  </div>;
}

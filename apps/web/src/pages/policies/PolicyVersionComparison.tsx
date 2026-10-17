import { Alert, Button, Col, Input, Popconfirm, Row, Space, Typography } from 'antd';
import type { Policy } from '@/types/domain';
import { validPolicyVersion } from '@/api/policies';
import { isPolicyAction } from '@/api/policyActions';
import { usePolicyText } from './usePolicyText';

function policySnapshot(policy: Partial<Policy>) {
  return { version: policy.version, name: policy.name, description: policy.description, language: policy.codeLanguage,
    code: policy.code ?? null, expression: policy.expression, action: policy.action, priority: policy.priority, interceptPoints: policy.interceptPoints,
    scopeAgentIds: policy.scopeAgentIds, scopeDepartments: policy.scopeDepartments, quotaId: policy.quotaId,
    degradeEndpointId: policy.degradeEndpointId, enabled: policy.enabled, dryRun: policy.dryRun };
}
export function PolicyVersionComparison({ draft, draftError, latest, busy, canAdopt, onAdopt }: {
  draft: Partial<Policy>; draftError?: string; latest: Policy; busy: boolean; canAdopt: boolean; onAdopt: () => void;
}) {
  const text = usePolicyText();
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('比较策略版本', 'Compare policy revisions')}</Typography.Title>
    <Alert type="info" message={text('读取仅供比较，不会改草稿、保存版本或自动发布。采纳会替换整份草稿，之后仍须手动保存。',
      'Reading only compares; it never changes the draft, save revision or publication. Adopting replaces the whole draft; save manually afterward.')} />
    {draftError && <Alert type="warning" showIcon message={draftError} />}
    <Row gutter={[12, 12]} style={{ width: '100%' }}>
      <Col xs={24} md={12}><Typography.Text strong>{text('当前草稿（可复制）', 'Current draft (copyable)')}</Typography.Text>
        <Input.TextArea readOnly rows={12} aria-label={text('当前策略草稿', 'Current policy draft')} value={JSON.stringify(policySnapshot(draft), null, 2)} /></Col>
      <Col xs={24} md={12}><Typography.Text strong>{text(`服务端版本 v${latest.version ?? '未知'}`, `Server revision v${latest.version ?? 'unknown'}`)}</Typography.Text>
        <Input.TextArea readOnly rows={12} aria-label={text('最新服务端策略', 'Latest server policy')} value={JSON.stringify(policySnapshot(latest), null, 2)} /></Col>
    </Row>
    {!validPolicyVersion(latest.version) && <Alert type="warning" message={text('服务端未提供有效版本，不能发布。', 'The server supplied no valid revision; publication is unavailable.')} />}
    {!isPolicyAction(latest.action) && <Alert type="warning" message={text(
      `最新策略动作 ${latest.rawAction ?? latest.action} 无法识别，不能采纳或发布。请核对服务端与客户端版本。`,
      `Latest policy action ${latest.rawAction ?? latest.action} is unknown; adoption and publication are blocked. Verify the server and client versions.`,
    )} />}
    <Popconfirm title={text('替换当前草稿和保存版本？', 'Replace the draft and save revision?')}
      description={text('请先复制需要保留的改动。只替换本地编辑内容，不会发布。', 'Copy any changes you need first. This replaces local editing content without publishing.')}
      okText={text('确认采纳最新策略', 'Confirm adopting latest policy')} onConfirm={onAdopt}>
      <Button disabled={busy || !canAdopt || !validPolicyVersion(latest.version) || !isPolicyAction(latest.action)}>{text('明确采纳最新策略', 'Adopt latest policy explicitly')}</Button>
    </Popconfirm>
  </Space>;
}

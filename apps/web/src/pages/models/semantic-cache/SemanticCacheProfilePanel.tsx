import { Alert, Button, Popconfirm, Space, Switch, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { Panel } from '@/components/Panel';
import { SemanticProfileFields } from './SemanticProfileFields';
import { SemanticProfileGuide } from './SemanticProfileGuide';
import { useSemanticProfile } from './useSemanticProfile';

export function SemanticCacheProfilePanel() {
  const scope = useAuthStore(state => `${state.tenant?.id}:${state.sessionGeneration}`);
  return <ScopedProfile key={scope} />;
}
function ScopedProfile() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess();
  const canRead = access.has('models:read'), canWrite = access.has('models:write');
  const state = useSemanticProfile(canRead, canWrite);
  return <Panel title={text('语义缓存', 'Semantic cache')} extra={<Button disabled={!canRead || state.busy}
    onClick={() => void state.read()}>{text('读取当前配置', 'Read current configuration')}</Button>}>
    <Space direction="vertical" style={{ width: '100%' }} size={12}>
      <SemanticProfileGuide />
      {!canRead && <Alert type="info" message={text('需要模型读取权限才能查看配置。', 'Model read permission is required to view configuration.')} />}
      {state.error && <Alert type="error" showIcon message={state.error} />}
      {state.current && <Space wrap>
        <Tag>{text('服务器当前版本', 'Current server version')}: {state.current.version}</Tag>
        <Tag color={state.current.enabled ? 'blue' : 'default'}>{state.current.enabled ? text('配置已启用', 'Configuration enabled') : text('配置已停用', 'Configuration disabled')}</Tag>
        <Typography.Text type="secondary">{text('当前端点部署与厂商权重版本仍需逐次核验。',
          'Endpoint placement and provider weight revision are not verified by this configuration view.')}</Typography.Text>
      </Space>}
      {state.blocked && <Alert type="warning" showIcon message={state.blocked === 'conflict'
        ? text('版本已改变，草稿与原保存版本已保留。', 'The version changed. Your draft and original expected version are retained.')
        : text('保存结果尚未确认，请读取当前配置；不会自动重试。', 'The save result is unknown. Read the current configuration; no retry is automatic.')}
        description={text('当前配置的读取结果不等于原保存请求的回执。', 'Reading current configuration does not recover a receipt for the original save request.')} />}
      <Space wrap>
        <Switch aria-label={text('启用语义缓存配置', 'Enable semantic cache configuration')} checked={state.draft.enabled}
          disabled={!canWrite || state.busy || Boolean(state.blocked) || state.baseline === undefined} onChange={state.setEnabled} />
        <Typography.Text>{text('启用语义缓存配置', 'Enable semantic cache configuration')}</Typography.Text>
        <Tag>{text('草稿保存基于版本', 'Draft expected version')}: {state.baseline ?? '—'}</Tag>
      </Space>
      {state.draft.settings && <SemanticProfileFields settings={state.draft.settings} endpoints={state.endpoints}
        disabled={!canWrite || state.busy || Boolean(state.blocked)} update={state.updateSettings} />}
      <Space wrap>
        <Button type="primary" loading={state.busy} disabled={!canWrite || Boolean(state.blocked) || state.baseline === undefined}
          onClick={() => void state.save()}>{text('保存缓存配置', 'Save cache configuration')}</Button>
        <Popconfirm title={text('丢弃草稿并采用已读取的服务器当前配置？', 'Discard your draft and adopt the server configuration you read?')}
          onConfirm={state.adoptCurrent}>
          <Button disabled={!canWrite || state.busy || !state.current || (Boolean(state.blocked) && !state.readAfterSave)}>
            {text('采用当前配置', 'Adopt current configuration')}</Button>
        </Popconfirm>
      </Space>
    </Space>
  </Panel>;
}

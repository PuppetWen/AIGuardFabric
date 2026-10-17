import { Alert, Button, Input, Popconfirm, Space } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { Panel } from '@/components/Panel';
import { SettlementGuide } from './SettlementGuide';
import { SettlementReceipt } from './SettlementReceipt';
import { useSettlement } from './useSettlement';
import { validAttempt } from './validation';

export function GatewaySettlementPanel() {
  const scope = useAuthStore(state => `${state.tenant?.id}:${state.tenant?.slug}:${state.sessionGeneration}`);
  return <ScopedSettlement key={scope} />;
}
function ScopedSettlement() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess(), canRead = access.has('models:read'), canWrite = access.has('models:write');
  const flow = useSettlement(canRead, canWrite);
  return <Panel title={text('模型费用结算与本地恢复', 'Model settlement and local recovery')}>
    <Space direction="vertical" style={{ width: '100%' }} size={12}>
      <SettlementGuide />
      {!canRead && <Alert type="info" message={text('需要模型读取权限。', 'Model read permission is required.')} />}
      <Input aria-label={text('原模型请求编号', 'Original model attempt ID')} maxLength={36} value={flow.attempt}
        disabled={!canRead || flow.busy || flow.unknown} onChange={event => flow.changeAttempt(event.target.value)}
        placeholder={text('粘贴 x-agf-attempt-id 实际 UUID', 'Paste the actual x-agf-attempt-id UUID')} />
      <Space wrap>
        <Button loading={flow.reading} disabled={!canRead || !validAttempt(flow.attempt)} onClick={() => void flow.read()}>
          {text('读取原结算回执', 'Read original settlement')}</Button>
        <Popconfirm title={text('仅在本地提交原编号已知费用与审计？不会重新调用模型。',
          'Publish known costs and audit locally for this original ID? No model is called again.')}
          onConfirm={() => void flow.recover()}>
          <Button type="primary" loading={flow.busy} disabled={!flow.canRecover}>
            {text('恢复本地结算', 'Recover local settlement')}</Button>
        </Popconfirm>
      </Space>
      {flow.unknown && <Alert type="warning" showIcon message={text('恢复结果尚未确认。保留原编号并读取，404 不解锁。',
        'Recovery result is unconfirmed. Keep the original ID and read; HTTP 404 does not unlock.')} />}
      {flow.error && <Alert type="error" showIcon message={flow.error} />}
      {flow.receipt && <SettlementReceipt value={flow.receipt} />}
    </Space>
  </Panel>;
}

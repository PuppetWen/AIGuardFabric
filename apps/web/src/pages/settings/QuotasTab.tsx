import { useTranslation } from 'react-i18next';
import { useEffect, useRef, useState } from 'react';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';

import { Alert, Button, Form, InputNumber, Popconfirm, message } from 'antd';
import type { FormInstance } from 'antd';
import { SaveOutlined } from '@ant-design/icons';

import { Panel } from '@/components/Panel';
import type { QuotaDefaults, Tenant } from '@/types/domain';

interface QuotasTabProps {
  quotaForm: FormInstance<QuotaDefaults>;
  tenant: Tenant | undefined;
  canWrite: boolean;
  reload: () => Promise<Tenant | undefined>;
}

/** Tenant-wide default token / concurrency quotas. */
export function QuotasTab({ quotaForm, tenant, canWrite, reload }: QuotasTabProps) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [errorText, setErrorText] = useState('');
  const version = useRef(tenant?.quotaDefaults.version ?? 0);
  useEffect(() => {
    if (tenant && !conflict) { quotaForm.setFieldsValue(tenant.quotaDefaults); version.current = tenant.quotaDefaults.version; }
  }, [tenant, quotaForm, conflict]);

  return (
    <Panel>
      {errorText && <Alert type="error" showIcon message={errorText} style={{ marginBottom: 12 }}
        description={conflict ? (zh ? '草稿已保留。请先复制要保留的修改，再确认加载最新配额。'
          : 'Your draft is retained. Copy changes you need before loading the latest quotas.') : undefined} />}
      {conflict && <Popconfirm title={zh ? '丢弃草稿并加载最新配额？' : 'Discard this draft and load the latest quotas?'}
        onConfirm={async () => {
          try {
            const latest = await reload();
            if (!latest) throw new Error(zh ? '未找到最新配额' : 'Latest quotas were not found');
            quotaForm.setFieldsValue(latest.quotaDefaults);
            version.current = latest.quotaDefaults.version;
            setConflict(false);
            setErrorText('');
          } catch (failure) {
            setErrorText(failure instanceof Error ? failure.message : (zh ? '加载失败' : 'Reload failed'));
          }
        }}>
        <Button style={{ marginBottom: 12 }}>{zh ? '加载最新配额' : 'Load latest quotas'}</Button>
      </Popconfirm>}
      <Form<QuotaDefaults> form={quotaForm} disabled={!canWrite || saving} layout="vertical" initialValues={tenant?.quotaDefaults} onFinish={async values => {
        if (!canWrite || conflict || !tenant) return;
        setSaving(true);
        setErrorText('');
        try {
          const saved = await settingsApi.saveQuotas(values, version.current);
          version.current = saved.data.version;
          await reload();
          message.success(t('settings.quotas.saved'));
        } catch (error) {
          setConflict(error instanceof ApiRequestError && error.status === 409);
          setErrorText(error instanceof Error ? error.message : (zh ? '保存失败' : 'Save failed'));
        }
        finally { setSaving(false); }
      }}>
        <p>以下配额用于模型网关调用，保存后立即生效。Token 配额为 0 表示不限；调用前按输入和 max_tokens 预留，完成后结算。未提供 Agent ID 的请求共用未分配组。</p>
        <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))' }}>
          <Form.Item name="tenantTokensPerDay" label={t('settings.quotas.tenantTokens')}>
            <InputNumber min={0} step={1_000_000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="agentTokensPerHour" label={t('settings.quotas.agentTokens')}>
            <InputNumber min={0} step={100_000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="sessionTokensPerTurn" label={t('settings.quotas.sessionTokens')}>
            <InputNumber min={0} step={1_000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="maxConcurrentSessions" label={t('settings.quotas.concurrentSessions')}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
        </div>
        <Button
          type="primary"
          icon={<SaveOutlined />}
          htmlType="submit" loading={saving} disabled={!canWrite || !tenant || conflict}
        >
          {t('common.save')}
        </Button>
      </Form>
    </Panel>
  );
}

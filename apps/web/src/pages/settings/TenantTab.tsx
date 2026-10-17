import { useTranslation } from 'react-i18next';
import { useEffect, useRef, useState } from 'react';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';

import { Alert, Button, ColorPicker, Form, Input, Popconfirm, Select, Space, Typography, message } from 'antd';
import type { FormInstance } from 'antd';
import { SaveOutlined } from '@ant-design/icons';

import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { Tenant } from '@/types/domain';

interface TenantTabProps {
  loading: boolean;
  error: unknown;
  tenantForm: FormInstance<Tenant>;
  tenant: Tenant | undefined;
  canWrite: boolean;
  reload: () => Promise<Tenant | undefined>;
}

/** Tenant identity and white-label branding. */
export function TenantTab({ loading, error, tenantForm, tenant, canWrite, reload }: TenantTabProps) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [errorText, setErrorText] = useState('');
  const version = useRef(tenant?.version ?? 0);
  useEffect(() => {
    if (tenant && !conflict) { tenantForm.setFieldsValue(tenant); version.current = tenant.version; }
  }, [tenant, tenantForm, conflict]);

  return (
    <DataState loading={loading} error={error}>
      <Panel>
        {errorText && <Alert type="error" showIcon message={errorText} style={{ marginBottom: 12 }}
          description={conflict ? (zh ? '草稿已保留。复制要保留的修改，再确认加载最新企业资料。'
            : 'Your draft is retained. Copy changes you need before loading the latest organization profile.') : undefined} />}
        {conflict && <Popconfirm title={zh ? '丢弃草稿并加载最新企业资料？' : 'Discard this draft and load the latest profile?'}
          onConfirm={async () => {
            try {
              const latest = await reload();
              if (!latest) throw new Error(zh ? '未找到最新企业资料' : 'Latest organization profile was not found');
              tenantForm.setFieldsValue(latest);
              version.current = latest.version;
              setConflict(false);
              setErrorText('');
            } catch (failure) {
              setErrorText(failure instanceof Error ? failure.message : (zh ? '加载失败' : 'Reload failed'));
            }
          }}>
          <Button style={{ marginBottom: 12 }}>{zh ? '加载最新企业资料' : 'Load latest profile'}</Button>
        </Popconfirm>}
        <Form<Tenant> form={tenantForm} disabled={!canWrite || saving} layout="vertical" initialValues={tenant} onFinish={async values => {
          if (!canWrite || conflict || !tenant) return;
          setSaving(true);
          setErrorText('');
          try {
            const saved = await settingsApi.saveTenant(values, version.current);
            version.current = saved.data.version;
            useAuthStore.getState().setTenant(saved.data);
            await reload();
            message.success(t('settings.tenant.saved'));
          } catch (failure) {
            setConflict(failure instanceof ApiRequestError && failure.status === 409);
            setErrorText(failure instanceof Error ? failure.message : (zh ? '保存失败' : 'Save failed'));
          }
          finally { setSaving(false); }
        }}>
          <Space direction="vertical" size={0} style={{ width: '100%' }}>
            <Typography.Title level={5}>{t('settings.tab.tenant')}</Typography.Title>
            <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', width: '100%' }}>
              <Form.Item name="name" label={t('settings.tenant.name')}>
                <Input />
              </Form.Item>
              <Form.Item name="slug" label={t('settings.tenant.slug')}>
                <Input disabled />
              </Form.Item>
              <Form.Item name="plan" label={t('settings.tenant.plan')}>
                <Select
                  options={['community', 'standard', 'enterprise'].map((value) => ({
                    value,
                    label: value,
                  }))}
                />
              </Form.Item>
              <Form.Item name="region" label={t('settings.tenant.region')}>
                <Select
                  options={['cn-hangzhou', 'cn-shanghai', 'cn-beijing'].map((value) => ({
                    value,
                    label: value,
                  }))}
                />
              </Form.Item>
            </div>

            <Typography.Title level={5}>{t('settings.tenant.whiteLabel')}</Typography.Title>
            <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', width: '100%' }}>
              <Form.Item name={['whiteLabel', 'productName']} label={t('settings.tenant.productName')}>
                <Input />
              </Form.Item>
              <Form.Item name={['whiteLabel', 'logoText']} label={t('settings.tenant.logoText')}>
                <Input maxLength={4} />
              </Form.Item>
              <Form.Item name={['whiteLabel', 'primaryColor']} label={t('settings.tenant.primaryColor')}
                getValueFromEvent={color => color.toHexString()}>
                <ColorPicker showText format="hex" />
              </Form.Item>
            </div>
            <Button
              type="primary"
              icon={<SaveOutlined />}
              htmlType="submit" loading={saving} disabled={!canWrite || !tenant || conflict}
            >
              {t('common.save')}
            </Button>
          </Space>
        </Form>
      </Panel>
    </DataState>
  );
}

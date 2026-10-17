import { useTranslation } from 'react-i18next';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';

import { Alert, Button, Descriptions, Form, InputNumber, Popconfirm, Switch, message } from 'antd';
import type { FormInstance } from 'antd';
import { SaveOutlined } from '@ant-design/icons';

import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { PasswordPolicy } from '@/types/domain';

interface PasswordTabProps {
  loading: boolean;
  error: unknown;
  policyForm: FormInstance<PasswordPolicy>;
  policy: PasswordPolicy | undefined;
  canWrite: boolean;
  reload: () => Promise<PasswordPolicy | undefined>;
}

/** Tenant password policy and MFA enforcement. */
export function PasswordTab({ loading, error, policyForm, policy, canWrite, reload }: PasswordTabProps) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [errorText, setErrorText] = useState('');
  const version = useRef(policy?.version ?? 0);
  useEffect(() => {
    if (policy && !conflict) { policyForm.setFieldsValue(policy); version.current = policy.version; }
  }, [policy, policyForm, conflict]);

  return (
    <DataState loading={loading} error={error}>
      <Panel>
        {errorText && <Alert type="error" showIcon message={errorText} style={{ marginBottom: 12 }}
          description={conflict ? (zh ? '草稿已保留。请先复制需要保留的修改，再确认加载最新口令策略。'
            : 'Your draft is retained. Copy changes you need before loading the latest password policy.') : undefined} />}
        {conflict && <Popconfirm title={zh ? '丢弃草稿并加载最新口令策略？' : 'Discard this draft and load the latest password policy?'}
          onConfirm={async () => {
            try {
              const latest = await reload();
              if (!latest) throw new Error(zh ? '未找到最新口令策略' : 'Latest password policy was not found');
              policyForm.setFieldsValue(latest);
              version.current = latest.version;
              setConflict(false);
              setErrorText('');
            } catch (failure) {
              setErrorText(failure instanceof Error ? failure.message : (zh ? '加载失败' : 'Reload failed'));
            }
          }}>
          <Button style={{ marginBottom: 12 }}>{zh ? '加载最新口令策略' : 'Load latest password policy'}</Button>
        </Popconfirm>}
        <Form<PasswordPolicy>
          form={policyForm}
          disabled={!canWrite || saving}
          layout="vertical"
          initialValues={policy}
          onFinish={async values => {
            if (!canWrite || conflict || !policy) return;
            setSaving(true);
            setErrorText('');
            try {
              const saved = await settingsApi.savePasswordPolicy(values, version.current);
              version.current = saved.data.version;
              await reload();
              message.success(t('settings.password.saved'));
            } catch (failure) {
              setConflict(failure instanceof ApiRequestError && failure.status === 409);
              setErrorText(failure instanceof Error ? failure.message : (zh ? '保存失败' : 'Save failed'));
            }
            finally { setSaving(false); }
          }}
        >
          <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
            <Form.Item name="minLength" label={t('settings.password.minLength')}>
              <InputNumber min={8} max={128} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="maxAgeDays" label={t('settings.password.maxAge')}>
              <InputNumber min={0} max={365} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="historySize" label={t('settings.password.history')}>
              <InputNumber min={0} max={24} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="lockoutThreshold" label={t('settings.password.lockout')}>
              <InputNumber min={1} max={20} style={{ width: '100%' }} />
            </Form.Item>
          </div>
          <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
            <Form.Item name="requireClasses" label="大小写、数字、符号至少三类" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="requireUppercase" label={t('settings.password.requireUppercase')} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="requireLowercase" label={t('settings.password.requireLowercase')} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="requireDigit" label={t('settings.password.requireDigit')} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="requireSymbol" label={t('settings.password.requireSymbol')} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="mfaEnforced" label={t('settings.password.mfa')} valuePropName="checked">
              <Switch />
            </Form.Item>
          </div>
          <Descriptions size="small" column={1}>
            <Descriptions.Item
              label={t('settings.password.ruleHint', { min: policy?.minLength ?? 12 })}
            >
              <span className="agf-mono">
                min={policy?.minLength} upper={String(policy?.requireUppercase)}{' '}
                digit={String(policy?.requireDigit)} symbol={String(policy?.requireSymbol)}
              </span>
            </Descriptions.Item>
          </Descriptions>
          <p>{zh ? '开启租户强制 MFA 前，请先在' : 'Before requiring MFA, enroll the current administrator in '}
            <Link to="/security">{zh ? '账号安全' : 'Account security'}</Link>
            {zh ? '中绑定当前管理员的验证器。未绑定的成员下次登录会先进入绑定流程。'
              : '. Members who have not enrolled will be guided through enrollment at their next sign-in.'}</p>
          <Button type="primary" htmlType="submit" loading={saving} icon={<SaveOutlined />}
            disabled={!canWrite || !policy || conflict}>
            {t('common.save')}
          </Button>
        </Form>
      </Panel>
    </DataState>
  );
}

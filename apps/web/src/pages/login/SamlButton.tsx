import { useState } from 'react';
import { Button, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { SAML_STORAGE_KEY, ssoApi, type SamlFlow } from '@/api/sso';

export function SamlButton({ tenant }: { tenant: () => string }) {
  const { i18n } = useTranslation();
  const [loading, setLoading] = useState(false);
  const start = async () => {
    setLoading(true);
    try {
      const tenantSlug = tenant()?.trim();
      if (!tenantSlug) throw new Error(i18n.language.startsWith('zh') ? '请先填写租户标识' : 'Enter the tenant first');
      const { data } = await ssoApi.samlStart(tenantSlug);
      if (new URL(data.redirectUri).origin !== window.location.origin) {
        throw new Error(i18n.language.startsWith('zh') ? '请使用管理员配置的控制台域名访问' : 'Use the configured console domain');
      }
      const flow: SamlFlow = { tenantSlug, state: data.state, binding: data.binding, createdAt: Date.now() };
      sessionStorage.setItem(SAML_STORAGE_KEY, JSON.stringify(flow));
      window.location.assign(data.authorizationUrl);
    } catch (e) {
      message.error(e instanceof Error ? e.message : String(e));
      setLoading(false);
    }
  };
  return <Button block loading={loading} onClick={() => void start()} style={{ marginTop: 8 }}>SAML 企业登录</Button>;
}

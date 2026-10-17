import { useState } from 'react';
import { Button, message } from 'antd';
import { OIDC_STORAGE_KEY, ssoApi, type OidcFlow } from '@/api/sso';

export function SsoButton({ tenant }: { tenant: () => string }) {
  const [loading, setLoading] = useState(false);
  const start = async () => {
    setLoading(true);
    try {
      const tenantSlug = tenant()?.trim();
      if (!tenantSlug) throw new Error('请先填写租户标识');
      const { data } = await ssoApi.start(tenantSlug);
      if (new URL(data.redirectUri).origin !== window.location.origin) {
        throw new Error('企业登录回调地址与当前控制台地址不同，请使用管理员配置的控制台域名访问');
      }
      const flow: OidcFlow = { tenantSlug, state: data.state, binding: data.binding, createdAt: Date.now() };
      sessionStorage.setItem(OIDC_STORAGE_KEY, JSON.stringify(flow));
      window.location.assign(data.authorizationUrl);
    } catch (e) { message.error(e instanceof Error ? e.message : String(e)); setLoading(false); }
  };
  return <Button block loading={loading} onClick={() => void start()} style={{ marginTop: 12 }}>OIDC 企业登录</Button>;
}

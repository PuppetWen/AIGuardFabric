import { Alert, Descriptions, Steps, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Panel } from '@/components/Panel';
import { useAuthStore } from '@/stores/authStore';

export function IdentityGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const slug = useAuthStore((s) => s.tenant?.slug) ?? 'default';
  const root = `${window.location.origin}/api/v1/auth/saml/${encodeURIComponent(slug)}`;
  return <Panel title={label('企业身份接入', 'Enterprise identity connection')}>
    <Alert showIcon type="info" style={{ marginBottom: 16 }}
      message={label('先从只读测试成员开始', 'Start with a viewer test member')}
      description={label('OIDC、SAML 和 LDAP / AD 各有独立配置页；登录时先填写租户标识。首次纳管建议只读角色，验证平台 MFA 与租户隔离后再扩大权限。',
        'OIDC, SAML and LDAP / AD have separate settings pages. Enter the tenant before sign-in. Start with the viewer role and verify platform MFA and tenant isolation before granting more access.')} />
    <Steps direction="vertical" items={[
      { title: 'OIDC', description: <span>{label('在', 'Under')} <Link to="/settings?tab=identity">{label('设置 → 企业登录', 'Settings → Enterprise sign-in')}</Link>
        {label('填写 Issuer、Client ID、Secret 与控制台回调地址；将回调地址登记到 IdP。',
          ', set the issuer, client ID, secret and console callback URL, then register that URL at the IdP.')}</span> },
      { title: 'SAML 2.0', description: <span>{label('在', 'Under')} <Link to="/settings?tab=saml">{label('设置 → SAML 2.0', 'Settings → SAML 2.0')}</Link>
        {label('复制 SP Entity ID 与 ACS URL 到 IdP，然后粘贴可信 IdP 元数据 XML。IdP 必须签名响应；NameID 应保持不变。',
          ', copy the SP Entity ID and ACS URL to the IdP, then paste trusted IdP metadata XML. Signed responses and an immutable NameID are required.')}</span> },
      { title: 'LDAP / AD', description: <span>{label('在', 'Under')} <Link to="/settings?tab=ldap">{label('设置 → LDAP / AD', 'Settings → LDAP / AD')}</Link>
        {label('填写加密目录地址、只读搜索账号、搜索根与不可变用户 ID 属性。使用 LDAPS 或 StartTLS 并校验证书。',
          ', enter the encrypted directory URL, read-only search account, search base and immutable user ID attribute. Use LDAPS or StartTLS with certificate validation.')}</span> },
      { title: label('手机扫码登录', 'Phone QR sign-in'), description: <span>{label('先在', 'First enable platform MFA under ')}
        <Link to="/security">{label('账号安全', 'Account security')}</Link>
        {label('启用平台 MFA。手机需已登录同一租户；电脑登录页生成 3 分钟二维码，手机扫码输入 MFA 并明确批准。',
          '. The phone must already be signed in to the same tenant. Generate a three-minute QR code on the desktop, then scan, enter MFA and explicitly approve on the phone.')}</span> },
      { title: label('试用和验证', 'Test and verify'), description: label(
        '退出当前会话，在登录页选择相应方式；登录后核对租户、只读权限、审计记录，并测试停用账号及 MFA。',
        'Sign out and select the method on the login page. Verify tenant, viewer permissions and audit records, then test account disablement and MFA.') },
    ]} />
    <Descriptions bordered size="small" column={1} items={[
      { key: 'entity', label: 'SAML SP Entity ID', children: <Typography.Text copyable>{`${root}/metadata`}</Typography.Text> },
      { key: 'acs', label: 'SAML ACS URL', children: <Typography.Text copyable>{`${root}/acs`}</Typography.Text> },
    ]} />
  </Panel>;
}

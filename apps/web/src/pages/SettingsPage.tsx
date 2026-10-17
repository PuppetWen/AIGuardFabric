import { useSearchParams } from 'react-router-dom';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Form, Tabs, message } from 'antd';

import { api, useApiQuery } from '@/api/client';
import { PageHeader } from '@/components/DataState';
import type {
  PasswordPolicy,
  QuotaDefaults,
  Tenant,
} from '@/types/domain';

import { AddUserModal } from './settings/AddUserModal';
import { ApiKeysTab } from './settings/ApiKeysTab';
import { CreateApiKeyModal } from './settings/CreateApiKeyModal';
import { validKeyScopes } from './settings/keyScopes';
import { NotificationsTab } from './settings/NotificationsTab';
import { PasswordTab } from './settings/PasswordTab';
import { QuotasTab } from './settings/QuotasTab';
import { TenantDirectory } from './settings/TenantDirectory';
import { IdentityTab } from './settings/IdentityTab';
import { LdapTab } from './settings/LdapTab';
import { SamlTab } from './settings/SamlTab';
import { useAuthStore } from '@/stores/authStore';
import { useSessionAccess } from '@/api/sessionAccess';

import { TenantTab } from './settings/TenantTab';
import { UsersTab } from './settings/UsersTab';

export default function SettingsPage() {
  const { t, i18n } = useTranslation();
  const access = useSessionAccess();
  const [params, setParams] = useSearchParams();
  const [tenantForm] = Form.useForm<Tenant>();
  const [policyForm] = Form.useForm<PasswordPolicy>();
  const [quotaForm] = Form.useForm<QuotaDefaults>();
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [manualKeyModalOpen, setManualKeyModalOpen] = useState(false);

  const tenants = useApiQuery('settings-tenants', () => api.tenants());
  const users = useApiQuery('settings-users', () => api.users(), { enabled: access.has('platform:admin') });
  const apiKeys = useApiQuery('settings-api-keys', () => api.apiKeys());
  const policy = useApiQuery('settings-policy', () => api.passwordPolicy());

  const tenantId = useAuthStore((state) => state.tenant?.id);
  const requestedTab = params.get('tab') ?? 'identity';
  const createKey = params.get('createKey');
  const requestedScopes = params.get('scopes');
  const canManageKeys = access.has('settings:admin');
  const linkedKeyModalOpen = requestedTab === 'apiKeys' && createKey === '1' && canManageKeys;
  const closeKeyModal = () => {
    setManualKeyModalOpen(false);
    if (!linkedKeyModalOpen) return;
    setParams(previous => {
      const next = new URLSearchParams(previous);
      next.delete('createKey');
      next.delete('scopes');
      return next;
    }, { replace: true });
  };
  const tabVisible = (tab: string) => tab === 'directory' ? access.identity?.superadmin === true
    : tab === 'tenant' || tab === 'users' ? access.has('platform:admin')
      : tab === 'quotas' ? access.has('quotas:read')
        : ['identity', 'ldap', 'saml', 'apiKeys', 'notifications', 'password'].includes(tab);
  const tenant = tenants.data?.data.find((row) => row.id === tenantId) ?? tenants.data?.data[0];
  const reloadTenant = async () => {
    const result = await tenants.refetch();
    if (result.error) throw result.error;
    return result.data?.data.find(row => row.id === tenantId);
  };

  return (
    <>
      <PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} />

      <Tabs
        activeKey={tabVisible(requestedTab) ? requestedTab : 'identity'}
        onChange={tab => setParams(previous => {
          const next = new URLSearchParams(previous);
          next.set('tab', tab);
          next.delete('createKey');
          next.delete('scopes');
          return next;
        })}
        items={[
          { key: 'identity', label: i18n.language.startsWith('zh') ? '企业登录' : 'Enterprise sign-in', children: <IdentityTab canWrite={access.has('settings:write')} /> },
          { key: 'ldap', label: 'LDAP / AD', children: <LdapTab canWrite={access.has('settings:write')} /> },
          { key: 'saml', label: 'SAML 2.0', children: <SamlTab canWrite={access.has('settings:write')} /> },
          ...(access.identity?.superadmin ? [{ key: 'directory', label: i18n.language.startsWith('zh') ? '租户管理' : 'Organizations', children: <TenantDirectory tenants={tenants.data?.data ?? []} reload={() => { void tenants.refetch(); }} /> }] : []),
          ...(access.has('platform:admin') ? [{
            key: 'tenant',
            label: t('settings.tab.tenant'),
            children: (
              <TenantTab
                key={tenant?.id ?? 'none'}
                loading={tenants.isLoading}
                error={tenants.error}
                tenantForm={tenantForm}
                tenant={tenant}
                canWrite={access.has('platform:admin')}
                reload={reloadTenant}
              />
            ),
          },
          {
            key: 'users',
            label: t('settings.tab.users'),
            children: (
              <UsersTab
                loading={users.isLoading}
                error={users.error}
                users={users.data?.data ?? []}
                onUpdated={() => { void users.refetch(); }}
                onAddUser={() => setUserModalOpen(true)}
              />
            ),
          }] : []),
          {
            key: 'apiKeys',
            label: t('settings.tab.apiKeys'),
            children: (
              <ApiKeysTab
                loading={apiKeys.isLoading}
                error={apiKeys.error}
                apiKeys={apiKeys.data?.data ?? []}
                canManage={canManageKeys}
                onCreateKey={() => {
                  setManualKeyModalOpen(true);
                }}
                onRevoked={() => { void apiKeys.refetch(); }}
              />
            ),
          },
          ...(access.has('quotas:read') ? [{
            key: 'quotas',
            label: t('settings.tab.quotas'),
            children: <QuotasTab key={tenant?.id ?? 'none'} quotaForm={quotaForm} tenant={tenant}
              canWrite={access.has('quotas:write')} reload={reloadTenant} />,
          }] : []),
          {
            key: 'notifications',
            label: t('settings.tab.notifications'),
            children: (
              <NotificationsTab />
            ),
          },
          {
            key: 'password',
            label: t('settings.tab.password'),
            children: (
              <PasswordTab
                loading={policy.isLoading}
                error={policy.error}
                policyForm={policyForm}
                policy={policy.data?.data}
                canWrite={access.has('settings:write')}
                reload={async () => {
                  const result = await policy.refetch();
                  if (result.error) throw result.error;
                  return result.data?.data;
                }}
              />
            ),
          },
        ].filter(item => tabVisible(item.key))}
      />

      <AddUserModal
        open={userModalOpen}
        onCancel={() => setUserModalOpen(false)}
        onConfirm={() => {
          message.success(t('settings.users.added'));
          setUserModalOpen(false);
          void users.refetch();
        }}
      />

      {(manualKeyModalOpen || linkedKeyModalOpen) && <CreateApiKeyModal
        open
        initialScopes={linkedKeyModalOpen ? validKeyScopes(requestedScopes?.split(',') ?? []) : []}
        onCancel={closeKeyModal}
        onConfirm={() => {
          message.success(t('settings.apiKeys.created'));
          void apiKeys.refetch();
        }}
      />}
    </>
  );
}

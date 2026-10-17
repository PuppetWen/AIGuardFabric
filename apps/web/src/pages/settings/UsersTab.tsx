import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Select, Table, Tag, message } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined } from '@ant-design/icons';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { User, UserRole } from '@/types/domain';
import { formatDateTime } from '@/utils/format';
import { userRoleKey } from '@/utils/labels';

import { ROLES } from './settings.data';

interface UsersTabProps {
  loading: boolean;
  error: unknown;
  users: User[];
  onUpdated: () => void;
  onAddUser: () => void;
}

/** Tenant user roster with inline role assignment. */
export function UsersTab({
  loading,
  error,
  users,
  onUpdated,
  onAddUser,
}: UsersTabProps) {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const [saving, setSaving] = useState<string>();
  async function update(record: User, body: { role?: UserRole; status?: User['status'] }) {
    setSaving(record.id);
    try { await settingsApi.updateUser(record.id, { ...body, expected_version: record.version }); onUpdated(); message.success(t('settings.users.updated')); }
    catch (error) {
      if (error instanceof ApiRequestError && error.status === 409) {
        onUpdated();
        message.error(t('settings.users.conflict'));
      } else {
        message.error(error instanceof Error ? error.message : t('settings.users.updateFailed'));
      }
    }
    finally { setSaving(undefined); }
  }

  const userColumns: ColumnsType<User> = [
    {
      title: t('settings.users.column.username'),
      dataIndex: 'username',
      width: 160,
      render: (value: string) => <span className="agf-mono">{value}</span>,
    },
    { title: t('settings.users.column.displayName'), dataIndex: 'displayName', width: 130 },
    { title: t('settings.users.column.email'), dataIndex: 'email', width: 220 },
    { title: t('settings.users.column.provider'), dataIndex: 'identityProvider', width: 110,
      render: (value?: string) => <Tag color={['oidc', 'ldap', 'saml'].includes(value ?? '') ? 'blue' : undefined}>{value === 'oidc'
        ? t('settings.users.provider.oidc') : value === 'ldap' ? 'LDAP / AD' : value === 'saml' ? 'SAML 2.0'
          : value && value !== 'local' ? value : t('settings.users.provider.local')}</Tag> },
    {
      title: t('settings.users.column.role'),
      dataIndex: 'role',
      width: 180,
      render: (value: UserRole, record) => (
        <Select<UserRole>
          size="small"
          value={value}
          disabled={value === 'owner' || saving === record.id}
          style={{ width: 150 }}
          onChange={(next) => {
            void update(record, { role: next });
          }}
          options={ROLES.filter((role) => role !== 'owner' || value === 'owner')
            .map((role) => ({ value: role, label: t(userRoleKey(role)) }))}
        />
      ),
    },
    {
      title: t('settings.users.column.mfa'),
      dataIndex: 'mfaEnabled',
      width: 100,
      render: (value: boolean) =>
        value ? <Tag color="green">{t('common.enabled')}</Tag> : <Tag color="red">{t('common.disabled')}</Tag>,
    },
    {
      title: t('settings.users.column.status'),
      dataIndex: 'status',
      width: 122,
      render: (value: User['status']) => (
        <Chip color={value === 'active' ? '#3dd68c' : value === 'locked' ? '#f0cc6a' : '#6f7683'}>
          {t(`status.${value === 'active' ? 'active' : value === 'locked' ? 'locked' : 'disabled'}`)}
        </Chip>
      ),
    },
    {
      title: t('settings.users.column.lastLogin'),
      dataIndex: 'lastLoginAt',
      width: 168,
      sorter: (a, b) => Date.parse(a.lastLoginAt) - Date.parse(b.lastLoginAt),
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    { title: t('common.actions'), width: 120, render: (_, record) => (
      <Button size="small" disabled={record.role === 'owner'} loading={saving === record.id}
        onClick={() => void update(record, { status: record.status === 'active' ? 'disabled' : 'active' })}>
        {record.status === 'active' ? t('settings.users.disable') : t('settings.users.enableUnlock')}
      </Button>
    ) },
  ];

  return (
    <DataState loading={loading} error={error}>
      <Panel
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={onAddUser}>
            {t('settings.users.add')}
          </Button>
        }
      >
        <Table<User>
          rowKey="id"
          size="small"
          columns={userColumns}
          dataSource={users}
          pagination={false}
          scroll={{ x: 1140 }}
        />
      </Panel>
    </DataState>
  );
}

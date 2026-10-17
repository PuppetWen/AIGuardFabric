import { useTranslation } from 'react-i18next';

import { Button, Modal, Table, Tag, message } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { KeyOutlined } from '@ant-design/icons';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import { settingsApi } from '@/api/settings';
import { Panel } from '@/components/Panel';
import type { ApiKey } from '@/types/domain';
import { formatDateTime } from '@/utils/format';

interface ApiKeysTabProps {
  loading: boolean;
  error: unknown;
  apiKeys: ApiKey[];
  canManage: boolean;
  onCreateKey: () => void;
  onRevoked: () => void;
}

/** Programmatic API keys with one-way revocation. */
export function ApiKeysTab({ loading, error, apiKeys, canManage, onCreateKey, onRevoked }: ApiKeysTabProps) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language?.startsWith('zh') ?? false;
  const locale = useAppLocale();

  const keyColumns: ColumnsType<ApiKey> = [
    { title: zh ? '绑定 Agent' : 'Bound Agent', dataIndex: 'boundAgentId', width: 200,
      render: (value: string | null) => value || (zh ? '未绑定' : 'Not bound') },
    { title: t('settings.apiKeys.column.name'), dataIndex: 'name', width: 220 },
    {
      title: t('settings.apiKeys.column.prefix'),
      dataIndex: 'prefix',
      width: 170,
      render: (value: string) => <span className="agf-mono">{value}••••••••</span>,
    },
    {
      title: t('settings.apiKeys.column.scopes'),
      dataIndex: 'scopes',
      width: 300,
      render: (values: string[]) => (
        <span className="agf-inline-list">
          {values.map((value) => (
            <Tag key={value} className="agf-mono" style={{ marginInlineEnd: 0, fontSize: 11 }}>
              {value}
            </Tag>
          ))}
        </span>
      ),
    },
    {
      title: t('settings.apiKeys.column.createdAt'),
      dataIndex: 'createdAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('settings.apiKeys.column.expiresAt'),
      dataIndex: 'expiresAt',
      width: 168,
      render: (value: string | null) =>
        value ? <span className="agf-mono">{formatDateTime(value, locale)}</span> : <Tag>{t('settings.apiKeys.never')}</Tag>,
    },
    {
      title: t('settings.apiKeys.column.lastUsed'),
      dataIndex: 'lastUsedAt',
      width: 168,
      render: (value: string | null) =>
        value ? <span className="agf-mono">{formatDateTime(value, locale)}</span> : <span className="agf-tertiary">—</span>,
    },
    {
      title: t('common.status'),
      dataIndex: 'revoked',
      width: 180,
      render: (revoked: boolean, record) =>
        revoked ? (
          <Tag color="red">{t('status.revoked')}</Tag>
        ) : canManage ? (
          <Button
            size="small"
            danger
            aria-label={t('settings.apiKeys.revoke')}
            onClick={() => {
              Modal.confirm({
                title: t('settings.apiKeys.revokeConfirm', { name: record.name }),
                okText: t('common.ok'),
                cancelText: t('common.cancel'),
                onOk: async () => {
                  try {
                    await settingsApi.revokeKey(record.id);
                    message.success(t('settings.apiKeys.revoked'));
                    onRevoked();
                  } catch (error) {
                    message.error(error instanceof Error ? error.message : zh ? '吊销失败' : 'Failed to revoke API key');
                    throw error;
                  }
                },
              });
            }}
          >
            {t('settings.apiKeys.revoke')}
          </Button>
        ) : <Tag color="green">{t('status.active')}</Tag>,
    },
  ];

  return (
    <DataState loading={loading} error={error}>
      <Panel
        extra={canManage ?
          <Button
            type="primary"
            icon={<KeyOutlined />}
            aria-label={t('settings.apiKeys.create')}
            onClick={onCreateKey}
          >
            {t('settings.apiKeys.create')}
          </Button> : undefined}
      >
        <Table<ApiKey>
          rowKey="id"
          size="small"
          columns={keyColumns}
          dataSource={apiKeys}
          pagination={false}
          scroll={{ x: 1380 }}
        />
      </Panel>
    </DataState>
  );
}

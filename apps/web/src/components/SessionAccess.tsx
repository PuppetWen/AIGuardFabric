import type { ReactNode } from 'react';
import { Button, Result, Space, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { FORCE_DEMO } from '@/api/config';
import { PAGE_PERMISSIONS, type useSessionAccess } from '@/api/sessionAccess';
import { DataState } from './DataState';

export function PageAccess({ path, access, children }: {
  path: string; access: ReturnType<typeof useSessionAccess>; children: ReactNode;
}) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  if (FORCE_DEMO || !(PAGE_PERMISSIONS[path]?.length)) return <>{children}</>;
  const missing = PAGE_PERMISSIONS[path].filter(permission => !access.has(permission));
  return <DataState loading={access.isLoading} error={access.error} onRetry={() => void access.refetch()}>
    {access.allows(path) ? children : <Result status="403"
      title={zh ? '当前账号无权打开此页面' : 'Your account cannot open this page'}
      subTitle={zh ? '请确认当前组织，并联系管理员核对职责与权限。已授权的数据仍可从左侧菜单查看。'
        : 'Check the current organization and ask an administrator to review your role. Authorized data remains available in the sidebar.'}
      extra={<Space direction="vertical" align="center">
        <Typography.Text code>{missing.join(', ')}</Typography.Text>
        <Space><Button onClick={() => void access.refetch()}>{zh ? '重新检查权限' : 'Check access again'}</Button>
          <Link to="/guide">{zh ? '查看操作指南' : 'Open the guide'}</Link></Space>
      </Space>} />}
  </DataState>;
}

import { useEffect, useMemo } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import {
  Avatar,
  Badge,
  Button,
  Dropdown,
  Layout,
  Menu,
  Radio,
  Select,
  Space,
  Switch,
  Tooltip,
  Typography,
  message,
} from 'antd';
import type { MenuProps } from 'antd';
import {
  ApartmentOutlined,
  ApiOutlined,
  AuditOutlined,
  BellOutlined,
  BlockOutlined,
  CloudServerOutlined,
  ClusterOutlined,
  DashboardOutlined,
  DeploymentUnitOutlined,
  FileSearchOutlined,
  ForkOutlined,
  GlobalOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  MoonOutlined,
  PieChartOutlined,
  ProfileOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  SunOutlined,
  TableOutlined,
  ThunderboltOutlined,
  UserOutlined,
} from '@ant-design/icons';

import { DemoModeBanner, useDataSource } from '@/components/DemoModeBanner';
import { GlobalSearch } from '@/components/GlobalSearch';
import { NotificationBell } from '@/components/NotificationBell';
import { PageErrorBoundary } from '@/components/PageErrorBoundary';
import { PageAccess } from '@/components/SessionAccess';
import { useSessionAccess } from '@/api/sessionAccess';
import { LOCALE_LABEL, SUPPORTED_LOCALES } from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import { logoutSession } from '@/api/session';
import { useUiStore } from '@/stores/uiStore';
import type { SupportedLocale } from '@/locales/i18n';
import { useApiQuery, api } from '@/api/client';

const { Header, Sider, Content } = Layout;

interface NavEntry {
  key: string;
  labelKey: string;
  icon: React.ReactNode;
}

interface NavGroup {
  key: string;
  labelKey: string;
  items: NavEntry[];
}

/** Sidebar information architecture — mirrors the documented page inventory. */
export const NAV_GROUPS: NavGroup[] = [
  {
    key: 'g-overview',
    labelKey: 'nav.group.overview',
    items: [{ key: '/', labelKey: 'nav.overview', icon: <DashboardOutlined /> }],
  },
  {
    key: 'g-assets',
    labelKey: 'nav.group.assets',
    items: [
      { key: '/assets', labelKey: 'nav.assets', icon: <TableOutlined /> },
      { key: '/agents', labelKey: 'nav.agents', icon: <DeploymentUnitOutlined /> },
      { key: '/mcps', labelKey: 'nav.mcps', icon: <ApiOutlined /> },
      { key: '/skills', labelKey: 'nav.skills', icon: <SafetyCertificateOutlined /> },
      { key: '/models', labelKey: 'nav.models', icon: <CloudServerOutlined /> },
      { key: '/topology', labelKey: 'nav.topology', icon: <ApartmentOutlined /> },
    ],
  },
  {
    key: 'g-detection',
    labelKey: 'nav.group.detection',
    items: [
      { key: '/findings', labelKey: 'nav.findings', icon: <FileSearchOutlined /> },
      { key: '/rules', labelKey: 'nav.rules', icon: <ForkOutlined /> },
      { key: '/redteam', labelKey: 'nav.redteam', icon: <ThunderboltOutlined /> },
      { key: '/alerts', labelKey: 'nav.alerts', icon: <BellOutlined /> },
      { key: '/cases', labelKey: 'nav.cases', icon: <ProfileOutlined /> },
    ],
  },
  {
    key: 'g-enforcement',
    labelKey: 'nav.group.enforcement',
    items: [
      { key: '/policies', labelKey: 'nav.policies', icon: <BlockOutlined /> },
      { key: '/runtime', labelKey: 'nav.runtime', icon: <SafetyCertificateOutlined /> },
      { key: '/ingest', labelKey: 'nav.ingest', icon: <ClusterOutlined /> },
    ],
  },
  {
    key: 'g-platform',
    labelKey: 'nav.group.platform',
    items: [
      { key: '/integrations', labelKey: 'nav.integrations', icon: <GlobalOutlined /> },
      { key: '/alicloud', labelKey: 'nav.alicloud', icon: <CloudServerOutlined /> },
      { key: '/audit', labelKey: 'nav.audit', icon: <AuditOutlined /> },
      { key: '/reports', labelKey: 'nav.reports', icon: <PieChartOutlined /> },
      { key: '/settings', labelKey: 'nav.settings', icon: <SettingOutlined /> },
      { key: '/guide', labelKey: 'nav.guide', icon: <ProfileOutlined /> },
      { key: '/security', labelKey: 'nav.security', icon: <SafetyCertificateOutlined /> },
    ],
  },
];

/** Route → page-title key, used by the top bar. */
export const ROUTE_TITLE_KEY: Record<string, string> = Object.fromEntries(
  NAV_GROUPS.flatMap((group) => group.items.map((item) => [item.key, item.labelKey])),
);

export function AppLayout() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const collapsed = useUiStore((state) => state.sidebarCollapsed);
  const toggleSidebar = useUiStore((state) => state.toggleSidebar);
  const theme = useUiStore((state) => state.theme);
  const setTheme = useUiStore((state) => state.setTheme);
  const locale = useUiStore((state) => state.locale);
  const setLocale = useUiStore((state) => state.setLocale);
  const { displayName, role, tenant } = useAuthStore();
  const { source } = useDataSource();
  const access = useSessionAccess();

  const tenants = useApiQuery('layout-tenants', () => api.tenants(), { staleTime: 300_000, enabled: access.has('settings:read') });

  const menuItems: MenuProps['items'] = NAV_GROUPS.map(group => ({ ...group, items: group.items.filter(item => access.allows(item.key)) }))
      .filter(group => group.items.length > 0).map((group) => ({
        key: group.key,
        type: 'group' as const,
        label: t(group.labelKey),
        children: group.items.map((item) => ({
          key: item.key,
          icon: item.icon,
          label: <Link to={item.key}>{t(item.labelKey)}</Link>,
        })),
      }));

  const selectedKey = useMemo(() => {
    const path = location.pathname === '/' ? '/' : `/${location.pathname.split('/')[1] ?? ''}`;
    return path;
  }, [location.pathname]);

  useEffect(() => {
    document.title = `${t(ROUTE_TITLE_KEY[selectedKey] ?? 'app.name')} · ${t('app.name')}`;
  }, [selectedKey, t]);

  const tenantOptions = (access.has('settings:read') ? tenants.data?.data ?? [] : []).map((item) => ({
        value: item.slug,
        label: `${item.name} · ${item.slug}`,
      }));

  const userMenu: MenuProps['items'] = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: t('layout.profile'),
    },
    {
      key: 'demo',
      label: source === 'demo' ? t('layout.demoMode') : t('layout.backendLive'),
      disabled: true,
    },
    { type: 'divider' },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: t('layout.logout'),
      danger: true,
    },
  ];

  return (
    <Layout className="agf-layout">
      <Sider
        className="agf-sider"
        width={228}
        collapsedWidth={72}
        collapsible
        collapsed={collapsed}
        trigger={null}
        theme="dark"
      >
        <div className="agf-brand">
          <span className="agf-brand__mark" aria-hidden>
            {tenant?.whiteLabel.logoText ?? 'AGF'}
          </span>
          {!collapsed ? (
            <span className="agf-brand__text">
              <span className="agf-brand__name">{tenant?.whiteLabel.productName ?? t('app.name')}</span>
              <span className="agf-brand__sub">{t('app.nameEn')}</span>
            </span>
          ) : null}
        </div>
        <Menu
          className="agf-menu"
          mode="inline"
          theme={theme === 'dark' ? 'dark' : 'light'}
          items={menuItems}
          selectedKeys={[selectedKey]}
        />
      </Sider>

      <Layout>
        <Header className="agf-header">
          <Tooltip title={collapsed ? t('layout.expand') : t('layout.collapse')}>
            <Button
              type="text"
              icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={toggleSidebar}
              aria-label={collapsed ? t('layout.expand') : t('layout.collapse')}
            />
          </Tooltip>

          <Typography.Text className="agf-header__title">
            {t(ROUTE_TITLE_KEY[selectedKey] ?? 'app.name')}
          </Typography.Text>

          <div className="agf-header__spacer" />

          <GlobalSearch />

          <div className="agf-header__group">
            <Select
              size="small"
              value={tenant?.slug}
              options={tenantOptions}
              showSearch
              optionFilterProp="label"
              loading={tenants.isFetching}
              disabled={!access.has('settings:read') || tenantOptions.length < 2}
              placeholder={t('layout.tenant')}
              onChange={(value) => {
                const next = (tenants.data?.data ?? []).find((item) => item.slug === value);
                if (!next) return;
                useAuthStore.getState().setTenant(next);
                navigate('/');
                message.info(`${t('layout.switchTenant')}: ${value}`);
              }}
              style={{ width: 190 }}
              aria-label={t('layout.tenant')}
            />

            <Radio.Group
              size="small"
              value={locale}
              onChange={(event) => setLocale(event.target.value as SupportedLocale)}
              aria-label={t('layout.locale')}
            >
              {SUPPORTED_LOCALES.map((code) => (
                <Radio.Button key={code} value={code}>
                  {LOCALE_LABEL[code]}
                </Radio.Button>
              ))}
            </Radio.Group>

            <Tooltip title={theme === 'dark' ? t('layout.theme.light') : t('layout.theme.dark')}>
              <Switch
                checkedChildren={<MoonOutlined />}
                unCheckedChildren={<SunOutlined />}
                checked={theme === 'dark'}
                onChange={(checked) => setTheme(checked ? 'dark' : 'light')}
                aria-label={t('layout.theme')}
              />
            </Tooltip>

            <NotificationBell />

            <Dropdown
              menu={{
                items: userMenu,
                onClick: ({ key }) => {
                  if (key === 'profile') navigate('/security');
                  if (key === 'logout') {
                    void logoutSession().then(() => {
                      message.success(t('layout.loggedOut'));
                      navigate('/login', { replace: true });
                    });
                  }
                },
              }}
              trigger={['click']}
              placement="bottomRight"
            >
              <Button type="text" style={{ height: 40, paddingInline: 6 }}>
                <Space size={8}>
                  <Avatar size={26} style={{ background: 'var(--agf-accent)', color: '#04101f' }}>
                    {(displayName ?? 'A').slice(0, 1)}
                  </Avatar>
                  <span style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.15 }}>
                    <span style={{ fontSize: 12, fontWeight: 600 }}>{displayName ?? 'admin'}</span>
                    <span className="agf-tertiary" style={{ fontSize: 11 }}>
                      {access.identity?.roles.join(', ') || role || '—'}
                    </span>
                  </span>
                  <Badge status={source === 'demo' ? 'warning' : 'success'} />
                </Space>
              </Button>
            </Dropdown>
          </div>
        </Header>

        <DemoModeBanner />

        <Content className="agf-content">
          <PageErrorBoundary key={`${tenant?.id ?? 'anonymous'}:${location.pathname}`}>
            <PageAccess path={selectedKey} access={access}><Outlet /></PageAccess>
          </PageErrorBoundary>
        </Content>
      </Layout>
    </Layout>
  );
}

export default AppLayout;

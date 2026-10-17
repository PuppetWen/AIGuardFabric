import { screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import { SchedulerNativeGuide } from './SchedulerNativeGuide';
import SchedulerNativePanel from './SchedulerNativePanel';
import { installHarness, mount, rights } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it.each(['en-US', 'zh-CN'])('describes the real six executors and separate deployment/secret boundary in %s without writes', async language => {
  await i18n.changeLanguage(language); const observe = vi.spyOn(api, 'observe'), bind = vi.spyOn(api, 'bind');
  mount(<SchedulerNativeGuide />);
  expect(screen.getByText('report / report-generate')).toBeInTheDocument(); expect(screen.getByText('archive / cold-archive')).toBeInTheDocument();
  expect(screen.getByText(/callbackBindingEnforced=false/)).toBeInTheDocument();
  expect(screen.getByText(/region_id=cn-hangzhou.*cluster_id=cluster-agf-demo.*app_name=app-agf-demo/)).toBeInTheDocument();
  expect(screen.getByText(language === 'en-US' ? /independent callback-token secret reference/ : /独立 callback token 的 Secret 引用/)).toBeInTheDocument();
  expect(screen.getByText(/\/tasks/)).toBeInTheDocument(); expect(observe).not.toHaveBeenCalled(); expect(bind).not.toHaveBeenCalled(); expect(api.state).not.toHaveBeenCalled();
});
it('does not query or show controls without the required read permission', async () => {
  rights.delete('alicloud:read'); const observe = vi.spyOn(api, 'observe'); mount(<SchedulerNativePanel />);
  expect(await screen.findByText('This page requires alicloud:read')).toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: 'Original observation ID' })).not.toBeInTheDocument();
  expect(api.state).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});

import { screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { agentteamsRoleMappingApi as api } from '@/api/agentteamsRoleMapping';
import { RoleMappingGuide } from './RoleMappingGuide';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it.each(['en-US', 'zh-CN'])('explains actual role selection, permanent disable and adoption-only TTL in %s without network writes', async language => {
  await i18n.changeLanguage(language); const save = vi.spyOn(api, 'save'), read = vi.spyOn(api, 'receipt'); mount(<RoleMappingGuide />);
  const cn = language === 'zh-CN';
  expect(screen.getByText(cn ? /新增映射需要数据库/ : /new mappings require a database/)).toBeInTheDocument();
  expect(screen.getByText(cn ? /没有删除解锁/ : /no delete-to-unlock/)).toBeInTheDocument();
  expect(screen.getByText(cn ? /不是运行权限 TTL/ : /not runtime authority TTL/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: cn ? '前往完整盘点（人工操作）' : 'Open full inventory (manual operation)' })).toHaveAttribute('href', '/alicloud?tab=inventory');
  expect(api.state).not.toHaveBeenCalled(); expect(save).not.toHaveBeenCalled(); expect(read).not.toHaveBeenCalled();
});

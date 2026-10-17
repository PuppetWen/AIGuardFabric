import { act, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import ApigGuide from './ApigGuide';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
it.each(['en-US', 'zh-CN'])('explains the actual Mock IDs, JSON source preparation, permissions and loss of rollback bodies in %s', async language => {
  await act(async () => { await i18n.changeLanguage(language); }); const view = mount(<ApigGuide />), text = view.container.textContent ?? '';
  for (const field of ['cn-hangzhou', 'api-agf-demo', 'gw-agf-demo', 'env-agf-demo', 'policy-agf-demo', 'attachment-agf-demo',
    'JSON（Structured）', 'alicloud:read', 'policies:read', 'alicloud:write', 'quotas:read/write', 'policies:write']) {
    if (field === 'JSON（Structured）') expect(text).toContain(language === 'zh-CN' ? field : 'JSON (Structured)'); else expect(text).toContain(field);
  }
  expect(text).toContain(language === 'zh-CN' ? 'GET 永不初始化' : 'GET never initializes');
  expect(text).toContain(language === 'zh-CN' ? '这条回滚正文会丢失' : 'the rollback body is lost');
  expect(text).toContain(language === 'zh-CN' ? '无数据库模式仅当前进程有效' : 'database-free mode lasts only for the current process');
  expect(screen.getByRole('list')).toBeInTheDocument();
});

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';

import i18n from '@/locales/i18n';
import { DemoModeBanner } from '@/components/DemoModeBanner';
import { __resetDataSource, api } from '@/api/client';

describe('DemoModeBanner', () => {
  it('renders the Chinese demo notice once the client has fallen back', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );
    __resetDataSource();
    await api.assets();

    await i18n.changeLanguage('zh-CN');

    render(
      <I18nextProvider i18n={i18n}>
        <DemoModeBanner />
      </I18nextProvider>,
    );

    expect(screen.getByTestId('demo-mode-banner')).toBeInTheDocument();
    expect(screen.getByText('演示数据（后端未连接）')).toBeInTheDocument();
  });

  it('renders nothing while live data is flowing', async () => {
    __resetDataSource();
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ items: [], total: 0, page: 1, pageSize: 10 }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
      ),
    );
    await api.assets();

    const { container } = render(
      <I18nextProvider i18n={i18n}>
        <DemoModeBanner />
      </I18nextProvider>,
    );

    expect(container).toBeEmptyDOMElement();
  });
});

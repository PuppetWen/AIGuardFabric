import { Suspense, lazy, useEffect } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { PageErrorBoundary } from './PageErrorBoundary';

afterEach(async () => {
  cleanup();
  vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});

function ignoreExpectedError(expected: unknown) {
  const reportError = console.error;
  vi.spyOn(console, 'error').mockImplementation((...args) => {
    if (!args.includes(expected)) reportError(...args);
  });
}

it.each([
  ['chromium', new TypeError('Failed to fetch dynamically imported module: https://agf.example/assets/old-page.js')],
  ['firefox', new TypeError('error loading dynamically imported module: https://agf.example/assets/old-page.js')],
  ['safari', new TypeError('Importing a module script failed.')],
  ['webpack', Object.assign(new Error('Loading chunk 17 failed.'), { name: 'ChunkLoadError' })],
])('offers one explicit reload for a cached %s lazy import failure', async (_, error) => {
  await i18n.changeLanguage('en-US');
  ignoreExpectedError(error);
  const importPage = vi.fn(async () => { throw error; });
  const Page = lazy(importPage);
  const reload = vi.fn();
  await act(async () => {
    render(<PageErrorBoundary onReload={reload}><Suspense fallback={<div>Loading</div>}>
      <Page />
    </Suspense></PageErrorBoundary>);
  });

  const button = await screen.findByRole('button', { name: 'Reload page' });
  expect(importPage).toHaveBeenCalledTimes(1);
  expect(reload).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  fireEvent.click(button);
  fireEvent.click(button);
  expect(reload).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Reloading…' })).toBeDisabled();
});

it.each([new Error('Unexpected render failure'), new TypeError('Failed to fetch')])(
  'keeps ordinary application errors retryable without treating them as chunk failures: %s', async error => {
    await i18n.changeLanguage('en-US');
    ignoreExpectedError(error);
    let failing = true;
    function Page() {
      if (failing) throw error;
      return <div>Page recovered</div>;
    }
    const reload = vi.fn();
    render(<PageErrorBoundary onReload={reload}><Page /></PageErrorBoundary>);
    expect(screen.queryByRole('button', { name: 'Reload page' })).not.toBeInTheDocument();
    failing = false;
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Page recovered')).toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
  },
);

it('recovers when navigating away from a failed route without remounting healthy routes', async () => {
  await i18n.changeLanguage('en-US');
  const failure = new TypeError('Failed to fetch dynamically imported module: /old-page.js');
  ignoreExpectedError(failure);
  function FailedPage(): never { throw failure; }
  const mounted = vi.fn();
  function HealthyPage() {
    useEffect(() => { mounted(); }, []);
    return <div>Second page</div>;
  }
  const reload = vi.fn();
  const view = render(<PageErrorBoundary resetKey="/first" onReload={reload}><FailedPage /></PageErrorBoundary>);
  await screen.findByRole('button', { name: 'Reload page' });
  view.rerender(<PageErrorBoundary resetKey="/second" onReload={reload}><HealthyPage /></PageErrorBoundary>);
  expect(await screen.findByText('Second page')).toBeInTheDocument();
  view.rerender(<PageErrorBoundary resetKey="/third" onReload={reload}><HealthyPage /></PageErrorBoundary>);
  expect(mounted).toHaveBeenCalledTimes(1);
  expect(reload).not.toHaveBeenCalled();
});

import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { AppRouter } from './router';

vi.mock('@/pages/LoginPage', async () => {
  const { createElement, lazy } = await import('react');
  const MissingDependency = lazy(async () => {
    throw new TypeError('Failed to fetch dynamically imported module: /assets/LoginPage-previous.js');
  });
  return { default: () => createElement(MissingDependency) };
});

afterEach(async () => {
  cleanup();
  vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
  window.history.replaceState({}, '', '/');
});

it('contains a public route chunk failure and preserves the address for explicit reload', async () => {
  await i18n.changeLanguage('en-US');
  const reportError = console.error;
  vi.spyOn(console, 'error').mockImplementation((...args) => {
    const expected = args.some(value => value instanceof Error
      && value.message === 'Failed to fetch dynamically imported module: /assets/LoginPage-previous.js');
    if (!expected) reportError(...args);
  });
  window.history.replaceState({}, '', '/login?returnTo=%2Fassets#session');
  await act(async () => { render(<AppRouter />); });

  expect(await screen.findByRole('button', { name: 'Reload page' })).toBeEnabled();
  expect(screen.getByText('Page resources could not be loaded')).toBeInTheDocument();
  expect(window.location.pathname + window.location.search + window.location.hash)
    .toBe('/login?returnTo=%2Fassets#session');
});

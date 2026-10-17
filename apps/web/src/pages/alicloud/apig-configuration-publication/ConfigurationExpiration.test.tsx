import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import ConfigurationPreview from './ConfigurationPreview';
import { preview, state } from './testFixtures';

afterEach(async () => {
  cleanup();
  vi.useRealTimers();
  await i18n.changeLanguage('zh-CN');
});

it('rejects an expired confirmed preview before the next clock tick and updates the idle button', async () => {
  await i18n.changeLanguage('en-US');
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
  const startedAt = Date.now();
  const onApply = vi.fn();
  render(
    <ConfigProvider theme={{ token: { motion: false } }}>
      <ConfigurationPreview
        preview={preview({ expiresAt: new Date(startedAt + 500).toISOString() })}
        data={state()}
        held={false}
        busy={false}
        canWrite
        onApply={onApply}
      />
    </ConfigProvider>,
  );
  for (const name of [
    'Confirm the target and public configuration differences above',
    'Confirm public fields only, retaining other environments, credentials and private rules',
    'Confirm streaming-response and shared-resource impact remain unknown',
    'Confirm there is no cloud CAS; pre-write comparison cannot exclude external concurrency',
  ]) {
    fireEvent.click(screen.getByRole('checkbox', { name }));
  }
  const submit = screen.getByRole('button', { name: 'Send one explicit new APIG configuration write' });
  expect(submit).toBeEnabled();
  vi.setSystemTime(startedAt + 600);
  fireEvent.click(submit);
  expect(onApply).not.toHaveBeenCalled();
  act(() => { vi.advanceTimersByTime(1000); });
  expect(submit).toBeDisabled();
  expect(onApply).not.toHaveBeenCalled();
});

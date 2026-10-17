import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import { BrokerQuarantine } from './BrokerQuarantine';

describe('broker quarantine actions', () => {
  it('keeps the reviewed version and reason after a conflict and never requests evidence implicitly', async () => {
    await i18n.changeLanguage('en-US');
    const row = {id: 'message-one', stream: 'TEST', streamSequence: 1, payloadHash: 'hash', payloadBytes: 12,
      reasonCode: 'invalid_payload', state: 'quarantined', version: 7, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()};
    const request = vi.spyOn(transport, 'callApi').mockImplementation(async (path, _fallback, options) => {
      if (options?.method === 'POST') throw new Error('Message changed; refresh and review');
      if (path !== '/api/v1/sources/broker/quarantine') throw new Error('Unexpected evidence request');
      return {data: {items: [row], total: 1, canManage: true}, meta: {source: 'live', elapsedMs: 1, at: Date.now()}} as never;
    });
    const client = new QueryClient({defaultOptions: {queries: {retry: false}}});
    const rendered = render(<QueryClientProvider client={client}><BrokerQuarantine /></QueryClientProvider>);
    fireEvent.click(screen.getByRole('button', {name: 'Platform message quarantine'}));
    fireEvent.click(await screen.findByRole('button', {name: 'Manual retry'}));
    expect(screen.getByRole('button', {name: 'Confirm action'})).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox', {name: 'Action reason'}), {target: {value: 'Reviewed publisher repair'}});
    fireEvent.click(screen.getByRole('button', {name: 'Confirm action'}));
    await waitFor(() => expect(screen.getAllByText('Message changed; refresh and review').length).toBeGreaterThan(0));
    expect(request).toHaveBeenCalledWith('/api/v1/sources/broker/quarantine/message-one/retry', expect.any(Function),
      expect.objectContaining({body: {expected_version: 7, reason: 'Reviewed publisher repair'}}));
    expect(screen.getByRole('textbox', {name: 'Action reason'})).toHaveValue('Reviewed publisher repair');
    expect(request.mock.calls.every(([path]) => !path.endsWith('/message-one'))).toBe(true);
    rendered.unmount(); client.clear(); vi.restoreAllMocks();
  });
});

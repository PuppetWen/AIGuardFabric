import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Form } from 'antd';
import { afterEach, expect, it, vi } from 'vitest';
import { api } from '@/api/client';
import { gatewayApi } from '@/api/gateway';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import type { ModelRoutePolicy } from '@/types/domain';
import { RouteEditorDrawer } from './RouteEditorDrawer';

afterEach(() => vi.restoreAllMocks());

it('keeps a conflicting route draft and sends the version from the opened row', async () => {
  await i18n.changeLanguage('en-US');
  const row: ModelRoutePolicy = { id: 'route-one', version: 5, name: 'Initial route',
    primaryEndpointId: 'endpoint-one', fallbackEndpointIds: [], strategy: 'priority',
    weights: {}, budgetCnyPerDay: 0, enabled: true };
  vi.spyOn(gatewayApi, 'list').mockResolvedValue({ data: { items: [] },
    meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } });
  const save = vi.spyOn(api, 'saveRoutePolicy').mockRejectedValue(new ApiRequestError('route changed', 409, 'conflict'));
  const onSaved = vi.fn();
  function Editor() {
    const [form] = Form.useForm<ModelRoutePolicy>();
    return <RouteEditorDrawer open canWrite routeTarget={row} form={form} onClose={vi.fn()} onSaved={onSaved} />;
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><Editor /></QueryClientProvider>);
  fireEvent.change(await screen.findByLabelText('Policy name'), { target: { value: 'Unsaved route' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText(/route changed/);
  expect(save).toHaveBeenCalledWith(expect.objectContaining({
    id: 'route-one', expectedVersion: 5, name: 'Unsaved route',
  }));
  expect(screen.getByLabelText('Policy name')).toHaveValue('Unsaved route');
  await waitFor(() => expect(screen.getByText('Save').closest('button')).toBeDisabled());
  expect(onSaved).not.toHaveBeenCalled();
  view.unmount(); client.clear();
  await i18n.changeLanguage('zh-CN');
});

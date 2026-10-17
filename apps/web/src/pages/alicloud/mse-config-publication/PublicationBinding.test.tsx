import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import type { ApiResult } from '@/api/dataSource';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import PublicationBinding from './PublicationBinding';
import { bindingBody, bindingDraft } from './binding';
import { config, deferred, result } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('does not invent a default namespace or silently trim a dedicated target', () => {
  const saved = config(), draft = { ...bindingDraft(saved), confirmed: true };
  expect(() => bindingBody(saved, draft)).toThrow('namespace');
  expect(() => bindingBody(saved, { ...draft, namespaceMode: 'specific', namespace: '' })).toThrow('namespace');
  expect(() => bindingBody(saved, { ...draft, namespaceMode: 'default', dataId: ' owned-policy.json ' })).toThrow('Data ID');
  expect(() => bindingBody(saved, { ...draft, namespaceMode: 'default', origin: 'https://nacos.example.test/path' })).toThrow('origin');
  const body = bindingBody(saved, { ...draft, namespaceMode: 'default' });
  expect(body).toMatchObject({ expected_version: 1, secrets: {}, clear_secrets: [], settings: {
    namespace_id: '', endpoint: saved.settings.endpoint, credential_source: 'ecs-role', managed_upsert_confirmed: true,
  } });
  expect(bindingBody(config(0), { ...draft, namespaceMode: 'default' }).expected_version).toBe(0);
  const live = { ...saved, mock: false, environmentMock: false };
  expect(() => bindingBody(live, { ...draft, mock: false, namespaceMode: 'default', origin: 'https://new-engine.example.test' })).toThrow('new credentials');
  expect(bindingBody(live, { ...draft, enabled: false, mock: false, namespaceMode: 'default', origin: 'https://new-engine.example.test' }))
    .toMatchObject({ enabled: false, mock: false, secrets: {}, clear_secrets: [] });
});
it('clears upsert confirmation on target or mode changes and sends an explicitly selected default namespace', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config()));
  const save = vi.spyOn(cloudApi, 'save').mockResolvedValue(result(config(2))), onSaved = vi.fn();
  mount(<PublicationBinding onSaved={onSaved} />);
  const confirm = await screen.findByRole('checkbox', { name: /Confirm management of this dedicated JSON Data ID/ });
  const button = screen.getByRole('button', { name: 'Save publication target binding' });
  expect(confirm).not.toBeChecked(); fireEvent.click(confirm); expect(button).toBeEnabled();
  fireEvent.change(screen.getByRole('textbox', { name: 'Dedicated Data ID' }), { target: { value: 'new-owned.json' } });
  expect(confirm).not.toBeChecked(); fireEvent.click(confirm);
  fireEvent.click(screen.getByRole('checkbox', { name: 'Configure Mock mode' })); expect(confirm).not.toBeChecked();
  fireEvent.click(screen.getByRole('radio', { name: 'Default namespace (explicit empty string)' })); fireEvent.click(confirm); fireEvent.click(button);
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(save).toHaveBeenCalledWith('alicloud-mse', expect.objectContaining({ expected_version: 1, mock: false,
    settings: expect.objectContaining({ namespace_id: '', config_data_id: 'new-owned.json', endpoint: config().settings.endpoint }), secrets: {}, clear_secrets: [] }));
  await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
});
it('keeps the target draft and original configuration version after conflict and a comparison GET', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValueOnce(result(config())).mockResolvedValue(result(config(8)));
  const save = vi.spyOn(cloudApi, 'save').mockRejectedValue(new Error('Configuration revision conflict'));
  mount(<PublicationBinding onSaved={vi.fn()} />);
  fireEvent.change(await screen.findByRole('textbox', { name: 'Dedicated Data ID' }), { target: { value: 'unsaved.json' } });
  fireEvent.click(screen.getByRole('radio', { name: 'Default namespace (explicit empty string)' }));
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm management/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Save publication target binding' }));
  await screen.findByText('Configuration revision conflict');
  fireEvent.click(screen.getByRole('button', { name: 'Read latest configuration to compare' }));
  await screen.findByText('Server configuration version 8');
  expect(screen.getByRole('textbox', { name: 'Dedicated Data ID' })).toHaveValue('unsaved.json');
  expect(screen.getByText('Save uses configuration version 1')).toBeInTheDocument(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Save publication target binding' }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(save).toHaveBeenLastCalledWith('alicloud-mse', expect.objectContaining({ expected_version: 1, settings: expect.objectContaining({ config_data_id: 'unsaved.json' }) }));
});
it('does not publish a late saved configuration or callback into a new tenant', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config()));
  const pending = deferred<ApiResult<CloudConfig>>();
  const save = vi.spyOn(cloudApi, 'save').mockReturnValue(pending.promise), onSaved = vi.fn();
  mount(<PublicationBinding onSaved={onSaved} />);
  fireEvent.click(await screen.findByRole('radio', { name: 'Default namespace (explicit empty string)' }));
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm management/ })); fireEvent.click(screen.getByRole('button', { name: 'Save publication target binding' }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await act(async () => { pending.resolve(result(config(9))); });
  expect(onSaved).not.toHaveBeenCalled(); expect(screen.queryByText('Save uses configuration version 9')).not.toBeInTheDocument();
});

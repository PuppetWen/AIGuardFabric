import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { gatewaySettlementApi as api } from '@/api/gatewaySettlement';
import { useSessionAccess } from '@/api/sessionAccess';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import { GatewaySettlementPanel } from './GatewaySettlementPanel';
import { attempt, audit, receipt, result } from './testFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
const rights = new Set<string>();
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); rights.clear(); rights.add('models:read'); rights.add('models:write');
  vi.mocked(useSessionAccess).mockImplementation(() => ({ has: permission => rights.has(permission) }) as ReturnType<typeof useSessionAccess>);
  vi.spyOn(api, 'read').mockResolvedValue(result(receipt()));
  vi.spyOn(api, 'recover').mockResolvedValue(result(receipt({ state: 'settled', auditId: audit, recoveryAvailable: false })));
});
afterEach(async () => { cleanup(); vi.restoreAllMocks(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
const mount = () => render(<ConfigProvider theme={{ token: { motion: false } }}><GatewaySettlementPanel /></ConfigProvider>);
async function read() {
  fireEvent.change(screen.getByRole('textbox', { name: 'Original model attempt ID' }), { target: { value: attempt } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original settlement' }));
  await screen.findByText('Known outcome awaiting audit');
}

it('reads the original ID and requires a separate confirmation before an empty-body local recovery', async () => {
  mount(); expect(api.read).not.toHaveBeenCalled(); expect(api.recover).not.toHaveBeenCalled();
  await read();
  fireEvent.click(screen.getByRole('button', { name: 'Recover local settlement' }));
  await screen.findByText('Publish known costs and audit locally for this original ID? No model is called again.');
  expect(api.recover).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'OK' }));
  await screen.findByText('Local settlement committed');
  expect(api.recover).toHaveBeenCalledTimes(1); expect(api.recover).toHaveBeenCalledWith(attempt, expect.any(AbortSignal));
  expect(screen.getByRole('button', { name: 'Recover local settlement' })).toBeDisabled();
});
it('keeps lookup available for readers and explains the actual header, original identity and no model replay', async () => {
  rights.delete('models:write'); mount(); await read();
  expect(screen.getByRole('button', { name: 'Recover local settlement' })).toBeDisabled();
  fireEvent.click(screen.getByText('Settlement lookup and recovery guide'));
  expect(await screen.findByText(/Copy the actual x-agf-attempt-id/)).toBeInTheDocument();
  expect(screen.getByText(/original caller needs models:write/)).toBeInTheDocument();
  expect(screen.queryByLabelText(/credential|model URL/i)).not.toBeInTheDocument();
});
it('shows unknown recovery with original ID retained and 404 cannot reenable writes', async () => {
  vi.mocked(api.recover).mockRejectedValue(new ApiRequestError('Lost reply', 0, 'network'));
  mount(); await read(); fireEvent.click(screen.getByRole('button', { name: 'Recover local settlement' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' }));
  await screen.findByText('Recovery result is unconfirmed. Keep the original ID and read; HTTP 404 does not unlock.');
  vi.mocked(api.read).mockRejectedValue(new ApiRequestError('Not found', 404, 'not-found'));
  fireEvent.click(screen.getByRole('button', { name: 'Read original settlement' }));
  await screen.findByText(/Not found/);
  expect(screen.getByDisplayValue(attempt)).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Recover local settlement' })).toBeDisabled();
});


it('distinguishes a terminal failure audit from success and unsent components from unknown charges', async () => {
  vi.mocked(api.read).mockResolvedValue(result(receipt({ state: 'settled', auditId: audit, recoveryAvailable: false,
    outcomeEvidence: 'sent-usage-unknown', components: [
      { usageId: attempt, evidence: 'not-sent', costMicro: null },
      { usageId: audit, evidence: 'sent-usage-unknown', costMicro: null },
    ] })));
  mount(); fireEvent.change(screen.getByRole('textbox', { name: 'Original model attempt ID' }), { target: { value: attempt } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original settlement' }));
  await screen.findByText('Local settlement committed');
  expect(screen.getByText('Terminal audit ID')).toBeInTheDocument();
  expect(screen.getByText('Not sent, no new charge')).toBeInTheDocument();
  expect(screen.getByText('Cost unknown; check the settlement charge state')).toBeInTheDocument();
  expect(screen.queryByText('Successful audit ID')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Recover local settlement' })).toBeDisabled();
});

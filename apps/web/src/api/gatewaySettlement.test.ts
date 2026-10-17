import { expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { gatewaySettlementApi as api } from './gatewaySettlement';

vi.mock('./transport', () => ({ callApi: vi.fn() }));
it('uses only the original path, disables fixture fallback and sends no execution payload', () => {
  const controller = new AbortController();
  api.read('original/id', controller.signal); api.recover('original/id', controller.signal);
  expect(callApi).toHaveBeenNthCalledWith(1, '/api/v1/gateway/attempts/original%2Fid', expect.any(Function),
    { noFallback: true, signal: controller.signal });
  expect(callApi).toHaveBeenNthCalledWith(2, '/api/v1/gateway/attempts/original%2Fid/recover', expect.any(Function),
    { method: 'POST', body: {}, noFallback: true, signal: controller.signal });
});

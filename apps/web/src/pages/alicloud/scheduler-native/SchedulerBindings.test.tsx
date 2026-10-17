import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import type { Binding } from './types';
import SchedulerNativePanel from './SchedulerNativePanel';
import { binding, boundJob, deferred, job, observationId, receipt, result, state } from './testFixtures';
import { adopt, installHarness, mockRead, mount, readOriginal, save } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('retains cross-page assignments and submits exact int64 strings with short canonical kinds', async () => {
  const first = receipt(), lastId = '9223372036854775807';
  const read = vi.spyOn(api, 'receipt').mockImplementation(async (id, page) => result(receipt({ requestId: id, total: 51,
    observation: { ...first.observation!, jobs: page === 2 ? [job(lastId)] : first.observation!.jobs, page: page ?? 1, total: 51, totalPages: 2 } })));
  const bind = vi.spyOn(api, 'bind').mockResolvedValue(result(binding({ version: 4 }))), observe = vi.spyOn(api, 'observe');
  mount(<SchedulerNativePanel />); await readOriginal(); await adopt();
  fireEvent.click(within(screen.getByLabelText('Observed job pagination')).getByTitle('2')); await screen.findByText(`Actual job ${lastId}`);
  fireEvent.mouseDown(screen.getByRole('combobox', { name: `Assign task ${lastId}` }));
  fireEvent.click(await screen.findByText('archive → cold-archive', { selector: '.ant-select-item-option-content' }));
  expect(bind).not.toHaveBeenCalled(); expect(read).toHaveBeenLastCalledWith(observationId, 2, expect.any(AbortSignal), 50);
  fireEvent.click(within(screen.getByLabelText('Observed job pagination')).getByTitle('1')); await screen.findByText('Actual job 9007199254741002');
  await save(); await waitFor(() => expect(bind).toHaveBeenCalledTimes(1));
  expect(bind.mock.calls[0][0]).toMatchObject({ action: 'replace', expected_version: 3, configuration_version: 1,
    observation_id: observationId, confirm_local_only: true,
    bindings: [{ kind: 'report', job_id: '9007199254741002' }, { kind: 'archive', job_id: lastId }] });
  expect(observe).not.toHaveBeenCalled();
});
it('keeps choices and CAS base after 409 and GET comparison until explicit adoption', async () => {
  mockRead(); const bind = vi.spyOn(api, 'bind').mockRejectedValue(new Error('Binding version conflict 409'));
  mount(<SchedulerNativePanel />); await readOriginal(); await adopt(); await save(); await screen.findByText('Binding version conflict 409');
  const originalId = bind.mock.calls[0][0].request_id;
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: binding({ version: 8 }) })));
  fireEvent.click(screen.getByRole('button', { name: /Reload local state/ })); await screen.findByText('3 / 8');
  expect(screen.getAllByText('9007199254741002').length).toBeGreaterThan(0); expect(bind).toHaveBeenCalledTimes(1);
  await adopt(); expect(screen.getByText('8 / 8')).toBeInTheDocument(); await save();
  await waitFor(() => expect(bind).toHaveBeenCalledTimes(2)); expect(bind.mock.calls[1][0]).toMatchObject({ expected_version: 8,
    bindings: [{ kind: 'report', job_id: '9007199254741002' }] }); expect(bind.mock.calls[1][0].request_id).not.toBe(originalId);
});
it('requires explicit empty replacement and refuses stale or ineligible observations', async () => {
  const expired = receipt({ finishedAt: new Date(Date.now() - 301000).toISOString() });
  vi.spyOn(api, 'receipt').mockResolvedValue(result(expired)); const bind = vi.spyOn(api, 'bind').mockResolvedValue(result(binding()));
  mount(<SchedulerNativePanel />); await readOriginal(); await adopt();
  expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled(); expect(bind).not.toHaveBeenCalled();
  vi.mocked(api.receipt).mockResolvedValue(result(receipt({ observation: { ...receipt().observation!, jobs: [job('9007199254741002', { enabled: null, status: null })] } })));
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ }));
  await screen.findByText('Unknown / http'); await adopt();
  expect(screen.getByRole('combobox', { name: 'Assign task 9007199254741002' })).toBeDisabled();
  const remove = screen.getAllByRole('button', { name: 'Remove selection' }).find(button => !button.hasAttribute('disabled'))!;
  fireEvent.click(remove); expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled();
  await save(); await waitFor(() => expect(bind).toHaveBeenCalledWith(expect.objectContaining({ bindings: [], confirm_local_only: true })));
});
it('discards a late binding result and draft on a tenant roundtrip without another mutation', async () => {
  mockRead(); const pending = deferred<ApiResult<Binding>>(), bind = vi.spyOn(api, 'bind').mockReturnValue(pending.promise);
  mount(<SchedulerNativePanel />); await readOriginal(); await adopt(); await save(); await waitFor(() => expect(bind).toHaveBeenCalledTimes(1));
  const id = bind.mock.calls[0][0].request_id;
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: binding({ version: 0, locallyEnabled: false, items: [] }) })));
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); });
  await act(async () => pending.resolve(result(binding({ version: 4 })))); await screen.findByText('0 / 0');
  expect(screen.queryByText(id)).not.toBeInTheDocument(); expect(screen.queryByText('Original observation receipt')).not.toBeInTheDocument();
  expect(bind).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled();
});

function savedRow(kind = 'report', runtime = 'report-generate') {
  const region = screen.getByRole('region', { name: 'Saved associations and adoption proofs' });
  return within(region).getByText(`${kind} → ${runtime}`).closest('tr')!;
}
function openProof(kind = 'report', runtime = 'report-generate') {
  fireEvent.click(within(savedRow(kind, runtime)).getByRole('button', { name: 'View qualification evidence' }));
  return screen.getByRole('region', { name: `Association proof ${kind}` });
}

it('keeps authenticated saved qualification after 300 seconds while a stale observation cannot be readopted', async () => {
  const old = new Date(Date.now() - 86400000).toISOString(), item = boundJob();
  const saved = binding({ evidenceFresh: false, verifiedAt: old, items: [boundJob({ decisionAt: old,
    adoptedProof: { ...item.adoptedProof!, observedAt: old }, currentEvidence: { ...item.currentEvidence!, observedAt: old } })] });
  const oldReceipt = receipt({ startedAt: old, submittedAt: old, finishedAt: old, observedAt: old,
    leaseExpiresAt: new Date(Date.parse(old) + 120000).toISOString() });
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: saved, latestObservation: oldReceipt, recentObservations: [oldReceipt] })));
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(oldReceipt));
  const bind = vi.spyOn(api, 'bind'), observe = vi.spyOn(api, 'observe');
  mount(<SchedulerNativePanel />); await screen.findByText('Saved per-job qualifications');
  expect(within(savedRow()).getByText('eligible')).toBeInTheDocument();
  expect(screen.getByText('The original 300-second adoption window elapsed; saved qualifications do not expire because of this')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Disable local associations' })).toBeEnabled();
  const proof = openProof();
  expect(within(proof).getAllByText(old)).toHaveLength(3);
  expect(read).not.toHaveBeenCalled();
  fireEvent.click(within(proof).getByRole('button', { name: 'Read original adopted observation (GET only)' }));
  await screen.findByText('Original observation receipt');
  expect(read).toHaveBeenCalledWith(observationId, 1, expect.any(AbortSignal), 50);
  await adopt(); expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled();
  expect(within(savedRow()).getByText('eligible')).toBeInTheDocument();
  expect(bind).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});

it('retains original proof and local qualification when the user explicitly archives its observation body', async () => {
  const saved = binding(), item = saved.items[0];
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: saved })));
  const read = mockRead(), bind = vi.spyOn(api, 'bind'), observe = vi.spyOn(api, 'observe');
  const archive = vi.spyOn(api, 'archive').mockResolvedValue(result({ generation: 8, archivedCount: 1, storedContentBytes: 0, stateVersion: 5 }));
  mount(<SchedulerNativePanel />); await readOriginal(); openProof();
  const ledgerRow = screen.getByRole('button', { name: 'Read original ID' }).closest('tr')!;
  fireEvent.click(within(ledgerRow).getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: /Archive selected bodies/ }));
  const confirm = await screen.findByRole('button', { name: 'Confirm body archive' });
  await waitFor(() => { expect(confirm).toBeVisible(); expect(confirm).toBeEnabled(); });
  expect(archive).not.toHaveBeenCalled();
  const tombstone = receipt({ status: 'archived', originalStatus: 'observed', archived: true,
    archivedAt: new Date().toISOString(), observation: null, available: false, archivable: false, allowedActions: ['read_receipt'] });
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: saved, latestObservation: tombstone,
    recentObservations: [], generation: 8, detailedObservationCount: 0, archivedCount: 1, storedContentBytes: 0 })));
  read.mockResolvedValue(result(tombstone)); fireEvent.click(confirm);
  await screen.findByText(/No observation body is available/);
  expect(archive).toHaveBeenCalledWith({ expected_generation: 7, request_ids: [observationId] });
  const proof = screen.getByRole('region', { name: 'Association proof report' });
  expect(within(proof).getByText(`${item.adoptedProof!.proofId} · 3`)).toBeInTheDocument();
  expect(within(proof).getByText('Original adoption proof (independent of archived body)')).toBeInTheDocument();
  expect(within(savedRow()).getByText('eligible')).toBeInTheDocument();
  expect(screen.getByText('CAS 3 · adoption 3')).toBeInTheDocument();
  expect(read).toHaveBeenCalledTimes(2); expect(bind).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});

it('preserves draft/CAS and a revoked decision despite positive evidence until a fresh observation and explicit replacement', async () => {
  const archiveJob = '9007199254741003', negativeId = '70000000-0000-4000-8000-000000000001';
  const positiveId = '80000000-0000-4000-8000-000000000001', initial = boundJob();
  const archiveItem = boundJob({ kind: 'archive', runtimeName: 'cold-archive', jobId: archiveJob,
    adoptedProof: { ...initial.adoptedProof!, proofId: '60000000-0000-4000-8000-000000000002', kind: 'archive', jobId: archiveJob } });
  const original = binding({ items: [boundJob(), archiveItem] });
  const first = receipt({ total: 2, observation: { ...receipt().observation!, jobs: [job(), job(archiveJob)], total: 2 } });
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: original, latestObservation: first, recentObservations: [first] })));
  vi.spyOn(api, 'receipt').mockResolvedValue(result(first)); const bind = vi.spyOn(api, 'bind'), observe = vi.spyOn(api, 'observe');
  mount(<SchedulerNativePanel />); await readOriginal(); await adopt();
  const revoked = binding({ version: 8, adoptionVersion: 3, status: 'revoked', current: false, eligibility: 'revoked',
    items: [boundJob(), { ...archiveItem, eligibility: 'revoked', reason: 'job_disabled', decisionObservationId: negativeId,
      currentEvidence: { ...archiveItem.currentEvidence!, observationId: positiveId, jobPresent: true, httpJob: true, enabled: true } }] });
  const positive = receipt({ ...first, requestId: positiveId });
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: revoked, latestObservation: positive, recentObservations: [positive] })));
  fireEvent.click(screen.getByRole('button', { name: /Reload local state/ })); await screen.findByText('3 / 8');
  expect(within(savedRow()).getByText('eligible')).toBeInTheDocument();
  expect(within(savedRow('archive', 'cold-archive')).getByText('revoked')).toBeInTheDocument();
  const proof = openProof('archive', 'cold-archive');
  expect(within(proof).getByText(negativeId)).toBeInTheDocument(); expect(within(proof).getByText(positiveId)).toBeInTheDocument();
  expect(within(proof).getByText('http / Yes / Yes')).toBeInTheDocument();
  expect(within(proof).getByText(/This item requires explicit readoption/)).toBeInTheDocument();
  expect(screen.getAllByText(archiveJob).length).toBeGreaterThan(1);
  expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled();
  expect(bind).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
  observe.mockImplementation(async input => {
    const observed = receipt({ requestId: input.request_id, total: 2,
      observation: { ...receipt().observation!, jobs: [job(), job(archiveJob)], total: 2 } });
    vi.mocked(api.state).mockResolvedValue(result(state({ bindings: revoked, latestObservation: observed, recentObservations: [observed] })));
    return result(observed);
  });
  fireEvent.click(screen.getByRole('button', { name: /^Observe with a new request ID$/ }));
  await waitFor(() => expect(observe).toHaveBeenCalledTimes(1));
  const freshId = observe.mock.calls[0][0].request_id;
  await waitFor(() => expect(screen.getByRole('textbox', { name: 'Original observation ID' })).toHaveValue(freshId));
  await screen.findByText(`Actual job ${archiveJob}`);
  expect(bind).not.toHaveBeenCalled(); expect(within(savedRow('archive', 'cold-archive')).getByText('revoked')).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Adopt latest local version and the read observation (keep selections)' })).toBeEnabled());
  await adopt(); expect(screen.getByText('8 / 8')).toBeInTheDocument();
  const at = new Date().toISOString();
  const renewed = binding({ version: 9, observationId: freshId, items: [boundJob(), archiveItem].map((item, index) => ({
    ...item, decisionObservationId: freshId, decisionAt: at,
    adoptedProof: { ...item.adoptedProof!, proofId: `90000000-0000-4000-8000-00000000000${index + 1}`,
      adoptionVersion: 9, observationId: freshId, observedAt: at },
    currentEvidence: { ...item.currentEvidence!, observationId: freshId, observedAt: at },
  })) });
  const adopted = receipt({ ...first, requestId: freshId });
  bind.mockImplementation(async () => { vi.mocked(api.state).mockResolvedValue(result(state({ bindings: renewed,
    latestObservation: adopted, recentObservations: [adopted] }))); return result(renewed); });
  await save(); await waitFor(() => expect(bind).toHaveBeenCalledTimes(1));
  expect(bind.mock.calls[0][0]).toMatchObject({ action: 'replace', expected_version: 8, observation_id: freshId,
    bindings: [{ kind: 'report', job_id: '9007199254741002' }, { kind: 'archive', job_id: archiveJob }] });
  await waitFor(() => expect(within(savedRow('archive', 'cold-archive')).getByText('eligible')).toBeInTheDocument());
});

it('shows a legacy missing proof as unverified and never gains eligibility or writes from a positive GET', async () => {
  const legacy = binding({ adoptionVersion: 0, status: 'unverified', current: false, eligibility: 'unverified', qualificationVerified: false,
    items: [boundJob({ eligibility: 'unverified', reason: 'proof_unavailable', adoptedProof: null,
      currentEvidence: null, decisionObservationId: null, decisionAt: null })] });
  vi.mocked(api.state).mockResolvedValue(result(state({ bindings: legacy })));
  mockRead(); const bind = vi.spyOn(api, 'bind'), observe = vi.spyOn(api, 'observe');
  mount(<SchedulerNativePanel />); await screen.findByText('Saved per-job qualifications');
  const proof = openProof(); expect(within(savedRow()).getByText('unverified')).toBeInTheDocument();
  expect(within(proof).getByText('Original adoption proof unavailable; qualification unverified')).toBeInTheDocument();
  await readOriginal(); expect(within(savedRow()).getByText('unverified')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled();
  expect(bind).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useSearchParams } from 'react-router-dom';
import { teamManagementApi } from '@/api/teamManagement';
import { useAuthStore } from '@/stores/authStore';
import { newRequestId } from '@/utils/requestId';
import type { TeamAction, TeamManagement, TeamOperation, TeamPreview, TeamRecoveryAction, TeamUserOption } from '@/types/teamManagement';
import { currentTeamPreview, currentTeamRecovery, initialTeamDraft, teamChange, type TeamDraftValues } from './teamDraftState';

interface Props {
  data: TeamManagement;
  ready: boolean;
  canPrepare: boolean;
  canApply: boolean;
  refresh: () => Promise<unknown>;
}
export function useTeamManagement({ data, ready, canPrepare, canApply, refresh }: Props) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const requestedTeam = params.get('team');
  const initialName = requestedTeam ?? data.items.find(item => item.currentAvailable)?.teamName;
  const initialTeam = data.items.find(item => item.teamName === initialName);
  const [draftState, setDraftState] = useState(() => ({ urlTeam: requestedTeam,
    values: initialTeamDraft(initialTeam ? 'update' : 'create', initialTeam) }));
  const baseDraft = draftState.urlTeam === requestedTeam ? draftState.values
    : { ...initialTeamDraft(initialTeam ? 'update' : 'create', initialTeam), ...(requestedTeam ? { teamName: requestedTeam } : {}) };
  // A retained tab follows navigation without unmounting an operation already in flight.
  // While membership is kept, show the complete baseline rather than a partial picker page.
  const draft = baseDraft.action === 'update' && !baseDraft.replaceMembers
    ? { ...baseDraft, memberNames: [...(data.items.find(item => item.teamName === baseDraft.teamName)?.memberNames ?? [])] }
    : baseDraft;
  const [preview, setPreview] = useState<TeamPreview>();
  const [previewDraftKey, setPreviewDraftKey] = useState<string>();
  const [previewLocationKey, setPreviewLocationKey] = useState<string>();
  const [confirmed, setConfirmed] = useState(false);
  const [liveConfirmed, setLiveConfirmed] = useState(false);
  const [directory, setDirectory] = useState(data.userDirectory);
  const [options, setOptions] = useState<TeamUserOption[]>(data.userDirectory?.items ?? []);
  const [usersFailed, setUsersFailed] = useState(false);
  const [operation, setOperation] = useState<TeamOperation | undefined>(() =>
    data.operations.find(item => item.requestId === params.get('request_id')));
  const [pendingDelete, setPendingDelete] = useState<string>();
  const requestId = params.get('request_id') ?? undefined;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [now, setNow] = useState(Date.now);
  const [consumedIds, setConsumedIds] = useState<string[]>([]);
  const consumed = useRef(new Set<string>());
  const running = useRef(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    const timer = setInterval(() => setNow(Date.now()), 10_000);
    return () => { alive.current = false; clearInterval(timer); };
  }, []);
  const team = data.items.find(item => item.teamName === draft.teamName);
  const cloudConfirmed = data.mocked === true || liveConfirmed;
  const directoryUsable = !!directory && !usersFailed && directory.selectionUsable && directory.pageComplete
    && directory.scopeId === data.scopeId && directory.configurationVersion === data.configurationVersion
    && directory.mocked === data.mocked && Date.parse(directory.observedAt) + 300_000 > now;
  const change = teamChange(draft, team);
  const activePreview = preview?.teamName === draft.teamName && preview.action === draft.action
    && previewLocationKey === location.key && previewDraftKey === JSON.stringify(change) ? preview : undefined;
  const usablePreview = !!activePreview && ready && currentTeamPreview(activePreview, data, now) && !consumedIds.includes(activePreview.id);
  const visibleOperation = operation?.requestId === requestId ? operation : undefined;
  const blockedDelete = pendingDelete === draft.teamName || (operation?.teamName === draft.teamName && operation.action === 'delete'
    && operation.status !== 'verified' && operation.status !== 'failed');
  const canPreview = canPrepare && ready && cloudConfirmed && !!change && !blockedDelete && draft.memberNames.length <= 200;
  const context = () => ({ request_id: newRequestId(), configuration_version: data.configurationVersion,
    confirm_live: data.mocked !== true && liveConfirmed });
  const invalidatePreview = () => { setPreview(undefined); setPreviewDraftKey(undefined); setPreviewLocationKey(undefined); setConfirmed(false); };
  const changeDraft = (values: TeamDraftValues) => { invalidatePreview(); setDraftState({ urlTeam: requestedTeam, values }); };
  const chooseTeam = (name: string) => {
    invalidatePreview();
    setDraftState({ urlTeam: name, values: initialTeamDraft(draft.action === 'create' ? 'update' : draft.action,
      data.items.find(item => item.teamName === name)) });
    setParams(previous => { const next = new URLSearchParams(previous); next.set('team', name); return next; });
  };
  const chooseAction = (action: TeamAction) => changeDraft(initialTeamDraft(action,
    team ?? data.items.find(item => item.currentAvailable)));
  const run = async (perform: (isCurrent: () => boolean) => Promise<void>, refetch = false) => {
    if (running.current) return;
    running.current = true; setBusy(true); setError('');
    const starting = useAuthStore.getState();
    const isCurrent = () => alive.current && useAuthStore.getState().tenant?.id === starting.tenant?.id
      && useAuthStore.getState().tenant?.slug === starting.tenant?.slug
      && useAuthStore.getState().sessionGeneration === starting.sessionGeneration;
    try { await perform(isCurrent); }
    catch (cause) { if (isCurrent()) setError(cause instanceof Error ? cause.message : String(cause)); }
    finally {
      if (isCurrent()) {
        if (refetch) {
          try { await refresh(); }
          catch (cause) { if (isCurrent()) setError(cause instanceof Error ? cause.message : String(cause)); }
        }
        if (isCurrent()) { running.current = false; setBusy(false); }
      }
    }
  };
  const readUsers = async (nameLike: string, cursor?: string) => {
    if (!canPrepare || !ready || !cloudConfirmed || running.current) return;
    invalidatePreview();
    await run(async isCurrent => {
      try {
        const result = await teamManagementApi.observeUsers({ ...context(), ...(nameLike ? { name_like: nameLike } : {}), ...(cursor ? { cursor } : {}) });
        if (!isCurrent()) return;
        setDirectory(result.data); setUsersFailed(false);
        setOptions(previous => [...new Map([...previous, ...result.data.items].map(user => [user.name, user])).values()]);
      } catch (cause) { if (isCurrent()) setUsersFailed(true); throw cause; }
    });
  };
  const prepare = async () => {
    if (!canPreview || !change || running.current) return;
    invalidatePreview();
    await run(async isCurrent => {
      const result = await teamManagementApi.preview({ ...context(), expected_state_version: team?.stateVersion ?? 0,
        ...(directoryUsable && directory ? { user_snapshot_id: directory.snapshotId } : {}), change });
      if (isCurrent()) { setPreview(result.data); setPreviewDraftKey(JSON.stringify(change)); setPreviewLocationKey(location.key); }
    });
  };
  const refreshPreview = async () => {
    if (!activePreview || running.current) return;
    setConfirmed(false);
    await run(async isCurrent => { const result = await teamManagementApi.getPreview(activePreview.id); if (isCurrent()) setPreview(result.data); });
  };
  const apply = async () => {
    if (!canApply || !ready || !activePreview || !confirmed || !cloudConfirmed || running.current
      || consumed.current.has(activePreview.id) || !currentTeamPreview(activePreview, data, Date.now())) return;
    consumed.current.add(activePreview.id); setConsumedIds(values => [...values, activePreview.id]); setConfirmed(false); setOperation(undefined);
    if (activePreview.action === 'delete') setPendingDelete(activePreview.teamName);
    const request = { ...context(), preview_id: activePreview.id, expected_state_version: activePreview.expectedStateVersion, confirm_apply: true as const };
    setDraftState({ urlTeam: activePreview.teamName, values: draft });
    setParams(previous => { const next = new URLSearchParams(previous); next.set('tab', 'teams');
      next.set('team', activePreview.teamName); next.set('request_id', request.request_id); return next; }, { replace: true });
    await run(async isCurrent => {
      const result = await teamManagementApi.apply(request);
      if (isCurrent()) {
        setOperation(result.data);
        if (result.data.status === 'verified' || result.data.status === 'failed') setPendingDelete(undefined);
      }
    }, true);
  };
  const restore = async () => {
    if (!requestId || running.current) return;
    await run(async isCurrent => {
      const result = await teamManagementApi.list(requestId);
      if (!isCurrent()) return;
      const found = result.data.operations.find(item => item.requestId === requestId);
      if (found) {
        setOperation(found);
        if (found.status === 'verified' || found.status === 'failed') setPendingDelete(undefined);
      } else setError(t('teamManagement.restoreMissing'));
    });
  };
  const recover = async (action: TeamRecoveryAction) => {
    if (!visibleOperation || running.current || !visibleOperation.allowedActions.includes(action)) return;
    if (action !== 'read_receipt' && (!canPrepare || !ready || !cloudConfirmed || visibleOperation.busy
      || !currentTeamRecovery(visibleOperation, data))) return;
    if (action === 'retry_inventory' && !canApply) return;
    await run(async isCurrent => {
      const result = action === 'read_receipt' ? await teamManagementApi.getOperation(visibleOperation.id)
        : action === 'observe' ? await teamManagementApi.observe(visibleOperation.id, context())
          : await teamManagementApi.publish(visibleOperation.id, context());
      if (isCurrent()) {
        setOperation(result.data);
        if (result.data.status === 'verified' || result.data.status === 'failed') setPendingDelete(undefined);
      }
    }, action !== 'read_receipt');
  };
  const viewOperation = (value: TeamOperation) => {
    setOperation(value); invalidatePreview();
    setParams(previous => { const next = new URLSearchParams(previous); next.set('request_id', value.requestId); return next; });
  };
  return { draft, team, preview: activePreview, confirmed, setConfirmed, liveConfirmed,
    setLiveConfirmed: (value: boolean) => { setLiveConfirmed(value); setConfirmed(false); },
    directory, directoryUsable, options, operation: visibleOperation, requestId, busy, error, canPreview, usablePreview,
    changeDraft, chooseTeam, chooseAction, readUsers, prepare, refreshPreview, apply, restore, recover, viewOperation };
}

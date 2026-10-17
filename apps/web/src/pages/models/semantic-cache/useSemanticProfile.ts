import { useCallback, useEffect, useRef, useState } from 'react';
import { semanticProfileApi, type SemanticProfile, type SemanticProfileInput, type SemanticSettings } from '@/api/semanticCacheProfile';
import { gatewayApi, type GatewayEndpoint } from '@/api/gateway';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import { defaultSettings, validInput, validVersion } from './validation';

type Draft = Pick<SemanticProfileInput, 'enabled' | 'settings'>;
type Blocked = 'conflict' | 'unknown';
const cloneDraft = (profile: Draft): Draft => ({ enabled: profile.enabled,
  settings: profile.settings ? { ...profile.settings } : null });

export function useSemanticProfile(canRead: boolean, canWrite: boolean) {
  const [current, setCurrent] = useState<SemanticProfile>();
  const [baseline, setBaseline] = useState<number>();
  const [draft, setDraft] = useState<Draft>({ enabled: false, settings: null });
  const [endpoints, setEndpoints] = useState<GatewayEndpoint[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [blocked, setBlocked] = useState<Blocked>();
  const [submitted, setSubmitted] = useState<SemanticProfileInput>();
  const [readAfterSave, setReadAfterSave] = useState(false);
  const alive = useRef(true);
  const locked = useRef(false);
  const initialized = useRef(false);
  const outcome = useRef<Blocked | undefined>(undefined);
  const run = useCallback(async (work: (stillCurrent: () => boolean) => Promise<void>) => {
    if (locked.current) return;
    locked.current = true; setBusy(true); setError(undefined);
    const scope = useAuthStore.getState();
    const stillCurrent = () => alive.current && useAuthStore.getState().tenant?.id === scope.tenant?.id
      && useAuthStore.getState().sessionGeneration === scope.sessionGeneration;
    try { await work(stillCurrent); }
    catch (cause) { if (stillCurrent()) setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { locked.current = false; if (stillCurrent()) setBusy(false); }
  }, []);
  const read = useCallback(() => !canRead ? Promise.resolve() : run(async stillCurrent => {
    const profile = await semanticProfileApi.read();
    if (!stillCurrent()) return;
    if (!validVersion(profile.data.version)) throw new Error('服务器版本无效 / Invalid server version');
    setCurrent(profile.data);
    if (!initialized.current) {
      initialized.current = true; setBaseline(profile.data.version); setDraft(cloneDraft(profile.data));
    }
    if (outcome.current) setReadAfterSave(true);
    // An explicit GET updates the server view, never a user's draft or expected version.
    const inventory = await gatewayApi.list();
    if (stillCurrent()) setEndpoints(inventory.data.items);
  }), [canRead, run]);
  useEffect(() => {
    alive.current = true;
    void read();
    return () => { alive.current = false; };
  }, [read]);
  const updateSettings = (patch: Partial<SemanticSettings>) => {
    if (!canWrite || locked.current || outcome.current) return;
    setDraft(old => ({ ...old, settings: { ...(old.settings ?? defaultSettings), ...patch } }));
  };
  const setEnabled = (enabled: boolean) => {
    if (!canWrite || locked.current || outcome.current) return;
    setDraft(old => ({ enabled, settings: enabled && !old.settings ? { ...defaultSettings } : old.settings }));
  };
  const save = () => run(async stillCurrent => {
    if (!canWrite || outcome.current || baseline === undefined) return;
    const body: SemanticProfileInput = { expected_version: baseline, ...cloneDraft(draft) };
    if (!validInput(body)) throw new Error('请检查端点、版本标签、维度和费用 / Check endpoints, revision labels, dimensions and price');
    // Freeze the body before PUT; an uncertain response must not silently create another attempt.
    setSubmitted(body); setReadAfterSave(false);
    outcome.current = 'unknown'; setBlocked('unknown');
    try {
      const reply = await semanticProfileApi.save(body);
      if (!stillCurrent()) return;
      if (!validVersion(reply.data.version) || reply.data.version !== body.expected_version + 1) {
        throw new Error('请读取当前配置确认保存结果 / Read the current configuration to check the save');
      }
      setCurrent(reply.data); setBaseline(reply.data.version); setDraft(cloneDraft(reply.data));
      outcome.current = undefined; setBlocked(undefined); setSubmitted(undefined);
    } catch (cause) {
      if (stillCurrent() && cause instanceof ApiRequestError && cause.status >= 400 && cause.status < 500 && cause.status !== 408) {
        const next = cause.status === 409 ? 'conflict' : undefined;
        outcome.current = next; setBlocked(next);
        if (!next) setSubmitted(undefined);
      }
      throw cause;
    }
  });
  const adoptCurrent = () => {
    if (!canWrite || locked.current || !current || (outcome.current && !readAfterSave)) return;
    setBaseline(current.version); setDraft(cloneDraft(current));
    outcome.current = undefined; setBlocked(undefined); setSubmitted(undefined); setError(undefined); setReadAfterSave(false);
  };
  return { current, baseline, draft, endpoints, busy, error, blocked, submitted, readAfterSave,
    read, updateSettings, setEnabled, save, adoptCurrent };
}

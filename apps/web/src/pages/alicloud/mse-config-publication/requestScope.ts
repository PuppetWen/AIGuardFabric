import { useAuthStore } from '@/stores/authStore';
import { newRequestId } from '@/utils/requestId';

const parameter = 'publication_request_id', ownership = 'agfMsePublicationRequest';
const documentId = newRequestId();
interface Identity { tenantId: string | null; tenantSlug: string | null; generation: number }
interface Owner extends Identity { requestId: string; documentId: string }
function identity(): Identity {
  const auth = useAuthStore.getState();
  return { tenantId: auth.tenant?.id ?? null, tenantSlug: auth.tenant?.slug ?? null, generation: auth.sessionGeneration };
}
function historyState(): Record<string, unknown> {
  const state: unknown = window.history.state;
  return typeof state === 'object' && state !== null && !Array.isArray(state) ? { ...state } : {};
}
function validOwner(value: unknown): value is Owner {
  if (typeof value !== 'object' || value === null) return false;
  const owner = value as Partial<Owner>;
  return typeof owner.requestId === 'string' && typeof owner.documentId === 'string'
    && (owner.tenantId === null || typeof owner.tenantId === 'string')
    && (owner.tenantSlug === null || typeof owner.tenantSlug === 'string')
    && typeof owner.generation === 'number' && Number.isInteger(owner.generation);
}
const sameIdentity = (left: Identity, right: Identity) => left.tenantId === right.tenantId
  && left.tenantSlug === right.tenantSlug && left.generation === right.generation;

/** Unowned external links prefill only. No credential material is recorded in history. */
export function initialRequest(): string {
  const id = new URL(window.location.href).searchParams.get(parameter) ?? '', owner = historyState()[ownership];
  if (!id || owner === undefined) return id;
  if (!validOwner(owner)) return '';
  if (owner.requestId !== id) return id; // A newly supplied link is a new explicit recovery input.
  const current = identity();
  if (owner.tenantId !== current.tenantId || owner.tenantSlug !== current.tenantSlug) return '';
  // authStore starts a refreshed document at generation 1; subsequent changes represent a new scope.
  return (owner.documentId === documentId ? owner.generation === current.generation : current.generation === 1) ? id : '';
}
export function rememberRequest(id: string) {
  const url = new URL(window.location.href); url.searchParams.set(parameter, id);
  window.history.replaceState({ ...historyState(), [ownership]: { ...identity(), requestId: id, documentId } }, '', url);
}
function forgetRequest() {
  const url = new URL(window.location.href), state = historyState();
  url.searchParams.delete(parameter); delete state[ownership];
  window.history.replaceState(state, '', url);
}
/** Observe actual scope changes, including A -> B -> A before React renders again. */
export function watchRequestScope(onChange: () => void): () => void {
  const id = initialRequest();
  if (id) rememberRequest(id); else forgetRequest();
  let previous = identity();
  return useAuthStore.subscribe(() => {
    const next = identity();
    if (!sameIdentity(previous, next)) { forgetRequest(); onChange(); }
    previous = next;
  });
}

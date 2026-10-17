import type { Action, Change, JobKind, SchedulePatch, SchedulerJob } from './types';
export interface Draft { action: Action; kind: JobKind | ''; name: string; patch: Record<keyof Required<SchedulePatch>, string>;
  replace: (keyof SchedulePatch)[] }
export const blankDraft = (): Draft => ({ action: 'create_disabled', kind: '', name: '', patch: { time_type: '1',
  time_expression: '', timezone: 'UTC', calendar: '', max_attempt: '0', attempt_interval: '0' },
  replace: ['time_type', 'time_expression', 'timezone', 'calendar', 'max_attempt', 'attempt_interval'] });
function integer(value: string, max: number) {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || Number(value) > max) throw new Error('Invalid integer'); return Number(value);
}
function text(value: string, max: number, empty = false) {
  if ((!empty && !value) || new TextEncoder().encode(value).length > max || value.trim() !== value || [...value].some(char => char.charCodeAt(0) < 32 || (char.charCodeAt(0) >= 127 && char.charCodeAt(0) <= 159))) throw new Error('Invalid text');
  return value;
}
export function buildChange(draft: Draft, job: SchedulerJob | null): Change {
  if (!draft.kind) throw new Error('Choose a task kind');
  if (draft.action === 'disable' || draft.action === 'enable') {
    const before = draft.action === 'disable';
    if (!job?.httpJob || job.kind !== 'http' || job.enabled !== before || job.status !== Number(before)) throw new Error('Choose a known HTTP Job in the required state');
    return { action: draft.action };
  }
  if (draft.action === 'update_schedule' && (!job?.httpJob || job.enabled !== false || job.status !== 0)) throw new Error('Disable the HTTP Job first');
  const patch: SchedulePatch = {};
  for (const field of draft.replace) {
    const value = draft.patch[field];
    if (field === 'time_type') { const kind = Number(value); if (!['-1', '1', '3', '5', '100'].includes(value)) throw new Error('Choose a documented time type'); patch.time_type = kind; }
    else if (field === 'max_attempt') patch.max_attempt = integer(value, 1000);
    else if (field === 'attempt_interval') patch.attempt_interval = integer(value, 86400);
    else patch[field] = text(value, field === 'timezone' ? 64 : 256, true);
  }
  if (!Object.keys(patch).length) throw new Error('Choose a field to change');
  if (draft.action === 'create_disabled' && (patch.time_type === undefined || !patch.timezone
    || patch.max_attempt === undefined || patch.attempt_interval === undefined)) throw new Error('Set all required creation fields explicitly');
  const existing = draft.action === 'update_schedule' ? job : null;
  const time = patch.time_type ?? existing?.schedule.kind, expression = patch.time_expression ?? existing?.schedule.expression;
  if (![1, 3, 5, -1, 100].includes(time ?? 0) || ([1, 3, 5].includes(time ?? 0) && !expression)
    || ([-1, 100].includes(time ?? 0) && !!expression)) throw new Error('Time type and expression are incompatible');
  if (draft.action === 'create_disabled') return { action: 'create_disabled', declaration: { kind: draft.kind,
    name: text(draft.name, 200), schedule: patch, total: 1 } };
  return { action: 'update_schedule', patch };
}

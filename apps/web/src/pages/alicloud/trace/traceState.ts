import type { TraceDraft, TraceQuery } from '@/types/agentTeamsTrace';

const day = 86_400_000;
export function initialTraceDraft(traceId = ''): TraceDraft {
  const until = new Date(Math.ceil(Date.now() / 1000) * 1000);
  return { traceId, from: new Date(until.getTime() - day).toISOString().slice(0, 19),
    until: until.toISOString().slice(0, 19), limit: 50 };
}
export function traceQuery(draft: TraceDraft, now: number): TraceQuery {
  const id = draft.traceId.trim();
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) throw new Error('Trace ID: 1–128 identifier characters / Trace ID 须为1至128个标识字符');
  const date = (value: string) => {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) throw new Error('Enter both UTC dates / 请填写起止 UTC 时间');
    // datetime-local normalizes :00 seconds away; preserve the exact UTC instant.
    const normalized = value.length === 16 ? `${value}:00` : value;
    const parsed = new Date(`${normalized}Z`);
    if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 19) !== normalized) throw new Error('Invalid UTC date / UTC 时间无效');
    return parsed;
  };
  const from = date(draft.from), until = date(draft.until);
  if (from >= until || until.getTime() - from.getTime() > 30 * day || until.getTime() > now + 60_000)
    throw new Error('Use a positive window of at most 30 days; end ≤ current time +60s / 时间窗须为正且不超过30天，结束时间不得超过当前时间60秒');
  if (!Number.isInteger(draft.limit) || draft.limit < 1 || draft.limit > 200) throw new Error('Page size must be 1–200 / 每页须为1至200条');
  return { traceId: id, from: from.toISOString(), until: until.toISOString(), limit: draft.limit };
}
// Event-only actual clock validation. Rendering does not call this function.
export const currentTraceQuery = (draft: TraceDraft) => traceQuery(draft, Date.now());

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';
import { identifier } from './config.mjs';

export const storage = new AsyncLocalStorage();
const controls = /[\x00-\x1f\x7f-\x9f]/;
function name(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 512 || controls.test(value)) {
    throw new TypeError('Worker and Team names must match inventory');
  }
  return value;
}
export class Worker {
  constructor(workerName, team = null) {
    this.name = name(workerName);
    this.team = team == null ? null : name(team);
    Object.freeze(this);
  }
}
function field(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
export function extract(carrier) {
  try {
    if (!carrier || Object.getPrototypeOf(carrier) !== Object.prototype ||
        Object.keys(carrier).some(k => !['trace_id', 'span_id', 'task_id'].includes(k))) return null;
    const trace = field(carrier, 'trace_id'), span = field(carrier, 'span_id'), task = field(carrier, 'task_id');
    if (typeof trace !== 'string' || !/^[0-9a-f]{32}$/.test(trace) || /^0+$/.test(trace) ||
        typeof span !== 'string' || !/^[0-9a-f]{16}$/.test(span) || /^0+$/.test(span)) return null;
    if (task != null) identifier(task, 'taskId');
    return { traceId: trace, spanId: span, taskId: task ?? null };
  } catch { return null; }
}
export function inject() {
  const current = storage.getStore();
  if (!current) return null;
  return { trace_id: current.traceId, span_id: current.spanId,
    ...(current.taskId === null ? {} : { task_id: current.taskId }) };
}
export function child(owner, worker, options = {}) {
  const current = storage.getStore();
  const parent = options.carrier !== undefined ? extract(options.carrier) : current?.owner === owner ? current : null;
  return Object.freeze({ owner, worker, traceId: parent?.traceId ?? randomBytes(16).toString('hex'),
    spanId: randomBytes(8).toString('hex'), parentSpanId: parent?.spanId ?? null,
    taskId: options.taskId == null ? parent?.taskId ?? null : identifier(options.taskId, 'taskId') });
}

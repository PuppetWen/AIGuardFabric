import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { child } from './context.mjs';

export function failure(error) {
  try { return ['AbortError', 'TimeoutError'].includes(error?.name) ? 'unknown' : 'error'; }
  catch { return 'unknown'; }
}
export function event(context, kind, from = null, to = null, status = 'unknown', duration = null, message = null) {
  return { event_id: randomUUID().replaceAll('-', ''), event_time: new Date().toISOString(), kind,
    from_team: from?.team ?? null, from_worker: from?.name ?? null,
    to_team: to?.team ?? null, to_worker: to?.name ?? null, task_id: context.taskId,
    trace_id: context.traceId, span_id: context.spanId, parent_span_id: context.parentSpanId,
    status, duration_ms: duration, message };
}
export class Span {
  #finished = false;
  #started = performance.now();
  constructor(collector, kind, worker, target, options) {
    this.collector = collector;
    this.kind = kind;
    this.worker = worker;
    this.target = target;
    this.options = options;
    this.context = child(collector, worker, options);
  }
  begin() { this.#started = performance.now(); }
  finish(status, count) {
    if (this.#finished) return;
    this.#finished = true;
    try {
      const duration = Math.min(7 * 86_400_000, Math.max(0, Math.round(performance.now() - this.#started)));
      const preview = this.options.capture === 'shape'
        ? `operation=${this.options.operation}; arguments=${count}; values=omitted` : null;
      this.collector.record(event(this.context, this.kind, this.worker, this.target, status, duration, preview));
    } catch { this.collector.fault('event_capture_failed'); }
  }
  classify(result) {
    if (!this.options.classify) return 'success';
    try {
      const status = this.options.classify(result);
      if (['success', 'error', 'unknown'].includes(status)) return status;
    } catch { /* Diagnostics must never replace business values or errors. */ }
    this.collector.diagnostic('classification_failed');
    return 'unknown';
  }
}

import { types } from 'node:util';
import { identifier } from './config.mjs';
import { Worker, storage } from './context.mjs';
import { Span, failure } from './events.mjs';
import { stream } from './streams.mjs';

export function instrument(collector, kind, worker, target, options = {}) {
  if (!(worker instanceof Worker) || (kind === 'call' && !(target instanceof Worker))) {
    throw new TypeError('Participants must be explicit Worker objects');
  }
  const operation = options.operation ?? kind;
  const capture = options.capture ?? 'omit', mode = options.mode ?? 'sync';
  if (typeof operation !== 'string' || !/^[A-Za-z0-9_.:-]{1,64}$/.test(operation)) {
    throw new TypeError('Operation must be a static tag');
  }
  if (!['omit', 'shape'].includes(capture) || !['sync', 'promise', 'iterator', 'asyncIterator'].includes(mode)) {
    throw new TypeError('Explicit capture and callable modes are required');
  }
  if (options.taskId != null) identifier(options.taskId, 'taskId');
  if (options.classify != null && typeof options.classify !== 'function') throw new TypeError('Invalid classifier');
  const settings = Object.freeze({ ...options, operation, capture, mode });
  return function decorate(fn) {
    if (typeof fn !== 'function') throw new TypeError('Expected an existing business callable');
    return function (...args) {
      let span;
      try {
        let carrier = settings.carrier;
        if (typeof carrier === 'function') {
          try { carrier = carrier(); }
          catch { collector.diagnostic('carrier_failed'); carrier = {}; }
        }
        span = new Span(collector, kind, worker, target, { ...settings, carrier });
      } catch {
        collector.fault('event_capture_failed');
        return Reflect.apply(fn, this, args);
      }
      return storage.run(span.context, () => {
        let result;
        try { result = Reflect.apply(fn, this, args); }
        catch (error) { span.finish(failure(error), args.length); throw error; }
        if (mode === 'iterator' || mode === 'asyncIterator') {
          try { return stream(result, span, args.length, mode === 'asyncIterator'); }
          catch {
            span.finish('unknown', args.length);
            collector.diagnostic('stream_mode_failed');
            return result;
          }
        }
        if (mode === 'promise') {
          return Promise.resolve(result).then(value => {
            span.finish(span.classify(value), args.length);
            return value;
          }, error => { span.finish(failure(error), args.length); throw error; });
        }
        // A caller must explicitly select promise mode; never report early success.
        if (types.isPromise(result)) {
          span.finish('unknown', args.length);
          collector.diagnostic('promise_mode_required');
        } else span.finish(span.classify(result), args.length);
        return result;
      });
    };
  };
}

import { types } from 'node:util';
import { storage } from './context.mjs';
import { failure } from './events.mjs';

export function stream(iterator, span, count, asynchronous) {
  let active = 0;
  let failed = null;
  let closing = false;
  let started = false;
  let closed = false;
  const native = types.isGeneratorObject(iterator);
  const output = {};
  function inspect(result, method) {
    try {
      const done = result && Object.getOwnPropertyDescriptor(result, 'done');
      if (done && 'value' in done && done.value === true) {
        closed = true;
        if (started) span.finish(failed ?? (method === 'return' || closing ? 'unknown' : 'success'), count);
      }
    } catch { span.collector.diagnostic('stream_result_unknown'); }
    return result;
  }
  function error(value, wasActive) {
    // A reentrant synchronous next() may fail while the real generator remains live.
    if (!asynchronous && wasActive) span.collector.diagnostic('concurrent_stream_step');
    else {
      failed = failure(value);
      if (native) {
        closed = true;
        if (started) span.finish(failed, count);
      }
    }
    throw value;
  }
  for (const method of ['next', 'return', 'throw']) {
    if (typeof iterator[method] !== 'function') continue;
    output[method] = function (...args) {
      const wasActive = active > 0;
      active += 1;
      if (!started && !closed) {
        if (method === 'next') { started = true; span.begin(); }
        else { closed = true; }
      }
      if (method === 'return') closing = true;
      try {
        const result = storage.run(span.context, () => Reflect.apply(iterator[method], iterator, args));
        if (asynchronous) {
          return Promise.resolve(result).then(value => inspect(value, method), value => error(value, wasActive))
            .finally(() => { active -= 1; });
        }
        try { return inspect(result, method); } finally { active -= 1; }
      } catch (value) { active -= 1; return error(value, wasActive); }
    };
  }
  output[asynchronous ? Symbol.asyncIterator : Symbol.iterator] = () => output;
  return output;
}

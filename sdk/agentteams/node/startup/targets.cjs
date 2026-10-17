'use strict';
const { types } = require('node:util');
const fs = require('node:fs');

function canonical(filename) {
  try { return fs.realpathSync(filename); } catch { return null; }
}
function state(target, code, report) {
  target.state = code;
  report(code);
}
function callable(original, decorate) {
  if (typeof original !== 'function' || types.isProxy(original) ||
      /^\s*class(?:\s|\{)/.test(Function.prototype.toString.call(original))) return null;
  const observed = decorate(original);
  let proxy;
  proxy = new Proxy(original, {
    apply(_target, receiver, args) { return Reflect.apply(observed, receiver, args); },
    // Constructors are business calls, never observed tasks. Preserve direct new.target and subclasses.
    construct(_target, args, newTarget) { return Reflect.construct(original, args, newTarget === proxy ? original : newTarget); },
  });
  return proxy;
}
function patch(module, target, report) {
  try {
    if (target.export === null) {
      const descriptor = Object.getOwnPropertyDescriptor(module, 'exports');
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.writable) {
        state(target, 'startup_locked_export', report); return false;
      }
      const replacement = callable(descriptor.value, target.decorate);
      if (!replacement) { state(target, 'startup_unsupported_callable', report); return false; }
      Object.defineProperty(module, 'exports', { ...descriptor, value: replacement });
    } else {
      let owner = module.exports;
      for (const name of target.export.slice(0, -1)) {
        if (!owner || !['object', 'function'].includes(typeof owner) || types.isProxy(owner)) {
          state(target, 'startup_unsupported_export', report); return false;
        }
        const descriptor = Object.getOwnPropertyDescriptor(owner, name);
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
          state(target, 'startup_accessor_or_missing_export', report); return false;
        }
        owner = descriptor.value;
      }
      if (!owner || !['object', 'function'].includes(typeof owner) || types.isProxy(owner)) {
        state(target, 'startup_unsupported_export', report); return false;
      }
      const name = target.export.at(-1), descriptor = Object.getOwnPropertyDescriptor(owner, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        state(target, 'startup_accessor_or_missing_export', report); return false;
      }
      if (!descriptor.writable) { state(target, 'startup_locked_export', report); return false; }
      const replacement = callable(descriptor.value, target.decorate);
      if (!replacement) { state(target, 'startup_unsupported_callable', report); return false; }
      Object.defineProperty(owner, name, { ...descriptor, value: replacement });
    }
    state(target, 'startup_instrumented', report);
    return true;
  } catch {
    state(target, 'startup_export_patch_unavailable', report);
    return false; // Telemetry/descriptor failures never replace business loading or its original exception.
  }
}
module.exports = Object.freeze({ canonical, patch });

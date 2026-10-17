'use strict';
// Version-specific private CJS hook; not a public or ESM execution hook.
const Module = require('node:module');
const { types } = require('node:util');
const { canonical, patch } = require('./targets.cjs');

function commonjs(module, result) {
  if (!(module instanceof Module) || types.isProxy(module) || types.isModuleNamespaceObject(result) ||
      types.isProxy(result)) return false;
  // Node 24.18/25.2 ESM loading sets this marker even for an ESM 'module.exports' custom export.
  // Private version-specific evidence, never a stable ESM hook or namespace-replacement promise.
  for (const symbol of Object.getOwnPropertySymbols(module)) {
    if (symbol.description === 'kRequiredModuleSymbol') return false;
    if (symbol.description === 'kFormat') {
      const descriptor = Object.getOwnPropertyDescriptor(module, symbol);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
          ![undefined, 'commonjs'].includes(descriptor.value)) return false;
    }
  }
  return true;
}

function install(configured, report) {
  const notify = code => { try { report(code); } catch { /* Telemetry cannot replace business. */ } };
  const original = Module._load, resolve = Module._resolveFilename;
  if (typeof original !== 'function' || typeof resolve !== 'function') {
    throw new Error('AgentTeams Node startup CommonJS hook unavailable');
  }
  const groups = new Map();
  for (const target of configured) {
    if (!groups.has(target.file)) groups.set(target.file, []);
    groups.get(target.file).push(target);
  }
  // Late installation cannot repair escaped references, replay module initialization or patch a partial cycle.
  for (const [filename, targets] of groups) {
    if (Object.values(Module._cache).some(module => canonical(module.filename) === filename)) {
      for (const target of targets) target.state = 'startup_preloaded_gap';
      notify('startup_preloaded_gap');
    }
  }
  function load(request, parent, isMain) {
    const result = Reflect.apply(original, this, arguments); // Exactly once; original throw escapes untouched.
    try {
      const filename = Reflect.apply(resolve, Module, [request, parent, isMain]);
      if (typeof filename !== 'string') return result;
      const targets = groups.get(canonical(filename));
      if (!targets) return result;
      const module = Module._cache[filename];
      if (!module || module.exports !== result) {
        notify('startup_cache_identity_gap'); return result;
      }
      const waiting = targets.filter(target => target.state === 'startup_waiting');
      if (!module.loaded) {
        for (const target of waiting) target.state = 'startup_circular_partial_gap';
        if (waiting.length) notify('startup_circular_partial_gap');
        return result;
      }
      if (!commonjs(module, result)) {
        for (const target of waiting) target.state = 'startup_non_cjs_gap';
        if (waiting.length) notify('startup_non_cjs_gap');
        return result;
      }
      for (const target of waiting) patch(module, target, notify);
      return module.exports;
    } catch {
      notify('startup_hook_unavailable');
      return result;
    }
  }
  Module._load = load;
  return Object.freeze({
    snapshot() { return configured.map(target => ({ target: target.index, state: target.state })); },
    detach() {
      // Do not overwrite another loader installed after this one; never undo exported business wrappers.
      if (Module._load === load) Module._load = original;
    },
  });
}
module.exports = Object.freeze({ install });

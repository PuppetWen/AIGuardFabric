'use strict';
// Server/operator-owned startup descriptor. Credentials are accepted only from one named environment variable.
const fs = require('node:fs');
const path = require('node:path');
const { types } = require('node:util');
const MAX_BYTES = 64 * 1024;
const safeTag = /^[A-Za-z0-9_.:-]{1,64}$/;
const safeName = /^[A-Za-z0-9_.:-]{1,128}$/;
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);

function invalid() { return new Error('Invalid AgentTeams Node startup configuration'); }
function supported(version = process.versions.node) {
  if (!/^(24\.18|25\.2)\.\d+$/.test(version)) {
    throw new Error('AgentTeams Node startup supports only Node 24.18.x or 25.2.x');
  }
}
function object(value, keys, required = keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || types.isProxy(value) ||
      Object.keys(value).some(key => !keys.includes(key)) || required.some(key => !Object.hasOwn(value, key))) {
    throw invalid();
  }
  for (const key of Object.keys(value)) {
    if (!Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value')) throw invalid();
  }
}
function worker(value) {
  object(value, ['name', 'team']);
  for (const key of ['name', 'team']) {
    if (key === 'team' && value[key] === null) continue;
    if (typeof value[key] !== 'string' || !value[key] || Buffer.byteLength(value[key]) > 512 ||
        /[\x00-\x1f\x7f-\x9f]/.test(value[key])) throw invalid();
  }
  return Object.freeze({ name: value.name, team: value.team });
}
function parse(raw, filename, { drainOnly = false } = {}) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > MAX_BYTES) throw invalid();
  let value;
  try { value = JSON.parse(raw); } catch { throw invalid(); }
  object(value, ['version', 'keyEnv', 'targets']);
  if (value.version !== 1 || typeof value.keyEnv !== 'string' ||
      !/^AGF_[A-Z0-9_]{1,80}$/.test(value.keyEnv) || !Array.isArray(value.targets) ||
      value.targets.length < 1 || value.targets.length > 32) throw invalid();
  const targets = value.targets.map((target, index) => {
    object(target, ['file', 'export', 'kind', 'worker', 'to', 'operation', 'mode', 'capture', 'taskId'],
      ['file', 'export', 'kind', 'worker', 'operation', 'mode']);
    if (typeof target.file !== 'string' || !target.file || target.file.length > 4096 ||
        /[\x00-\x1f\x7f]/.test(target.file) || !['.cjs', '.js'].includes(path.extname(target.file)) ||
        !['task', 'call'].includes(target.kind) || typeof target.operation !== 'string' || !safeTag.test(target.operation) ||
        !['sync', 'promise', 'iterator', 'asyncIterator'].includes(target.mode) ||
        !['omit', 'shape'].includes(target.capture ?? 'omit') ||
        (target.taskId !== undefined && (typeof target.taskId !== 'string' || !safeName.test(target.taskId)))) {
      throw invalid();
    }
    if (target.export !== null && (!Array.isArray(target.export) || target.export.length < 1 ||
        target.export.length > 4 || target.export.some(name => typeof name !== 'string' ||
          !/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(name) || forbidden.has(name)))) throw invalid();
    if ((target.kind === 'call') !== Object.hasOwn(target, 'to')) throw invalid();
    const from = worker(target.worker), to = target.kind === 'call' ? worker(target.to) : null;
    let file = path.resolve(path.dirname(filename), target.file);
    if (!drainOnly) {
      try {
        file = fs.realpathSync(file);
        if (!fs.statSync(file).isFile()) throw invalid();
      } catch { throw invalid(); }
      if (!['.cjs', '.js'].includes(path.extname(file))) throw invalid();
    }
    return Object.freeze({ index, file, export: target.export === null ? null : Object.freeze([...target.export]),
      kind: target.kind, worker: from, to, operation: target.operation, mode: target.mode,
      capture: target.capture ?? 'omit', taskId: target.taskId });
  });
  for (let index = 0; index < targets.length; index += 1) {
    for (const previous of targets.slice(0, index)) {
      const a = previous.export ?? [], b = targets[index].export ?? [];
      if (previous.file === targets[index].file &&
          a.slice(0, Math.min(a.length, b.length)).every((name, pos) => name === b[pos])) throw invalid();
    }
  }
  return Object.freeze({ version: 1, keyEnv: value.keyEnv, targets: Object.freeze(targets) });
}
function read(options = {}) {
  const filename = process.env.AGF_NODE_STARTUP_CONFIG;
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw invalid();
  let canonical, raw;
  try {
    canonical = fs.realpathSync(filename);
    const stat = fs.statSync(canonical);
    if (!stat.isFile() || stat.size > MAX_BYTES) throw invalid();
    raw = fs.readFileSync(canonical, 'utf8');
  } catch { throw invalid(); }
  return parse(raw, canonical, options);
}
function collectorOptions(descriptor, environment = process.env) {
  if (!['true', 'false'].includes(environment.AGF_EXPECTED_MOCKED) ||
      !environment.AGF_SCOPE_ID || !environment.AGF_SPOOL_DIR || !path.isAbsolute(environment.AGF_SPOOL_DIR)) {
    throw invalid();
  }
  return { platformUrl: environment.AGF_PLATFORM_URL, sourceId: environment.AGF_SOURCE_ID,
    bindingId: environment.AGF_BINDING_ID, expectedScope: environment.AGF_SCOPE_ID,
    expectedMocked: environment.AGF_EXPECTED_MOCKED === 'true', collectorKey: environment[descriptor.keyEnv],
    spoolDir: environment.AGF_SPOOL_DIR };
}
module.exports = Object.freeze({ supported, parse, read, collectorOptions });

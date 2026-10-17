import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import { fixture, target } from './startup_support.mjs';
const require = createRequire(import.meta.url);
const { parse, supported, collectorOptions } = require('../startup/config.cjs');

test('supported runtime range is explicit rather than an arbitrary Node major promise', () => {
  for (const version of ['24.18.0', '24.18.1', '25.2.0', '25.2.1']) assert.doesNotThrow(() => supported(version));
  for (const version of ['24.17.0', '24.19.0', '25.1.0', '25.3.0', '26.0.0', '24.18', 'v25.2.1']) {
    assert.throws(() => supported(version), /supports only/);
  }
});

test('descriptor accepts only a bounded exact target set and does not evaluate configured code', t => {
  const f = fixture(t, 'config');
  f.write('work.cjs', 'throw new Error("business module must not be imported by config parser");');
  const config = { version: 1, keyEnv: 'AGF_STARTUP_KEY', targets: [target('./work.cjs')] };
  const filename = f.environment.AGF_NODE_STARTUP_CONFIG;
  const parsed = parse(JSON.stringify(config), filename);
  assert.equal(parsed.targets.length, 1); assert.equal(parsed.targets[0].capture, 'omit');
  assert(Object.isFrozen(parsed)); assert(Object.isFrozen(parsed.targets));
  for (const change of [{ version: 2 }, { collectorKey: 'private marker' }, { keyEnv: 'raw key value' },
    { targets: [] }, { targets: Array.from({ length: 33 }, (_, i) => target('./work.cjs', [`work${i}`])) }]) {
    assert.throws(() => parse(JSON.stringify({ ...config, ...change }), filename), /Invalid/);
  }
  assert.throws(() => parse('x'.repeat(64 * 1024 + 1), filename), /Invalid/);
});

test('unknown fields duplicate paths accessors implicit modes and credential/carrier capture are rejected', t => {
  const f = fixture(t, 'target-validation'); f.write('work.cjs', 'exports.work=()=>1;');
  const filename = f.environment.AGF_NODE_STARTUP_CONFIG;
  const input = item => JSON.stringify({ version: 1, keyEnv: 'AGF_STARTUP_KEY', targets: [item] });
  for (const change of [{ mode: 'auto' }, { operation: 123 }, { capture: 'values' }, { export: ['__proto__'] },
    { export: ['constructor'] }, { export: [] }, { export: 'work' }, { taskId: '' }, { file: './work.mjs' },
    { carrier: { trace_id: 'caller' } }, { classify: 'arbitrary-code' }, { worker: { name: 'a', team: null, key: 'private' } },
    { kind: 'task', to: { name: 'b', team: null } }, { kind: 'call' }]) {
    assert.throws(() => parse(input(target('./work.cjs', ['work'], change)), filename), /Invalid/);
  }
  for (const targets of [[target('./work.cjs'), target('./work.cjs')],
    [target('./work.cjs', null), target('./work.cjs')],
    [target('./work.cjs', ['container']), target('./work.cjs', ['container', 'work'])]]) {
    assert.throws(() => parse(JSON.stringify({ version: 1, keyEnv: 'AGF_STARTUP_KEY', targets }), filename), /Invalid/);
  }
});

test('invalid startup configuration fails before the original entry without echoing descriptor secrets', async t => {
  const f = fixture(t, 'fail-before-entry'); f.write('work.cjs', 'exports.work=()=>1;');
  f.configure([target('./work.cjs')], { collectorKey: 'descriptor-secret-must-not-echo' });
  const entry = f.write('entry.cjs', `require('node:fs').writeFileSync('business-ran','yes');`);
  const response = await f.run(entry);
  assert.notEqual(response.code, 0); assert(!fs.existsSync(`${f.directory}/business-ran`));
  assert(response.stderr.includes('startup configuration')); assert(!response.stderr.includes('descriptor-secret-must-not-echo'));
});

test('scope Mock mode and absolute spool must be explicit in existing collector environment', () => {
  for (const environment of [{ AGF_EXPECTED_MOCKED: 'true' }, { AGF_EXPECTED_MOCKED: 'auto' },
    { AGF_EXPECTED_MOCKED: 'false', AGF_SCOPE_ID: 'x', AGF_SPOOL_DIR: 'relative-spool' }]) {
    assert.throws(() => collectorOptions({ keyEnv: 'AGF_STARTUP_KEY' }, environment), /Invalid/);
  }
});

test('drain-only validates shape while allowing unavailable old business files without importing them', t => {
  const f = fixture(t, 'drain-config');
  const input = JSON.stringify({ version: 1, keyEnv: 'AGF_STARTUP_KEY', targets: [target('./removed-business.js')] });
  assert.throws(() => parse(input, f.environment.AGF_NODE_STARTUP_CONFIG), /Invalid/);
  const config = parse(input, f.environment.AGF_NODE_STARTUP_CONFIG, { drainOnly: true });
  assert.equal(config.targets.length, 1); assert.equal(config.targets[0].mode, 'sync');
});

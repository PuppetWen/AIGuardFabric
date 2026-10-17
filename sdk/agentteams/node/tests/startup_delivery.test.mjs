import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Worker } from '../index.mjs';
import { fixture, target, STARTUP, KEY, closeAndPrint } from './startup_support.mjs';

test('lost ACK is replayed only from the existing journal by drain-only without reexecuting business', async t => {
  const f = fixture(t, 'lost-ack'), receiver = await f.receiver(); receiver.control.drop = true;
  f.write('work.cjs', `const fs=require('node:fs');exports.work=function(){fs.appendFileSync('business-count','1');return 37;};`);
  f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `const value=require('./work.cjs').work();require(${JSON.stringify(STARTUP)}).close(0.1).then(status=>console.log(JSON.stringify({value,status})));`);
  const result = await f.run(entry, { env: { AGF_PLATFORM_URL: receiver.url } });
  assert.equal(result.code, 0); assert.equal(result.json().value, 37); assert.equal(result.json().status.pending, 1);
  assert(receiver.bodies.length >= 1); const first = receiver.bodies[0]; const original = f.events();
  assert.equal(original.length, 1); receiver.control.drop = false;
  const drained = await f.drain({ AGF_PLATFORM_URL: receiver.url });
  assert.equal(drained.code, 0); assert.equal(drained.json().businessModulesLoaded, false);
  assert.equal(drained.json().businessCalls, 0); assert.equal(drained.json().pending, 0);
  assert.equal(drained.json().deduped, 1); assert.equal(fs.readFileSync(path.join(f.directory, 'business-count'), 'utf8'), '1');
  assert.equal(receiver.bodies.at(-1), first); assert.equal(f.events().length, 0);
  assert.equal(receiver.headers[0].authorization, `Bearer ${KEY}`); assert(!first.includes(KEY));
});

test('unknown ACK leaves the original UUID journal intact instead of treating telemetry receipt as business success', async t => {
  const f = fixture(t, 'bad-ack'), receiver = await f.receiver(); receiver.control.badAck = true;
  f.write('work.cjs', 'exports.work=()=>41;'); f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `const value=require('./work.cjs').work();require(${JSON.stringify(STARTUP)}).close(0.1).then(status=>console.log(JSON.stringify({value,status})));`);
  const result = await f.run(entry, { env: { AGF_PLATFORM_URL: receiver.url } });
  assert.equal(result.code, 0); assert.equal(result.json().value, 41);
  assert.equal(result.json().status.sent, 0); assert.equal(result.json().status.pending, 1);
  assert.equal(result.json().status.lastError, 'invalid_ack'); assert.equal(f.events().length, 1);
  const original = f.events(); receiver.control.badAck = false;
  const drained = await f.drain({ AGF_PLATFORM_URL: receiver.url });
  assert.equal(drained.code, 0); assert.deepEqual(JSON.parse(receiver.bodies.at(-1)).events, original);
});

test('a foreign delivery identity cannot drain or overwrite an old queue; normal startup reports a gap', async t => {
  const f = fixture(t, 'queue-identity');
  f.write('work.cjs', 'exports.work=()=>43;'); f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `const value=require('./work.cjs').work();const status=require(${JSON.stringify(STARTUP)}).status();${closeAndPrint('({value,status})')}`);
  const first = await f.run(entry); assert.equal(first.code, 0); assert.equal(f.events().length, 1);
  const original = f.events();
  const changed = { AGF_BINDING_ID: '00000000-0000-4000-8000-000000000099' };
  const second = await f.run(entry, { env: changed });
  assert.equal(second.code, 0); assert.equal(second.json().value, 43);
  assert.equal(second.json().status.reason, 'startup_owned_queue_gap'); assert.deepEqual(f.events(), original);
  const drain = await f.drain(changed); assert.notEqual(drain.code, 0); assert.deepEqual(f.events(), original);
  assert(!drain.stderr.includes(KEY));
});

test('drain-only never imports or calls the configured handler even if that handler now throws on import', async t => {
  const f = fixture(t, 'drain-no-business'), receiver = await f.receiver();
  const work = f.write('work.cjs', `exports.work=()=>47;`); f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `const value=require('./work.cjs').work();${closeAndPrint('({value})')}`);
  const result = await f.run(entry, { env: { AGF_PLATFORM_URL: receiver.url } });
  assert.equal(result.code, 0); assert.equal(f.events().length, 1);
  // This is owned test fixture evolution; production business source is never rewritten by the SDK.
  fs.writeFileSync(work, `require('node:fs').writeFileSync('forbidden-import','yes');throw new Error('should not be imported');`);
  const drained = await f.drain({ AGF_PLATFORM_URL: receiver.url });
  assert.equal(drained.code, 0); assert(!fs.existsSync(path.join(f.directory, 'forbidden-import')));
  assert.equal(drained.json().businessModulesLoaded, false); assert.equal(f.events().length, 0);
});

test('explicit call-worker mapping uses the existing collector team/from/to context without raw argument capture', async t => {
  const f = fixture(t, 'call-worker');
  // Worker import above proves the same existing SDK API is used; no parallel event schema exists.
  assert.equal(new Worker('worker-a', 'team-a').team, 'team-a');
  f.write('work.cjs', `exports.work=value=>value;`);
  f.configure([target('./work.cjs', ['work'], { kind: 'call', to: { name: 'worker-b', team: 'team-b' } })]);
  const entry = f.write('entry.cjs', `const value=require('./work.cjs').work({private:'input-is-not-collected'});${closeAndPrint('({same:value.private===\'input-is-not-collected\'})')}`);
  const result = await f.run(entry); assert.equal(result.code, 0); assert.equal(result.json().same, true);
  assert.equal(f.events().length, 1); const event = f.events()[0];
  assert.deepEqual([event.kind, event.from_team, event.from_worker, event.to_team, event.to_worker],
    ['call', 'team-a', 'worker-a', 'team-b', 'worker-b']);
  assert.equal(event.message, null); assert(!JSON.stringify(event).includes('input-is-not-collected'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import { Outbox, QueueFull } from '../spool.mjs';
import { fixture } from './support.mjs';

test('active rollback journals plus both databases stay inside the configured disk budget', async t => {
  const f = fixture(t, 'disk-budget');
  const config = f.config({ maxDiskBytes: 1024 * 1024, maxBytes: 256 * 1024, batchBytes: 128 * 1024 });
  const box = new Outbox(config); f.add(() => box.close());
  const monitor = new Worker(new URL('./disk-monitor.mjs', import.meta.url), { workerData: config.spoolDir });
  f.add(() => monitor.terminate());
  assert.equal((await once(monitor, 'message'))[0], 'ready');
  for (let i = 0; i < 140; i += 1) box.append({ event_id: `owned-${i}`, message: 'x'.repeat(1000) });
  for (let i = 0; i < 30; i += 1) {
    const batch = box.batch(100); box.defer(batch, 0, i % 2 === 0 ? 'network_error' : 'http_429');
  }
  const before = box.counts();
  assert.equal(before.pending, 140);
  box.ack(box.batch(100)); box.ack(box.batch(100));
  assert.equal(box.counts().pending, 0);
  const received = once(monitor, 'message'); monitor.postMessage('stop');
  const result = (await received)[0];
  assert(result.journalSeen, 'monitor must actually observe an active rollback journal');
  assert(result.peak <= config.maxDiskBytes, JSON.stringify(result));
  t.diagnostic(`owned SDK file peak=${result.peak}, budget=${config.maxDiskBytes}`);
});

test('disk-page exhaustion and rollback preserve prior events within the total owned-file budget', async t => {
  const f = fixture(t, 'disk-full');
  const config = f.config({ maxDiskBytes: 1024 * 1024, maxBytes: 384 * 1024, batchBytes: 128 * 1024 });
  const box = new Outbox(config); f.add(() => box.close());
  const monitor = new Worker(new URL('./disk-monitor.mjs', import.meta.url), { workerData: config.spoolDir });
  f.add(() => monitor.terminate());
  assert.equal((await once(monitor, 'message'))[0], 'ready');
  let stored = 0, failure;
  for (let i = 0; i < 1000; i += 1) {
    try { box.append({ event_id: `owned-${i}`, message: 'x'.repeat(1000) }); stored += 1; }
    catch (error) { failure = error; break; }
  }
  assert(failure, 'fixture must actually reach a bound');
  assert(!(failure instanceof QueueFull), 'page budget must reject before logical queue bounds');
  assert.match(failure.message, /full/i);
  assert(stored > 100); assert.equal(box.counts().pending, stored);
  const original = box.batch(100);
  try { box.defer(original, 0, 'owned_storage_failure_' + 'x'.repeat(40)); }
  catch (error) { assert.match(error.message, /full/i); }
  assert.deepEqual(box.batch(100), original);
  assert.equal(box.counts().pending, stored);
  while (box.counts().pending) box.ack(box.batch(100));
  const received = once(monitor, 'message'); monitor.postMessage('stop');
  const result = (await received)[0];
  assert(result.journalSeen); assert(result.peak <= config.maxDiskBytes, JSON.stringify(result));
  t.diagnostic(`full/rollback owned SDK file peak=${result.peak}, budget=${config.maxDiskBytes}`);
});

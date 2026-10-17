import test from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from '../index.mjs';
import { fixture, KEY, SCOPE } from './support.mjs';

test('real HTTP acknowledgements remove events with collector credential isolated from event body', async t => {
  const f = fixture(t, 'ack'), receiver = await f.receiver();
  const collector = f.collector(f.config({ platformUrl: receiver.url }));
  collector.heartbeat();
  const status = await collector.flush(1);
  assert.equal(status.sent, 1); assert.equal(status.pending, 0); assert.equal(status.durable, true);
  assert.equal(receiver.headers[0].authorization, `Bearer ${KEY}`);
  assert(!receiver.bodies[0].includes(KEY));
  assert.equal(JSON.stringify(collector.config).includes(KEY), false);
});
test('response loss and restart replay identical event/time/body without executing business again', async t => {
  const f = fixture(t, 'lost'), receiver = await f.receiver(); receiver.replies.push('drop');
  const config = f.config({ platformUrl: receiver.url }), collector = f.collector(config);
  let count = 0;
  const fn = collector.task(new Worker('worker-a'))(() => { count += 1; return 7; });
  assert.equal(fn(), 7);
  await collector.deliverOnce(0.2);
  assert.equal(collector.status().pending, 1);
  await collector.close(0);
  const resumed = f.collector(config), status = await resumed.flush(2);
  assert.equal(status.deduped, 1); assert.equal(status.pending, 0); assert.equal(count, 1);
  assert.equal(receiver.bodies[0], receiver.bodies[1]);
});
test('invalid success body preserves events and never reports an acknowledgement', async t => {
  const f = fixture(t, 'bad-ack'), receiver = await f.receiver(); receiver.replies.push('bad_ack');
  const collector = f.collector(f.config({ platformUrl: receiver.url })); collector.heartbeat();
  await collector.deliverOnce(0.2);
  assert.equal(collector.status().sent, 0); assert.equal(collector.status().pending, 1);
  assert.equal(collector.status().lastError, 'invalid_ack');
});
test('permission rejection pauses delivery, while identity conflict quarantines unchanged event', async t => {
  for (const code of [401, 403, 409]) {
    const f = fixture(t, `reject-${code}`), receiver = await f.receiver(); receiver.replies.push(code);
    const collector = f.collector(f.config({ platformUrl: receiver.url })); collector.heartbeat();
    const first = await collector.flush(1);
    assert.equal(first.paused, `http_${code}`);
    assert.equal(code === 409 ? first.quarantined : first.pending, 1);
    await collector.flush(0.05); assert.equal(receiver.bodies.length, 1);
    if (code === 409) { collector.resume(); await collector.flush(0.05); assert.equal(receiver.bodies.length, 1); }
  }
});
test('HTTP redirects never forward the collector key or event to a second destination', async t => {
  const f = fixture(t, 'redirect'), destination = await f.receiver(), receiver = await f.receiver();
  receiver.replies.push({ redirect: `${destination.url}/unexpected` });
  const collector = f.collector(f.config({ platformUrl: receiver.url })); collector.heartbeat();
  const status = await collector.flush(1);
  assert.equal(status.paused, 'http_302'); assert.equal(status.quarantined, 1);
  assert.equal(destination.bodies.length, 0); assert.equal(destination.headers.length, 0);
});
test('configuration cannot be rebound through assignment; Key rotation retains delivery identity', async t => {
  const f = fixture(t, 'immutable'), receiver = await f.receiver();
  const collector = f.collector(f.config({ platformUrl: receiver.url })); collector.heartbeat();
  assert.throws(() => { collector.config = f.config({ bindingId: '00000000-0000-4000-8000-000000000099' }); }, TypeError);
  assert.throws(() => { collector.config.bindingId = 'different'; }, TypeError);
  collector.rotateKey('agf_owned_rotated_key'); await collector.flush(1);
  assert.equal(receiver.headers[0].authorization, 'Bearer agf_owned_rotated_key');
  assert.equal(JSON.parse(receiver.bodies[0]).binding_id, collector.config.bindingId);
});

test('HTTP 1.1 chunked success truncated after legal headers keeps the exact committed event', async t => {
  const f = fixture(t, 'truncated-chunked'), receiver = await f.receiver(); receiver.replies.push('truncate');
  const collector = f.collector(f.config({ platformUrl: receiver.url })); collector.heartbeat();
  await collector.deliverOnce(0.5);
  assert.equal(collector.status().lastError, 'network_error');
  assert.equal(collector.status().pending, 1); assert.equal(collector.status().sent, 0);
  const status = await collector.flush(2);
  assert.equal(status.pending, 0); assert.equal(status.deduped, 1);
  assert.equal(receiver.bodies[0], receiver.bodies[1]);
});

test('429 reduces batch size while replay preserves event IDs and never repeats business calls', async t => {
  const f = fixture(t, 'split'), receiver = await f.receiver(); receiver.replies.push(429);
  const collector = f.collector(f.config({ platformUrl: receiver.url }));
  let calls = 0;
  const work = collector.task(new Worker('worker-a'))(() => { calls += 1; return calls; });
  assert.equal(work(), 1); assert.equal(work(), 2); assert.equal(work(), 3);
  await collector.deliverOnce(0.5);
  assert.equal(collector.status().pending, 3); assert.equal(collector.status().sent, 0);
  const first = JSON.parse(receiver.bodies[0]).events;
  const status = await collector.flush(2);
  assert.equal(status.sent, 3); assert.equal(status.pending, 0); assert.equal(calls, 3);
  const retried = receiver.bodies.slice(1).map(body => JSON.parse(body).events);
  assert.deepEqual(retried.map(batch => batch.length), [1, 1, 1]);
  assert.deepEqual(retried.flat(), first);
});

test('acknowledgement requires exact scope, Mock mode and integer event accounting', async t => {
  const base = { received: 1, accepted: 1, deduped: 0, scopeId: SCOPE, mocked: true,
    durable: true, authorizationStatus: 'unknown' };
  for (const change of [{ scopeId: '00000000-0000-4000-8000-000000000099' }, { mocked: false },
    { received: 2 }, { accepted: 0 }, { deduped: 0.5 }, { durable: null }, { authorizationStatus: 'authorized' }]) {
    const f = fixture(t, 'ack-identity'), receiver = await f.receiver(); receiver.replies.push({ ...base, ...change });
    const collector = f.collector(f.config({ platformUrl: receiver.url })); collector.heartbeat();
    await collector.deliverOnce(0.5);
    assert.equal(collector.status().lastError, 'invalid_ack');
    assert.equal(collector.status().pending, 1); assert.equal(collector.status().sent, 0);
  }
});

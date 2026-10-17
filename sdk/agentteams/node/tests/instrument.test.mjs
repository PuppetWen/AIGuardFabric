import test from 'node:test';
import assert from 'node:assert/strict';
import { Worker, inject, mcpResult } from '../index.mjs';
import { Outbox } from '../spool.mjs';
import { fixture } from './support.mjs';

function queued(collector) {
  // Read through the delivery API after a receiver is supplied in delivery tests;
  // these fixtures use the owned outbox only after close to inspect immutable events.
  return collector.status();
}
async function events(collector) {
  const config = collector.config;
  await collector.close(0);
  const box = new Outbox(config);
  try { return box.batch(100).map(([, event]) => event); } finally { box.close(); }
}
test('sync return, receiver, arguments and thrown object stay identical; input values are omitted', async t => {
  const f = fixture(t, 'sync');
  const collector = f.collector(f.config());
  const value = { password: 'do-not-capture', token: 'Bearer hidden' }, problem = { secret: 'private exception' };
  const owner = { fn: collector.task(new Worker('worker-a', 'team-a'))(function (argument) {
    assert.equal(this, owner); assert.equal(argument, value); return value;
  }) };
  assert.equal(owner.fn(value), value);
  const fail = collector.task(new Worker('worker-a'))(() => { throw problem; });
  assert.throws(fail, error => error === problem);
  const data = await events(collector);
  assert.deepEqual(data.map(event => event.status), ['success', 'error']);
  assert(!JSON.stringify(data).includes('do-not-capture'));
  assert(!JSON.stringify(data).includes('private exception'));
});
test('explicit promise mode preserves values/rejections and AbortError is unknown', async t => {
  const f = fixture(t, 'promise'), collector = f.collector(f.config());
  const value = {}, problem = new DOMException('secret message', 'AbortError');
  const fn = collector.task(new Worker('worker-a'), { mode: 'promise' })(async () => value);
  assert.equal(await fn(), value);
  const fail = collector.task(new Worker('worker-a'), { mode: 'promise' })(async () => { throw problem; });
  await assert.rejects(fail(), error => error === problem);
  assert.deepEqual((await events(collector)).map(event => event.status), ['success', 'unknown']);
});
test('ALS concurrent roots stay separate and nested Worker call has exactly one real edge', async t => {
  const f = fixture(t, 'context'), collector = f.collector(f.config());
  const a = new Worker('worker-a', 'team-a'), b = new Worker('worker-b', 'team-b');
  const callee = collector.task(b, { mode: 'promise' })(async () => inject());
  const call = collector.callWorker(a, b, { mode: 'promise' })(async () => callee());
  const task = collector.task(a, { mode: 'promise', taskId: 'owned-task' })(async () => {
    await Promise.resolve(); return call();
  });
  const [first, second] = await Promise.all([task(), task()]);
  assert.notEqual(first.trace_id, second.trace_id);
  assert.equal(inject(), null);
  const data = await events(collector);
  assert.equal(data.filter(event => event.kind === 'call').length, 2);
  for (const trace of [first.trace_id, second.trace_id]) {
    const group = data.filter(event => event.trace_id === trace);
    assert.equal(group.length, 3);
    const edge = group.find(event => event.kind === 'call');
    const inbound = group.find(event => event.kind === 'task' && event.from_worker === 'worker-b');
    const root = group.find(event => event.parent_span_id === null);
    assert.equal(edge.parent_span_id, root.span_id);
    assert.equal(inbound.parent_span_id, edge.span_id);
    assert.equal(edge.from_worker, 'worker-a'); assert.equal(edge.to_worker, 'worker-b');
  }
});
test('telemetry failures, classifier/carrier exceptions and wrong stream mode never replace business', async t => {
  const f = fixture(t, 'faults'), collector = f.collector(f.config({ maxItems: 1 }), {
    onStatus() { throw new Error('diagnostic callback'); },
  });
  const value = {};
  const fn = collector.task(new Worker('worker-a'), { classify() { throw {}; }, carrier() { throw {}; } })(() => value);
  assert.equal(fn(), value);
  const wrong = collector.task(new Worker('worker-a'), { mode: 'iterator' })(() => null);
  assert.equal(wrong(), null);
  assert.equal(collector.task(new Worker('worker-a'))(() => value)(), value);
  assert.equal(queued(collector).pending, 1);
  assert.equal(queued(collector).dropped, 2);
  assert.equal((await events(collector))[0].status, 'unknown');
});
test('lazy stream does not prefetch; return and throw preserve values and early close is unknown', async t => {
  const f = fixture(t, 'stream'), collector = f.collector(f.config());
  let calls = 0;
  const fn = collector.task(new Worker('worker-a'), { mode: 'iterator' })(function* () {
    calls += 1; yield 1; calls += 1; yield 2;
  });
  const iterator = fn();
  assert.equal(calls, 0); assert.equal(collector.status().pending, 0);
  assert.deepEqual(iterator.next(), { value: 1, done: false });
  assert.equal(calls, 1);
  assert.deepEqual(iterator.return('closed'), { value: 'closed', done: true });
  assert.equal(calls, 1);
  const problem = {};
  const broken = fn(); broken.next();
  assert.throws(() => broken.throw(problem), error => error === problem);
  assert.deepEqual((await events(collector)).map(event => event.status), ['unknown', 'error']);
});
test('async streams forward next input and cancellation; full consumption alone is success', async t => {
  const f = fixture(t, 'async-stream'), collector = f.collector(f.config());
  const cancel = new DOMException('private message', 'AbortError');
  const fn = collector.task(new Worker('worker-a'), { mode: 'asyncIterator' })(async function* () {
    const value = yield 1; if (value === 'cancel') throw cancel; yield value;
  });
  const stream = fn();
  assert.deepEqual(await stream.next(), { value: 1, done: false });
  await assert.rejects(stream.next('cancel'), error => error === cancel);
  const full = fn(); await full.next();
  assert.deepEqual(await full.next(7), { value: 7, done: false });
  assert.equal((await full.next()).done, true);
  assert.deepEqual((await events(collector)).map(event => event.status), ['unknown', 'success']);
});
test('reentrant next rejection does not prematurely finalize an active generator', async t => {
  const f = fixture(t, 'reentrant'), collector = f.collector(f.config());
  let iterator;
  const fn = collector.task(new Worker('worker-a'), { mode: 'iterator' })(function* () {
    assert.throws(() => iterator.next(), TypeError); yield 1; yield 2;
  });
  iterator = fn(); iterator.next();
  assert.equal(collector.status().pending, 0);
  iterator.next(); iterator.next();
  assert.equal((await events(collector))[0].status, 'success');
});
test('heartbeat has no inherited Worker/task and invalid carrier starts an independent root', async t => {
  const f = fixture(t, 'heartbeat'), collector = f.collector(f.config());
  const task = collector.task(new Worker('worker-a'), { taskId: 'task-one' })(() => { collector.heartbeat(); return inject(); });
  const context = task();
  const data = await events(collector), heartbeat = data.find(event => event.kind === 'heartbeat');
  assert.equal(heartbeat.from_worker, null); assert.equal(heartbeat.task_id, null);
  assert.notEqual(heartbeat.trace_id, context.trace_id);
});
test('unstarted sync and async generator closure never reports a business task', async t => {
  const f = fixture(t, 'unstarted'), collector = f.collector(f.config());
  let entered = 0;
  const sync = collector.task(new Worker('worker-a'), { mode: 'iterator' })(function* () {
    entered += 1; yield 1;
  });
  const asyncFn = collector.task(new Worker('worker-a'), { mode: 'asyncIterator' })(async function* () {
    entered += 1; yield 1;
  });
  const a = sync(), b = asyncFn();
  assert.deepEqual(a.return('closed'), { value: 'closed', done: true });
  assert.deepEqual(await b.return('closed'), { value: 'closed', done: true });
  assert.equal(a.next().done, true); assert.equal((await b.next()).done, true);
  const problem = {};
  assert.throws(() => sync().throw(problem), value => value === problem);
  await assert.rejects(asyncFn().throw(problem), value => value === problem);
  assert.equal(entered, 0); assert.deepEqual(await events(collector), []);
});
test('stream duration begins with consumption and excludes idle time before next', async t => {
  const f = fixture(t, 'stream-duration'), collector = f.collector(f.config());
  const fn = collector.task(new Worker('worker-a'), { mode: 'iterator' })(function* () { yield 1; });
  const iterator = fn();
  await new Promise(resolve => setTimeout(resolve, 300));
  iterator.next(); iterator.next();
  const [event] = await events(collector);
  assert.equal(event.status, 'success'); assert(event.duration_ms < 200);
});
test('MCP classifier only reads explicit decoded protocol fields and preserves unknown/error distinctions', () => {
  assert.equal(mcpResult({ content: [], isError: true }), 'error');
  assert.equal(mcpResult({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'error' } }), 'error');
  for (const value of [{}, { result: {} }, { content: [], isError: 'false' },
    { jsonrpc: '2.0', id: 1, method: 'tools/call', result: { content: [] } }]) assert.equal(mcpResult(value), 'unknown');
  const value = { content: [] }; Object.defineProperty(value, 'isError', { get() { throw new Error('must not invoke'); } });
  assert.equal(mcpResult(value), 'unknown');
});

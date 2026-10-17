import { types } from 'node:util';
import { Config, budget, key } from './config.mjs';
import { Worker, child } from './context.mjs';
import { event } from './events.mjs';
import { instrument } from './instrument.mjs';
import { Outbox, QueueFull } from './spool.mjs';
import { send } from './delivery.mjs';

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
function wait(promise, milliseconds) {
  let timer;
  return Promise.race([promise, new Promise(resolve => { timer = setTimeout(resolve, milliseconds); })])
    .finally(() => clearTimeout(timer));
}
export class Collector {
  #config;
  #authorization;
  #outbox;
  #onStatus;
  #timer;
  #sending;
  #abort;
  #closing = false;
  #auto;
  #lastCounts = { pending: 0, quarantined: 0, bytes: 0 };
  #sent = 0;
  #deduped = 0;
  #dropped = 0;
  #attempts = 0;
  #paused = null;
  #lastError = null;
  #durable = null;
  #batchItems;
  constructor(config, { autostart = true, onStatus } = {}) {
    if (!(config instanceof Config)) throw new TypeError('Expected validated Config');
    this.#config = config;
    this.#authorization = config.authorization();
    this.#outbox = new Outbox(config);
    this.#onStatus = onStatus;
    this.#auto = autostart;
    this.#batchItems = config.batchItems;
    if (autostart) this.#wake();
  }
  get config() { return this.#config; }
  task(worker, options = {}) { return instrument(this, 'task', worker, null, options); }
  callWorker(from, to, options = {}) { return instrument(this, 'call', from, to, options); }
  heartbeat() {
    const root = child(this, null, { carrier: {}, taskId: null });
    this.record(event(root, 'heartbeat'));
  }
  message(from, to = null, status = 'unknown') {
    if (!(from instanceof Worker) || (to !== null && !(to instanceof Worker)) ||
        !['success', 'error', 'unknown'].includes(status)) throw new TypeError('Explicit message participants/outcome required');
    this.record(event(child(this, from), 'message', from, to, status));
  }
  rotateKey(value) {
    if (this.#closing) throw new Error('Collector is closed');
    this.#authorization = `Bearer ${key(value)}`;
  }
  record(value) {
    try {
      if (this.#closing) { this.fault('collector_closed'); return; }
      this.#outbox.append(value);
      this.#wake();
    } catch (error) { this.fault(error instanceof QueueFull ? 'queue_full' : 'queue_write_failed'); }
  }
  fault(code) { this.#dropped += 1; this.diagnostic(code); }
  diagnostic(code) { this.#lastError = code; this.#notify(); }
  status() {
    try { this.#lastCounts = this.#outbox?.counts() ?? this.#lastCounts; }
    catch { this.#lastError = 'queue_read_failed'; }
    return { ...this.#lastCounts, sent: this.#sent, deduped: this.#deduped, dropped: this.#dropped,
      paused: this.#paused, lastError: this.#lastError, durable: this.#durable,
      closed: this.#closing, deliveryActive: !!this.#sending };
  }
  #notify() {
    try {
      const result = this.#onStatus?.(this.status());
      if (types.isPromise(result)) result.catch(() => {});
    } catch { /* Status callbacks cannot replace business results or exceptions. */ }
  }
  #wake() {
    if (!this.#auto || this.#closing || this.#timer || this.#sending) return;
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.deliverOnce(this.#config.requestTimeout).finally(() => this.#wake());
    }, 200);
    this.#timer.unref();
  }
  deliverOnce(timeout = this.#config.requestTimeout) {
    if (this.#sending) return this.#sending;
    if (this.#paused || !this.#outbox) return Promise.resolve(false);
    this.#sending = this.#deliver(timeout).catch(() => {
      this.#paused = 'delivery_storage_failed';
      this.diagnostic('delivery_storage_failed');
      return false;
    }).finally(() => { this.#sending = null; });
    return this.#sending;
  }
  async #deliver(timeout) {
    const batch = this.#outbox.batch(this.#batchItems);
    if (!batch.length) return false;
    this.#abort = new AbortController();
    const result = await send(this.#config, this.#authorization, batch, timeout, this.#abort.signal);
    this.#abort = null;
    if (result.code === 'ack') {
      this.#outbox.ack(batch);
      this.#sent += result.accepted;
      this.#deduped += result.deduped;
      this.#durable = result.durable;
      this.#attempts = 0;
      this.#lastError = null;
    } else {
      this.#lastError = result.code;
      this.#attempts = Math.min(this.#attempts + 1, 10);
      const redirect = result.code.startsWith('http_3');
      const quarantine = ['http_400', 'http_404', 'http_409', 'http_413'].includes(result.code) || redirect;
      if (['http_401', 'http_403', 'http_409'].includes(result.code) || redirect) this.#paused = result.code;
      if (result.code === 'http_429' && batch.length > 1) this.#batchItems = Math.max(1, Math.floor(batch.length / 2));
      const delay = Math.max(result.retryAfter ?? 0, Math.min(30, 0.25 * 2 ** this.#attempts) * (0.8 + Math.random() * 0.4));
      this.#outbox.defer(batch, delay, result.code, quarantine);
    }
    this.#notify();
    return true;
  }
  async flush(timeout = 5) {
    budget(timeout);
    const deadline = performance.now() + timeout * 1000;
    while (performance.now() < deadline) {
      const status = this.status();
      if (!status.pending || status.paused) return status;
      const remaining = (deadline - performance.now()) / 1000;
      if (remaining < 0.01) break;
      await wait(this.deliverOnce(Math.min(this.#config.requestTimeout, remaining)), remaining * 1000);
      if (performance.now() < deadline) await sleep(Math.min(20, deadline - performance.now()));
    }
    return this.status();
  }
  resume() {
    if (this.#closing) throw new Error('Collector is closed');
    this.#paused = null;
    this.#wake();
  }
  async close(timeout = 5) {
    budget(timeout);
    if (this.#closing) return this.status();
    this.#closing = true;
    clearTimeout(this.#timer);
    await this.flush(timeout);
    if (this.#sending) this.#abort?.abort();
    const release = () => {
      try { this.#lastCounts = this.#outbox.counts(); this.#outbox.close(); }
      catch { this.#lastError = 'queue_close_failed'; }
      this.#outbox = null;
    };
    if (this.#sending) this.#sending.finally(release); else release();
    return this.status();
  }
}

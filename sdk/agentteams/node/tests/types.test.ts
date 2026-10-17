import { Collector, Config, Worker, inject, mcpResult, type Carrier, type Status } from '../index.mjs';

const config = new Config({ platformUrl: 'https://platform.example.invalid', sourceId: 'source',
  bindingId: 'binding', collectorKey: 'not-a-real-key', spoolDir: 'not-executed' });
declare const collector: Collector;
const worker = new Worker('worker', 'team');
const sync = collector.task(worker)(function (this: { factor: number }, value: number) {
  return this.factor * value;
});
const syncResult: number = sync.call({ factor: 2 }, 3);
const asynchronous = collector.task(worker, { mode: 'promise', classify: mcpResult })(async (value: number) => value);
const promiseResult: Promise<number> = asynchronous(3);
const iterator = collector.callWorker(worker, worker, { mode: 'iterator' })(function* (): Generator<string, number, boolean> {
  const input = yield 'first';
  return input ? 1 : 0;
});
const stream: Generator<string, number, boolean> = iterator();
const step: IteratorResult<string, number> = stream.next(true);
const asyncIterator = collector.task(worker, { mode: 'asyncIterator' })(async function* () { yield 1; });
const asyncStream: AsyncGenerator<number, void, unknown> = asyncIterator();
const carrier: Carrier | null = inject();
const status: Status = collector.status();
collector.message(worker, worker, 'unknown');
const cleanup: Promise<Status> = collector.close(0);
// @ts-expect-error Collector configuration is immutable.
collector.config = config;
// @ts-expect-error A wrapped callable keeps its parameter types.
sync.call({ factor: 2 }, 'not-a-number');
// @ts-expect-error Transport timeout must be numeric.
collector.flush('five');
void [syncResult, promiseResult, step, asyncStream, carrier, status, cleanup];

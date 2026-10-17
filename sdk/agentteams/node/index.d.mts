export interface ConfigOptions {
  platformUrl: string;
  sourceId: string;
  bindingId: string;
  collectorKey: string;
  spoolDir: string;
  expectedScope?: string | null;
  expectedMocked?: boolean | null;
  maxItems?: number;
  maxBytes?: number;
  maxDiskBytes?: number;
  batchItems?: number;
  batchBytes?: number;
  requestTimeout?: number;
}
export class Config {
  constructor(options: ConfigOptions);
  readonly platformUrl: string;
  readonly sourceId: string;
  readonly bindingId: string;
  readonly spoolDir: string;
  readonly expectedScope: string | null;
  readonly expectedMocked: boolean | null;
  readonly maxItems: number;
  readonly maxBytes: number;
  readonly maxDiskBytes: number;
  readonly batchItems: number;
  readonly batchBytes: number;
  readonly requestTimeout: number;
}
export class Worker {
  constructor(name: string, team?: string | null);
  readonly name: string;
  readonly team: string | null;
}
export interface Carrier { trace_id: string; span_id: string; task_id?: string }
export type Outcome = 'success' | 'error' | 'unknown';
export interface InstrumentOptions {
  operation?: string;
  taskId?: string;
  carrier?: Carrier | (() => Carrier | null) | null;
  capture?: 'omit' | 'shape';
  mode?: 'sync' | 'promise' | 'iterator' | 'asyncIterator';
  classify?: (value: unknown) => Outcome;
}
export interface Status {
  pending: number;
  quarantined: number;
  bytes: number;
  sent: number;
  deduped: number;
  dropped: number;
  paused: string | null;
  lastError: string | null;
  durable: boolean | null;
  closed: boolean;
  deliveryActive: boolean;
}
type Callable = (this: any, ...args: any[]) => any;
type Wrapped<F extends Callable, O extends InstrumentOptions> = O['mode'] extends 'promise'
  ? (this: ThisParameterType<F>, ...args: Parameters<F>) => Promise<Awaited<ReturnType<F>>> : F;
export class Collector {
  constructor(config: Config, options?: { autostart?: boolean; onStatus?: (status: Status) => void | Promise<void> });
  readonly config: Config;
  task<O extends InstrumentOptions = InstrumentOptions>(worker: Worker, options?: O):
    <F extends Callable>(fn: F) => Wrapped<F, O>;
  callWorker<O extends InstrumentOptions = InstrumentOptions>(from: Worker, to: Worker, options?: O):
    <F extends Callable>(fn: F) => Wrapped<F, O>;
  heartbeat(): void;
  message(from: Worker, to?: Worker | null, status?: Outcome): void;
  status(): Status;
  flush(timeout?: number): Promise<Status>;
  close(timeout?: number): Promise<Status>;
  resume(): void;
  rotateKey(value: string): void;
}
export function inject(): Carrier | null;
export function mcpResult(value: unknown): Outcome;

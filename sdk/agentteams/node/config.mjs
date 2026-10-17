import path from 'node:path';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// 128 KiB for event journal headers/sector padding, plus lock DB and its journal.
export const DISK_RESERVE = 256 * 1024;

export function identifier(value, label = 'identifier') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value)) {
    throw new TypeError(`${label} must be an opaque identifier`);
  }
  return value;
}
export function uuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Expected a UUID');
  return value.toLowerCase();
}
export function key(value) {
  if (typeof value !== 'string' || !value || /\s|[\x00-\x1f\x7f]/.test(value)) {
    throw new TypeError('Collector key is missing or invalid');
  }
  return value;
}
export function budget(value) {
  if (!Number.isFinite(value) || value < 0 || value > 60) {
    throw new TypeError('Timeout must be between zero and 60 seconds');
  }
  return value;
}

export class Config {
  #key;
  constructor(options) {
    if (Number(process.versions.node.split('.')[0]) < 24) throw new Error('Node >=24 is required');
    const address = new URL(options.platformUrl);
    if (!['http:', 'https:'].includes(address.protocol) || !address.hostname || address.username ||
        address.password || address.search || address.hash || address.href.length > 4096) {
      throw new TypeError('Platform must be HTTP(S), without credentials, query or fragment');
    }
    this.platformUrl = address.href.replace(/\/+$/, '');
    this.sourceId = uuid(options.sourceId);
    this.bindingId = uuid(options.bindingId);
    this.expectedScope = options.expectedScope == null ? null : uuid(options.expectedScope);
    this.expectedMocked = options.expectedMocked ?? null;
    if (this.expectedMocked !== null && typeof this.expectedMocked !== 'boolean') {
      throw new TypeError('Expected Mock mode must be boolean');
    }
    this.#key = key(options.collectorKey);
    if (typeof options.spoolDir !== 'string' || !options.spoolDir) throw new TypeError('Spool directory is required');
    this.spoolDir = path.resolve(options.spoolDir);
    this.maxItems = options.maxItems ?? 10_000;
    this.maxBytes = options.maxBytes ?? 16 * 1024 * 1024;
    this.maxDiskBytes = options.maxDiskBytes ?? 64 * 1024 * 1024;
    this.batchItems = options.batchItems ?? 100;
    this.batchBytes = options.batchBytes ?? 256 * 1024;
    this.requestTimeout = options.requestTimeout ?? 5;
    for (const value of [this.maxItems, this.maxBytes, this.maxDiskBytes, this.batchItems, this.batchBytes]) {
      if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError('Queue bounds must be positive integers');
    }
    if (this.maxItems > 1_000_000 || this.maxDiskBytes < 512 * 1024 || this.maxDiskBytes > 256 * 1024 * 1024 ||
        this.maxDiskBytes < 2 * this.maxBytes + DISK_RESERVE || this.batchItems > 100 ||
        this.batchBytes > 256 * 1024 || this.batchBytes > this.maxBytes ||
        !Number.isFinite(this.requestTimeout) || this.requestTimeout < 0.1 || this.requestTimeout > 30) {
      throw new TypeError('Queue or transport bounds are outside the supported limits');
    }
    this.identity = Object.freeze({ schema: 1, runtime: 'node', platform: this.platformUrl,
      source: this.sourceId, binding: this.bindingId, scope: this.expectedScope, mocked: this.expectedMocked });
    this.endpoint = `${this.platformUrl}/api/v1/alicloud/agentteams/audit-sources/${this.sourceId}/events`;
    Object.freeze(this);
  }
  authorization() { return `Bearer ${this.#key}`; }
}

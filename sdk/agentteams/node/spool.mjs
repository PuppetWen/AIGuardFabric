import { DatabaseSync } from 'node:sqlite';
import * as fs from 'node:fs';
import path from 'node:path';
import { DISK_RESERVE } from './config.mjs';

const APPLICATION = 0x4147464e;
const FILES = new Set(['collector-lock.sqlite', 'collector-lock.sqlite-journal', 'events.sqlite3', 'events.sqlite3-journal']);
export class QueueFull extends Error {}
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
export function noLinks(directory) {
  let current = path.resolve(directory);
  for (;;) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error('Spool path contains a link');
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
function verify(db, identity, kind) {
  if (db.prepare('PRAGMA application_id').get().application_id !== APPLICATION) {
    throw new Error('Existing database is not an owned Node collector database');
  }
  const metadata = db.prepare("SELECT value FROM metadata WHERE name='identity'").get();
  const type = db.prepare("SELECT value FROM metadata WHERE name='kind'").get();
  if (metadata?.value !== identity || type?.value !== kind) throw new Error('Spool delivery identity differs');
}
function create(db, identity, kind) {
  db.exec(`PRAGMA application_id=${APPLICATION}; CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)`);
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('identity', identity);
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('kind', kind);
}
function existing(file) {
  if (!fs.existsSync(file)) return false;
  // Validate ownership before opening writable. SQLite itself then recovers owned hot
  // journals; a readOnly metadata query could not recover a crash-interrupted commit.
  const header = Buffer.alloc(100);
  const descriptor = fs.openSync(file, 'r');
  try {
    const bytes = fs.readSync(descriptor, header, 0, header.length, 0);
    if (bytes !== 100 || header.subarray(0, 16).toString() !== 'SQLite format 3\0' ||
        header.readInt32BE(68) !== APPLICATION) throw new Error('Existing database is not owned');
  } finally { fs.closeSync(descriptor); }
  return true;
}
export class Outbox {
  #owner;
  #db;
  #config;
  constructor(config) {
    this.#config = config;
    const directory = path.resolve(config.spoolDir);
    if (directory.startsWith('\\\\')) throw new Error('Use a local spool, not a network share');
    noLinks(directory);
    fs.mkdirSync(directory, { recursive: true });
    noLinks(directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (!FILES.has(entry.name) || !entry.isFile() || entry.isSymbolicLink()) {
        throw new Error('Spool directory contains unowned data or links');
      }
    }
    const identity = canonical(config.identity);
    const lock = path.join(directory, 'collector-lock.sqlite');
    const events = path.join(directory, 'events.sqlite3');
    try {
      const owned = existing(lock);
      if (!owned && fs.existsSync(events)) throw new Error('Events have no owned lock database');
      this.#owner = new DatabaseSync(lock, { timeout: 0, allowExtension: false });
      this.#owner.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_spill=OFF; PRAGMA max_page_count=16; BEGIN EXCLUSIVE');
      if (this.#owner.prepare('PRAGMA page_count').get().page_count > 16 ||
          this.#owner.prepare('PRAGMA page_size').get().page_size > 4096) throw new Error('Lock database exceeds reserved budget');
      if (owned) verify(this.#owner, identity, 'lock'); else create(this.#owner, identity, 'lock');
      // Commit identity once; EXCLUSIVE mode retains the OS lock across this commit.
      this.#owner.exec('COMMIT; BEGIN EXCLUSIVE');
      const present = existing(events);
      this.#db = new DatabaseSync(events, { timeout: 0, allowExtension: false });
      if (present) verify(this.#db, identity, 'events');
      this.#db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF');
      if (!present) this.#db.exec('PRAGMA auto_vacuum=FULL');
      const pageSize = this.#db.prepare('PRAGMA page_size').get().page_size;
      const pages = Math.floor((config.maxDiskBytes - DISK_RESERVE) / (2 * pageSize + 8));
      if (this.#db.prepare('PRAGMA page_count').get().page_count > pages) throw new Error('Existing spool exceeds disk bound');
      const applied = this.#db.prepare(`PRAGMA max_page_count=${pages}`).get().max_page_count;
      if (applied !== pages) throw new Error('Unable to enforce disk bound');
      if (!present) this.#mutate(() => {
        create(this.#db, identity, 'events');
        this.#db.exec(`CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,bytes INTEGER NOT NULL,
          state TEXT NOT NULL DEFAULT 'pending',retry_at REAL NOT NULL DEFAULT 0,reason TEXT);
          CREATE INDEX delivery ON events(state,retry_at,sequence)`);
      });
    } catch (error) { this.close(); throw error; }
  }
  #mutate(apply) {
    this.#db.exec('BEGIN IMMEDIATE');
    try { const result = apply(); this.#db.exec('COMMIT'); return result; }
    catch (error) {
      if (this.#db.isTransaction) this.#db.exec('ROLLBACK');
      throw error;
    }
  }
  append(event) {
    const payload = canonical(event), bytes = Buffer.byteLength(payload);
    if (bytes + this.#config.bindingId.length + 64 > this.#config.batchBytes) throw new QueueFull('event_too_large');
    this.#mutate(() => {
      const prior = this.#db.prepare('SELECT payload FROM events WHERE id=?').get(event.event_id);
      if (prior) {
        if (prior.payload !== payload) throw new Error('Event identity collision');
        return;
      }
      const counts = this.#db.prepare('SELECT count(*) AS count,coalesce(sum(bytes),0) AS bytes FROM events').get();
      if (counts.count >= this.#config.maxItems || counts.bytes + bytes > this.#config.maxBytes) {
        throw new QueueFull('queue_full');
      }
      this.#db.prepare('INSERT INTO events(id,payload,bytes) VALUES (?,?,?)').run(event.event_id, payload, bytes);
    });
  }
  batch(limit) {
    const rows = this.#db.prepare("SELECT id,payload FROM events WHERE state='pending' AND retry_at<=? ORDER BY sequence LIMIT ?")
      .all(Date.now() / 1000, Math.min(limit, this.#config.batchItems));
    const batch = [];
    let bytes = Buffer.byteLength(canonical({ binding_id: this.#config.bindingId, events: [] }));
    for (const row of rows) {
      const size = Buffer.byteLength(row.payload) + (batch.length ? 1 : 0);
      if (bytes + size > this.#config.batchBytes) break;
      batch.push([row.id, JSON.parse(row.payload)]);
      bytes += size;
    }
    return batch;
  }
  ack(batch) {
    this.#mutate(() => {
      const statement = this.#db.prepare("DELETE FROM events WHERE id=? AND payload=? AND state='pending'");
      for (const [id, event] of batch) statement.run(id, canonical(event));
    });
  }
  defer(batch, delay, reason, quarantine = false) {
    if (!/^[a-z0-9_]{1,64}$/.test(reason)) throw new Error('Unsafe diagnostic');
    this.#mutate(() => {
      const statement = this.#db.prepare('UPDATE events SET state=?,retry_at=?,reason=? WHERE id=? AND payload=?');
      for (const [id, event] of batch) {
        statement.run(quarantine ? 'quarantined' : 'pending', Date.now() / 1000 + delay, reason, id, canonical(event));
      }
    });
  }
  counts() {
    const counts = { pending: 0, quarantined: 0, bytes: 0 };
    for (const row of this.#db.prepare('SELECT state,count(*) AS count,sum(bytes) AS bytes FROM events GROUP BY state').all()) {
      counts[row.state] = row.count;
      counts.bytes += row.bytes;
    }
    return counts;
  }
  close() {
    if (this.#db) { this.#db.close(); this.#db = null; }
    if (this.#owner) { this.#owner.close(); this.#owner = null; }
  }
}

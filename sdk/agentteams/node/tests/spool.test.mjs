import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Outbox, QueueFull } from '../spool.mjs';
import { fixture, KEY } from './support.mjs';
import { child } from './processes.mjs';

test('restart preserves exact payload and never stores collector Key', async t => {
  const f = fixture(t, 'restart'), config = f.config();
  const value = { event_id: 'stable-one', message: null, event_time: '2026-09-30T00:00:00.000Z' };
  const first = new Outbox(config); first.append(value); const batch = first.batch(100); first.close();
  const second = new Outbox(config);
  try {
    assert.deepEqual(second.batch(100), batch);
    for (const name of fs.readdirSync(config.spoolDir)) assert(!fs.readFileSync(path.join(config.spoolDir, name)).includes(KEY));
    second.ack(batch); assert.equal(second.counts().pending, 0);
  } finally { second.close(); }
});
test('full queue retains prior events and same ID cannot mutate content', t => {
  const f = fixture(t, 'bounds'), box = new Outbox(f.config({ maxItems: 1 }));
  try {
    box.append({ event_id: 'first', message: null }); box.append({ event_id: 'first', message: null });
    assert.throws(() => box.append({ event_id: 'first', message: 'changed' }));
    assert.throws(() => box.append({ event_id: 'second', message: null }), QueueFull);
    assert.equal(box.batch(100)[0][0], 'first'); assert.equal(box.counts().pending, 1);
  } finally { box.close(); }
});
test('binding/source/platform identity change refuses old queue without retargeting or deletion', t => {
  const f = fixture(t, 'identity'), config = f.config();
  const box = new Outbox(config); box.append({ event_id: 'first' }); box.close();
  for (const options of [{ bindingId: '00000000-0000-4000-8000-000000000099' },
    { sourceId: '00000000-0000-4000-8000-000000000099' }, { platformUrl: 'http://127.0.0.1:2' }]) {
    assert.throws(() => new Outbox(f.config(options)));
  }
  const original = new Outbox(config);
  try { assert.equal(original.counts().pending, 1); } finally { original.close(); }
});
test('a second owner of the same directory is refused and the first owner remains writable', t => {
  const f = fixture(t, 'owners'), config = f.config(), first = new Outbox(config);
  try {
    assert.throws(() => new Outbox(config), /locked|busy/i);
    first.append({ event_id: 'owned' }); assert.equal(first.counts().pending, 1);
  } finally { first.close(); }
  const resumed = new Outbox(config); resumed.close();
});
test('foreign database is rejected byte-for-byte unchanged', t => {
  const f = fixture(t, 'foreign'), config = f.config(); fs.mkdirSync(config.spoolDir);
  const file = path.join(config.spoolDir, 'collector-lock.sqlite'), db = new DatabaseSync(file);
  db.exec("CREATE TABLE user_data(value TEXT); INSERT INTO user_data VALUES ('preserve')"); db.close();
  const before = fs.readFileSync(file);
  assert.throws(() => new Outbox(config), /owned/);
  assert.deepEqual(fs.readFileSync(file), before);
});
test('spool symlink/junction is rejected and cleanup only unlinks the owned link', t => {
  const f = fixture(t, 'link'), config = f.config(), target = path.join(f.directory, 'owned-target');
  fs.mkdirSync(target); fs.writeFileSync(path.join(target, 'keep.txt'), 'preserve');
  fs.symlinkSync(target, config.spoolDir, process.platform === 'win32' ? 'junction' : 'dir');
  f.add(() => { assert.equal(path.dirname(config.spoolDir), f.directory); fs.unlinkSync(config.spoolDir); });
  assert.throws(() => new Outbox(config), /link/);
  assert.equal(fs.readFileSync(path.join(target, 'keep.txt'), 'utf8'), 'preserve');
});
test('process termination releases the OS lock and preserves already committed events', async t => {
  const f = fixture(t, 'killed-owner'), config = f.config();
  const code = `import {Config} from ${JSON.stringify(new URL('../config.mjs', import.meta.url).href)};
    import {Outbox} from ${JSON.stringify(new URL('../spool.mjs', import.meta.url).href)};
    let raw=''; for await(const part of process.stdin) raw+=part;
    const box=new Outbox(new Config(JSON.parse(raw))); box.append({event_id:'persisted-before-crash'});
    process.stdout.write('ready\\n'); setInterval(()=>{},1000);`;
  const owned = await child(f, code, { ...config, collectorKey: KEY });
  assert.throws(() => new Outbox(config), /locked|busy/i);
  await owned.kill();
  const resumed = new Outbox(config);
  try { assert.equal(resumed.batch(100)[0][0], 'persisted-before-crash'); } finally { resumed.close(); }
});
test('SQLite hot journal recovery rolls back interrupted mutation without losing original event', async t => {
  const f = fixture(t, 'hot-journal'), config = f.config(), box = new Outbox(config);
  box.append({ event_id: 'first', message: 'original' }); const original = box.batch(100); box.close();
  const code = `import {DatabaseSync} from 'node:sqlite'; let raw='';for await(const part of process.stdin)raw+=part;
    const db=new DatabaseSync(JSON.parse(raw));db.exec('PRAGMA cache_size=1; BEGIN IMMEDIATE');
    db.prepare('UPDATE events SET payload=?').run(JSON.stringify({event_id:'first',message:'uncommitted'.repeat(5000)}));
    process.stdout.write('ready\\n');setInterval(()=>{},1000);`;
  const owned = await child(f, code, path.join(config.spoolDir, 'events.sqlite3'));
  await owned.kill();
  const journal = path.join(config.spoolDir, 'events.sqlite3-journal');
  assert(fs.existsSync(journal), 'fixture must exercise a real crash journal');
  const resumed = new Outbox(config);
  try { assert.deepEqual(resumed.batch(100), original); } finally { resumed.close(); }
});

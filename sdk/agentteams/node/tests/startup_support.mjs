import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { noLinks } from '../spool.mjs';

export const STARTUP = fileURLToPath(new URL('../startup.cjs', import.meta.url));
export const DRAIN = fileURLToPath(new URL('../startup-drain.mjs', import.meta.url));
export const KEY = 'agf_owned_startup_collector_secret';
const OWNER = '/root/meter_review:node-startup-tests-v1';
const SOURCE = '00000000-0000-4000-8000-000000000001';
const BINDING = '00000000-0000-4000-8000-000000000002';
const SCOPE = '00000000-0000-4000-8000-000000000003';
const marker = directory => path.join(directory, '.startup-test-owner');
function root() {
  const input = process.env.AGF_NODE_STARTUP_TEST_DIR;
  assert(input && path.isAbsolute(input), 'explicit task-owned AGF_NODE_STARTUP_TEST_DIR required');
  const directory = path.resolve(input);
  noLinks(directory);
  fs.mkdirSync(directory, { recursive: true });
  if (!fs.existsSync(marker(directory))) {
    assert.deepEqual(fs.readdirSync(directory), [], 'never adopt existing user/test data');
    fs.writeFileSync(marker(directory), JSON.stringify({ owner: OWNER, path: directory }), { flag: 'wx' });
  }
  assert.deepEqual(JSON.parse(fs.readFileSync(marker(directory))), { owner: OWNER, path: directory });
  return directory;
}
function tree(directory) {
  noLinks(directory);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    assert(!entry.isSymbolicLink());
    if (entry.isDirectory()) tree(path.join(directory, entry.name));
    else assert(entry.isFile());
  }
}
export function fixture(t, label) {
  const parent = root(), directory = path.join(parent, `${label}-${randomUUID().replaceAll('-', '')}`);
  fs.mkdirSync(directory);
  fs.writeFileSync(marker(directory), JSON.stringify({ owner: OWNER, path: directory }), { flag: 'wx' });
  const closers = [];
  t.after(async () => {
    for (const close of closers.reverse()) await close();
    assert.equal(path.dirname(path.resolve(directory)), parent);
    assert.deepEqual(JSON.parse(fs.readFileSync(marker(directory))), { owner: OWNER, path: directory });
    tree(directory);
    fs.rmSync(directory, { recursive: true, force: false });
    if (fs.readdirSync(parent).length === 1) {
      assert.deepEqual(JSON.parse(fs.readFileSync(marker(parent))), { owner: OWNER, path: parent });
      noLinks(parent); fs.unlinkSync(marker(parent)); fs.rmdirSync(parent);
    }
  });
  const write = (name, text) => {
    const file = path.resolve(directory, name);
    assert(file.startsWith(`${directory}${path.sep}`));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text, { flag: 'wx' });
    return file;
  };
  const environment = { ...process.env, NODE_OPTIONS: '', AGF_NODE_STARTUP_CONFIG: path.join(directory, 'startup.json'),
    AGF_PLATFORM_URL: 'http://127.0.0.1:1', AGF_SOURCE_ID: SOURCE, AGF_BINDING_ID: BINDING,
    AGF_SCOPE_ID: SCOPE, AGF_EXPECTED_MOCKED: 'true', AGF_STARTUP_KEY: KEY, AGF_SPOOL_DIR: path.join(directory, 'spool') };
  async function execute(args, extra = {}) {
    const child = spawn(process.execPath, args, { cwd: directory, env: { ...environment, ...extra },
      stdio: ['ignore', 'pipe', 'pipe'] });
    closers.push(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); });
    let stdout = '', stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', text => { stdout += text; if (stdout.length > 64 * 1024) child.kill(); });
    child.stderr.on('data', text => { stderr += text; if (stderr.length > 64 * 1024) child.kill(); });
    const timer = setTimeout(() => child.kill(), 8000);
    try {
      const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
      assert(stdout.length <= 64 * 1024 && stderr.length <= 64 * 1024);
      return { code, stdout, stderr, json: () => JSON.parse(stdout.trim().split('\n').at(-1)) };
    } finally { clearTimeout(timer); }
  }
  return { directory, write, environment,
    configure(targets, change = {}) {
      write('startup.json', JSON.stringify({ version: 1, keyEnv: 'AGF_STARTUP_KEY', targets, ...change }));
    },
    run(entry, { preloads = [], args = [], env = {} } = {}) {
      return execute([...preloads.flatMap(file => ['--require', file]), '--require', STARTUP, entry, ...args], env);
    },
    drain(env = {}) { return execute([DRAIN, '--drain-only', '2'], env); },
    events() {
      const file = path.join(directory, 'spool', 'events.sqlite3');
      if (!fs.existsSync(file)) return [];
      const db = new DatabaseSync(file, { readOnly: true, allowExtension: false });
      try { return db.prepare('SELECT payload FROM events ORDER BY sequence').all().map(row => JSON.parse(row.payload)); }
      finally { db.close(); }
    },
    async receiver() {
      const bodies = [], headers = [], seen = new Set();
      const control = { drop: false, badAck: false };
      const server = createServer(async (request, response) => {
        const parts = [];
        for await (const chunk of request) parts.push(chunk);
        const body = Buffer.concat(parts).toString(); bodies.push(body); headers.push(request.headers);
        const batch = JSON.parse(body);
        let accepted = 0, deduped = 0;
        for (const event of batch.events) {
          if (seen.has(event.event_id)) deduped += 1;
          else { seen.add(event.event_id); accepted += 1; }
        }
        if (control.drop) { response.destroy(); return; }
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify(control.badAck ? { accepted } : { received: batch.events.length, accepted,
          deduped, scopeId: SCOPE, mocked: true, durable: true, authorizationStatus: 'unknown' }));
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      closers.push(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
      return { bodies, headers, control, url: `http://127.0.0.1:${server.address().port}` };
    },
  };
}
export function target(file, exported = ['work'], changes = {}) {
  return { file, export: exported, kind: 'task', worker: { name: 'worker-a', team: 'team-a' },
    operation: 'owned-task', mode: 'sync', ...changes };
}
export const closeAndPrint = expression => `Promise.resolve(require(${JSON.stringify(STARTUP)}).close(0)).then(() => console.log(JSON.stringify(${expression})));`;

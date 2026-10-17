import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { Collector, Config } from '../index.mjs';
import { noLinks } from '../spool.mjs';

export const KEY = 'agf_owned_node_collector_secret';
export const SOURCE = '00000000-0000-4000-8000-000000000001';
export const BINDING = '00000000-0000-4000-8000-000000000002';
export const SCOPE = '00000000-0000-4000-8000-000000000003';
export const ROOT = path.resolve(process.env.AGF_NODE_SDK_TEST_DIR ??
  path.join(fileURLToPath(new URL('../../../../', import.meta.url)), 'node-sdk-validation'));
const OWNER = '/root/meter_tests:node-sdk-validation:20260930';
const marker = directory => path.join(directory, 'ownership.json');
function initRoot() {
  noLinks(ROOT);
  fs.mkdirSync(ROOT, { recursive: true });
  if (fs.existsSync(marker(ROOT))) assert.equal(JSON.parse(fs.readFileSync(marker(ROOT))).owner, OWNER);
  else {
    assert.equal(fs.readdirSync(ROOT).length, 0, 'do not adopt existing task data');
    fs.writeFileSync(marker(ROOT), JSON.stringify({ owner: OWNER, path: ROOT }), { flag: 'wx' });
  }
}
function validateTree(directory) {
  noLinks(directory);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    assert(!entry.isSymbolicLink(), 'never recursively delete a link');
    if (entry.isDirectory()) validateTree(path.join(directory, entry.name));
    else assert(entry.isFile(), 'unknown filesystem object');
  }
}
export function fixture(t, label) {
  initRoot();
  const directory = path.join(ROOT, `${label}-${randomUUID().replaceAll('-', '')}`);
  fs.mkdirSync(directory);
  fs.writeFileSync(marker(directory), JSON.stringify({ owner: OWNER, path: directory }), { flag: 'wx' });
  const closers = [];
  t.after(async () => {
    for (const close of closers.reverse()) await close();
    assert.equal(path.dirname(path.resolve(directory)), ROOT);
    const identity = JSON.parse(fs.readFileSync(marker(directory)));
    assert.equal(identity.owner, OWNER);
    assert.equal(identity.path, directory);
    validateTree(directory);
    fs.rmSync(directory, { recursive: true, force: false });
  });
  return {
    directory,
    add(close) { closers.push(close); },
    config(options = {}) {
      return new Config({ platformUrl: 'http://127.0.0.1:1', sourceId: SOURCE, bindingId: BINDING,
        expectedScope: SCOPE, expectedMocked: true, collectorKey: KEY, spoolDir: path.join(directory, 'spool'), ...options });
    },
    collector(config, options = {}) {
      const collector = new Collector(config, { autostart: false, ...options });
      closers.push(() => collector.close(0));
      return collector;
    },
    async receiver() {
      const bodies = [], headers = [], seen = new Set(), replies = [];
      const server = createServer(async (request, response) => {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const raw = Buffer.concat(chunks).toString();
        bodies.push(raw);
        headers.push(request.headers);
        const batch = JSON.parse(raw);
        const reply = replies.shift();
        if (reply && typeof reply === 'object' && reply.redirect) {
          response.writeHead(302, { Location: reply.redirect }).end(); return;
        }
        if (Number.isInteger(reply)) { response.writeHead(reply).end(); return; }
        let accepted = 0, deduped = 0;
        for (const event of batch.events) {
          if (seen.has(event.event_id)) deduped += 1;
          else { seen.add(event.event_id); accepted += 1; }
        }
        if (reply === 'drop') { response.destroy(); return; }
        if (reply === 'truncate') {
          response.writeHead(200, { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' });
          response.flushHeaders();
          response.write('{"received":');
          setTimeout(() => response.destroy(), 20); return;
        }
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify(reply === 'bad_ack' ? { accepted: 1 } : reply && typeof reply === 'object' ? reply : {
          received: batch.events.length, accepted, deduped, scopeId: SCOPE, mocked: true,
          durable: true, authorizationStatus: 'unknown' }));
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      closers.push(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
      return { bodies, headers, replies, url: `http://127.0.0.1:${server.address().port}` };
    },
  };
}
export function cleanRoot() {
  if (!fs.existsSync(ROOT)) return;
  noLinks(ROOT);
  assert.equal(JSON.parse(fs.readFileSync(marker(ROOT))).owner, OWNER);
  assert.deepEqual(fs.readdirSync(ROOT), ['ownership.json'], 'only empty owned root may be removed');
  fs.unlinkSync(marker(ROOT));
  fs.rmdirSync(ROOT);
}

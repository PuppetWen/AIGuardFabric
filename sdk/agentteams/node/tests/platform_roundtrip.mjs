// Opt-in real loopback platform/SQL probe. Key arrives on stdin; stdout contains safe metrics only.
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { Collector, Config, Worker, inject } from '../index.mjs';

const ROOT_OWNERS = new Set(['AIGuardFabric requirements completion 20260920',
  'AIGuardFabric requirements completion local 20260920']);
const OWNER_PREFIX = 'AIGuardFabric AgentTeams SDK platform test ';
const PRIVATE_VALUE = 'owned-sdk-user@example.invalid; phone=13800138000';

function windowsScript(code) {
  const executable = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  assert(path.isAbsolute(executable) && fs.statSync(executable).isFile());
  return execFileSync(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(code, 'utf16le').toString('base64')], { windowsHide: true, stdio: 'pipe', timeout: 15_000 });
}
function noReparse(values) {
  const candidates = new Set();
  for (const value of values) {
    let current = value;
    for (;;) {
      const metadata = fs.lstatSync(current);
      assert(!metadata.isSymbolicLink(), 'reparse path rejected');
      candidates.add(current);
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  if (process.platform === 'win32') {
    const encoded = Buffer.from(JSON.stringify([...candidates])).toString('base64');
    windowsScript(`$ErrorActionPreference='Stop'; $paths=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')));
      foreach($entry in $paths){$item=Get-Item -LiteralPath $entry -Force; if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse path rejected'}}`);
  }
}
function ownedCase(request, create = false) {
  const root = process.env.AGF_SDK_TEST_DIR;
  assert(typeof root === 'string' && path.isAbsolute(root));
  assert(['requirements-20260920', 'codex-requirements-20260920'].includes(path.basename(root)));
  const rootMarker = path.join(root, 'task-owner.txt');
  noReparse([root, rootMarker]);
  assert(ROOT_OWNERS.has(fs.readFileSync(rootMarker, 'utf8').replace(/^\uFEFF/, '').trim()));
  assert(typeof request.run_id === 'string' && /^[0-9a-f]{32}$/.test(request.run_id));
  const directory = path.join(root, 'agentteams-sdk-case-' + request.run_id);
  const marker = path.join(directory, 'task-owner.txt');
  if (create && !fs.existsSync(directory)) {
    fs.mkdirSync(directory);
    fs.writeFileSync(marker, OWNER_PREFIX + request.run_id, { flag: 'wx' });
  }
  if (!fs.existsSync(directory) && request.action === 'cleanup') return { root, directory, marker };
  noReparse([directory, marker]);
  assert.equal(fs.readFileSync(marker, 'utf8'), OWNER_PREFIX + request.run_id);
  assert.equal(path.dirname(path.resolve(directory)), path.resolve(root));
  return { root, directory, marker };
}
function cleanCase(request) {
  const { root, directory, marker } = ownedCase(request);
  if (!fs.existsSync(directory)) return { cleaned: true };
  const tree = [];
  function collect(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    if (entries.length) noReparse(entries.map(entry => path.join(current, entry.name)));
    for (const entry of entries) {
      const target = path.join(current, entry.name);
      assert(!entry.isSymbolicLink() && (entry.isFile() || entry.isDirectory()));
      tree.push(target);
      if (entry.isDirectory()) collect(target);
    }
  }
  collect(directory);
  noReparse([directory, ...tree]);
  if (process.platform === 'win32') {
    // Check and delete within one native shell; no computed path is handed to another deletion shell.
    const encoded = Buffer.from(JSON.stringify({ root, directory, owner: OWNER_PREFIX + request.run_id })).toString('base64');
    windowsScript(`$ErrorActionPreference='Stop'; $v=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')));
      $target=[IO.Path]::GetFullPath($v.directory); $parent=[IO.Path]::GetDirectoryName($target);
      if($parent -cne [IO.Path]::GetFullPath($v.root)){throw 'Case outside root'};
      if((Get-Content -LiteralPath (Join-Path $target 'task-owner.txt') -Raw) -cne $v.owner){throw 'Owner mismatch'};
      $nodes=@(Get-Item -LiteralPath $target -Force)+@(Get-ChildItem -LiteralPath $target -Force -Recurse);
      foreach($node in $nodes){if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse descendant'}};
      Remove-Item -LiteralPath $target -Recurse -Force`);
  } else {
    for (const entry of fs.readdirSync(directory)) {
      if (entry !== 'task-owner.txt') fs.rmSync(path.join(directory, entry), { recursive: true });
    }
    fs.unlinkSync(marker);
    fs.rmdirSync(directory);
  }
  assert(!fs.existsSync(directory));
  return { cleaned: true };
}
function configuration(request, directory) {
  const address = new URL(request.platform_url);
  assert.equal(address.protocol, 'http:');
  assert.equal(address.hostname, '127.0.0.1');
  assert(address.port && address.pathname === '/' && !address.username && !address.password && !address.search && !address.hash);
  assert.equal(request.expected_mocked, true);
  assert(['business', 'revoked', 'disabled'].includes(request.action));
  return new Config({ platformUrl: request.platform_url, sourceId: request.source_id, bindingId: request.binding_id,
    collectorKey: request.collector_key, spoolDir: path.join(directory, 'node-' + request.action),
    expectedScope: request.scope_id, expectedMocked: true, maxBytes: 64 * 1024,
    maxDiskBytes: 512 * 1024, batchBytes: 16 * 1024, requestTimeout: 2 });
}
function containsPrivate(config, credential) {
  return fs.readdirSync(config.spoolDir).some(name => {
    const raw = fs.readFileSync(path.join(config.spoolDir, name));
    return [credential, PRIVATE_VALUE, 'owned-sdk-user@example.invalid', '13800138000'].some(value => raw.includes(Buffer.from(value)));
  });
}
function queued(config) {
  const database = new DatabaseSync(path.join(config.spoolDir, 'events.sqlite3'), { readOnly: true, allowExtension: false });
  try {
    return database.prepare("SELECT payload FROM events WHERE state='pending' ORDER BY sequence").all()
      .map(row => JSON.parse(row.payload));
  } finally { database.close(); }
}
async function business(config, credential) {
  const collector = new Collector(config, { autostart: false });
  const first = new Worker('worker-demo', 'my-team'), second = new Worker('sdk-receiver', 'sdk-receiving-team');
  const calls = { root: 0, child: 0, handoff: 0, send: 0, error: 0, timeout: 0 };
  let carrier;
  const original = Object.freeze({ private: PRIVATE_VALUE });
  const failed = new Error(PRIVATE_VALUE), timedOut = new DOMException(PRIVATE_VALUE, 'TimeoutError');
  const child = collector.task(second, { operation: 'sdk.child', mode: 'promise', carrier: () => carrier })(async argument => {
    calls.child += 1;
    await Promise.resolve();
    return argument;
  });
  const handoff = collector.callWorker(first, second, { operation: 'sdk.handoff', mode: 'promise' })(async argument => {
    calls.handoff += 1;
    carrier = inject();
    assert.equal(carrier.task_id, 'sdk-root-task');
    return child(argument);
  });
  const root = collector.task(first, { operation: 'sdk.root', mode: 'promise', taskId: 'sdk-root-task' })(async (argument, privateArgument) => {
    calls.root += 1;
    assert.equal(privateArgument, PRIVATE_VALUE);
    const value = await handoff(argument);
    calls.send += 1; // The test business send completes before its metadata event.
    collector.message(first, second, 'success');
    return value;
  });
  const failure = collector.task(first, { operation: 'sdk.failure', mode: 'promise', taskId: 'sdk-error-task' })(async () => {
    calls.error += 1;
    throw failed;
  });
  const timeout = collector.task(second, { operation: 'sdk.timeout', mode: 'promise', taskId: 'sdk-timeout-task' })(async () => {
    calls.timeout += 1;
    throw timedOut;
  });
  try {
    assert.equal(await root(original, PRIVATE_VALUE), original);
    await assert.rejects(failure(), error => error === failed);
    await assert.rejects(timeout(), error => error === timedOut);
    collector.heartbeat();
    const frozen = queued(config);
    assert.equal(frozen.length, 7);
    assert(!containsPrivate(config, credential));
    const firstReport = await collector.flush(8);
    assert.equal(firstReport.pending, 0); assert.equal(firstReport.sent, 7); assert.equal(firstReport.durable, true);
    // Explicitly repeat the unchanged telemetry identities, never business functions.
    for (const event of frozen) collector.record(event);
    const secondReport = await collector.flush(8);
    assert.equal(secondReport.pending, 0); assert.equal(secondReport.deduped, 7);
    assert(Object.values(calls).every(count => count === 1) && !containsPrivate(config, credential));
    return { events: 7, durable: true, deduped: 7, business_once: true,
      return_identity: true, exception_identity: true, private_omitted: true };
  } finally { await collector.close(0); }
}
async function blocked(config, credential, action) {
  const collector = new Collector(config, { autostart: false });
  const expected = action === 'revoked' ? 'http_401' : 'http_409';
  let calls = 0, report;
  const original = Object.freeze({ private: PRIVATE_VALUE });
  const application = collector.task(new Worker('worker-demo', 'my-team'), { operation: 'sdk.blocked', mode: 'promise' })(async (argument, privateArgument) => {
    calls += 1;
    assert.equal(privateArgument, PRIVATE_VALUE);
    return argument;
  });
  try {
    assert.equal(await application(original, PRIVATE_VALUE), original);
    collector.heartbeat();
    report = await collector.flush(5);
    assert.equal(calls, 1); assert.equal(report.sent, 0); assert.equal(report.paused, expected);
    assert.equal(report.pending, action === 'revoked' ? 2 : 0);
    assert.equal(report.quarantined, action === 'revoked' ? 0 : 2);
    assert(!containsPrivate(config, credential));
  } finally { await collector.close(0); }
  const reopened = new Collector(config, { autostart: false });
  try {
    const retained = reopened.status();
    assert.equal(retained.pending, report.pending); assert.equal(retained.quarantined, report.quarantined);
  } finally { await reopened.close(0); }
  return { business_once: true, private_omitted: true, sent: 0, paused: expected, pending: report.pending,
    quarantined: report.quarantined, retained_after_reopen: true };
}
async function main() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    assert(length <= 64 * 1024);
    chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (request.action === 'cleanup') return cleanCase(request);
  const { directory } = ownedCase(request, true);
  const config = configuration(request, directory);
  return request.action === 'business' ? business(config, request.collector_key)
    : blocked(config, request.collector_key, request.action);
}
try {
  const report = await main();
  console.log(JSON.stringify({ ok: true, ...report }));
} catch (error) {
  // No traceback, argument/exception text, carrier, credential or business payload in gate logs.
  console.log(JSON.stringify({ ok: false, error_type: error?.constructor?.name ?? 'Unknown' }));
  process.exitCode = 1;
}

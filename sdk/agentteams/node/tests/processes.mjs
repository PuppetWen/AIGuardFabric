import { spawn } from 'node:child_process';
import { once } from 'node:events';
import assert from 'node:assert/strict';

export async function child(f, code, input) {
  const process = spawn(globalThis.process.execPath, ['--input-type=module', '-e', code], { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(process, 'exit');
  f.add(async () => {
    if (process.exitCode === null && process.signalCode === null) process.kill();
    await exited;
  });
  process.stdin.end(JSON.stringify(input));
  let failure = '';
  process.stderr.on('data', data => { failure += data; });
  let timer;
  const ready = await Promise.race([
    once(process.stdout, 'data').then(([data]) => data.toString()),
    exited.then(() => { throw new Error(`Owned subprocess ended before ready: ${failure}`); }),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Owned subprocess readiness timed out')), 10_000); }),
  ]).finally(() => clearTimeout(timer));
  assert.equal(ready.trim(), 'ready');
  return { process, async kill() { process.kill(); await exited; } };
}

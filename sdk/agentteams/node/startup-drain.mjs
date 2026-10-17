// Queue-only maintenance. No configured business module is loaded or invoked.
import configuration from './startup/config.cjs';
import runtime from './startup/runtime.cjs';

async function main() {
  configuration.supported();
  const args = process.argv.slice(2);
  if (args.length < 1 || args.length > 2 || args[0] !== '--drain-only' ||
      (args[1] !== undefined && !/^(?:[1-9]|[12][0-9]|30)$/.test(args[1]))) {
    throw new Error('Use startup-drain.mjs --drain-only [1..30 seconds]');
  }
  const descriptor = configuration.read({ drainOnly: true });
  const { instance } = runtime.collector(descriptor, { autostart: false });
  let status;
  try { status = await instance.flush(Number(args[1] ?? 5)); }
  finally { await instance.close(0); }
  process.stdout.write(`${JSON.stringify({ ...status, businessModulesLoaded: false, businessCalls: 0 })}\n`);
  if (status.pending || status.quarantined || status.lastError) process.exitCode = 1;
}
try { await main(); }
catch {
  process.stderr.write('AgentTeams Node queue drain configuration or delivery incomplete\n');
  process.exitCode = 1;
}

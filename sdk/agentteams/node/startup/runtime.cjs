'use strict';
const configuration = require('./config.cjs');
const { install } = require('./load.cjs');

function collector(descriptor, { autostart = true, optional = false } = {}) {
  // These existing ESM files have no top-level await. Node's supported sync require(esm) loads SDK only.
  const { Collector, Config, Worker } = require('../index.mjs');
  let config;
  try { config = new Config(configuration.collectorOptions(descriptor)); }
  catch { throw new Error('AgentTeams Node startup collector configuration invalid'); }
  let instance;
  try { instance = new Collector(config, { autostart }); }
  catch {
    if (optional) return { instance: null, Worker };
    throw new Error('AgentTeams Node startup owned queue unavailable');
  }
  return { instance, Worker };
}
function start(descriptor) {
  const { instance, Worker } = collector(descriptor, { optional: true });
  if (!instance) {
    // Forks may inherit preload plus the parent's spool. No competing queue or telemetry retry executes business.
    return Object.freeze({ status: () => ({ supported: false, reason: 'startup_owned_queue_gap', automaticEsmCoverage: false }),
      close: async () => ({ supported: false, reason: 'startup_owned_queue_gap' }) });
  }
  let closed = false;
  const configured = descriptor.targets.map(target => {
    const from = new Worker(target.worker.name, target.worker.team);
    const to = target.to === null ? null : new Worker(target.to.name, target.to.team);
    const options = { operation: target.operation, mode: target.mode, capture: target.capture,
      ...(target.taskId === undefined ? {} : { taskId: target.taskId }) };
    return { ...target, state: 'startup_waiting',
      decorate: target.kind === 'task' ? instance.task(from, options) : instance.callWorker(from, to, options) };
  });
  const hook = install(configured, code => instance.diagnostic(code));
  async function close(timeout = 5) {
    if (closed) return instance.status();
    closed = true;
    hook.detach();
    return instance.close(timeout);
  }
  // Does not install uncaughtException, signal or exit handlers; original business failure/exit remains original.
  process.once('beforeExit', () => { void close(5).catch(() => {}); });
  return Object.freeze({
    status() { return { ...instance.status(), targets: hook.snapshot(), automaticEsmCoverage: false }; },
    close,
  });
}
module.exports = Object.freeze({ collector, start });

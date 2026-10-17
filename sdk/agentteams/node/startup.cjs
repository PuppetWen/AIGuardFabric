'use strict';
// Preload with --require; Node itself still executes the application's original entry and argv.
const { isMainThread } = require('node:worker_threads');
const configuration = require('./startup/config.cjs');
configuration.supported();
if (!isMainThread) {
  // Inherited --require in workers must not contend for the main process's immutable queue identity.
  module.exports = Object.freeze({ status: () => ({ supported: false, reason: 'startup_worker_thread_gap' }) });
} else {
  let runtime;
  try { runtime = require('./startup/runtime.cjs').start(configuration.read()); }
  catch { throw new Error('AgentTeams Node startup configuration or owned queue unavailable'); }
  module.exports = runtime;
}

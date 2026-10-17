import { Collector, Config } from '../index.mjs';

// Set credentials in your application's secret environment, never in source code.
const settings = process.env;
if (!['true', 'false'].includes(settings.AGF_EXPECTED_MOCKED)) {
  throw new Error('AGF_EXPECTED_MOCKED must explicitly be true or false');
}
const collector = new Collector(new Config({
  platformUrl: settings.AGF_PLATFORM_URL,
  sourceId: settings.AGF_SOURCE_ID,
  bindingId: settings.AGF_BINDING_ID,
  expectedScope: settings.AGF_SCOPE_ID,
  expectedMocked: settings.AGF_EXPECTED_MOCKED === 'true',
  collectorKey: settings.AGF_COLLECTOR_KEY,
  spoolDir: settings.AGF_SPOOL_DIR,
}), { autostart: false });
collector.heartbeat();
try { console.log(await collector.flush(5)); } // Only counters and fixed diagnostic codes.
finally { await collector.close(0); }

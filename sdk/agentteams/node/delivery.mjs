import { request as http } from 'node:http';
import { request as https } from 'node:https';
import { uuid } from './config.mjs';
import { canonical } from './spool.mjs';

export function validateAck(config, batch, text) {
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { code: 'invalid_ack' };
    const { received, accepted, deduped, mocked, durable, authorizationStatus } = value;
    const scope = uuid(value.scopeId);
    if (![received, accepted, deduped].every(n => Number.isSafeInteger(n) && n >= 0) ||
        received !== batch.length || accepted + deduped !== received || typeof mocked !== 'boolean' ||
        typeof durable !== 'boolean' || authorizationStatus !== 'unknown' ||
        (config.expectedScope !== null && scope !== config.expectedScope) ||
        (config.expectedMocked !== null && mocked !== config.expectedMocked)) return { code: 'invalid_ack' };
    return { code: 'ack', accepted, deduped, durable };
  } catch { return { code: 'invalid_ack' }; }
}
export function send(config, authorization, batch, timeout, signal) {
  return new Promise(resolve => {
    let settled = false;
    let request;
    const finish = value => { if (!settled) { settled = true; clearTimeout(timer); resolve(value); } };
    const timer = setTimeout(() => { request?.destroy(); finish({ code: 'network_error' }); }, timeout * 1000);
    const body = canonical({ binding_id: config.bindingId, events: batch.map(([, event]) => event) });
    try {
      const address = new URL(config.endpoint);
      // Dedicated standard-library request: no redirects, business client, dispatcher or headers.
      request = (address.protocol === 'https:' ? https : http)(address, {
        method: 'POST', agent: false, signal, headers: { Authorization: authorization,
          'Content-Type': 'application/json', Accept: 'application/json',
          'Content-Length': Buffer.byteLength(body), 'User-Agent': 'AIGuardFabric-AgentTeams-Node/0.1' },
      }, response => {
        if (response.statusCode !== 200) {
          const raw = response.headers['retry-after'];
          const retryAfter = typeof raw === 'string' && /^\d+(\.\d+)?$/.test(raw) ? Math.min(60, Number(raw)) : 0;
          response.destroy();
          finish({ code: `http_${response.statusCode}`, retryAfter });
          return;
        }
        const chunks = [];
        let bytes = 0;
        response.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > 64 * 1024) { response.destroy(); finish({ code: 'invalid_ack' }); }
          else chunks.push(chunk);
        });
        response.on('end', () => finish(validateAck(config, batch, Buffer.concat(chunks).toString('utf8'))));
        response.on('error', () => finish({ code: 'network_error' }));
        response.on('aborted', () => finish({ code: 'network_error' }));
      });
      request.on('error', () => finish({ code: 'network_error' }));
      request.end(body);
    } catch { request?.destroy(); finish({ code: 'network_error' }); }
  });
}

/* Local MCP fixture. No network calls or filesystem operations; every tool is a read-only echo. */
const http = require('node:http');
const { randomUUID } = require('node:crypto');
const port = Number(process.env.AGF_TEST_MCP_PORT || 18084);
const token = process.env.AGF_TEST_MCP_TOKEN || 'mcp-loopback-validation';
const sessions = new Set();
const calls = [];
const tools = [{ name: 'readonly_echo', description: 'Read-only local test echo',
  inputSchema: { type: 'object', properties: { text: { type: 'string' }, stream: { type: 'boolean' }, redact: { type: 'boolean' } } },
  annotations: { readOnlyHint: true, destructiveHint: false } }];
function reply(res, status, data, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(data == null ? '' : JSON.stringify(data));
}
http.createServer(async (req, res) => {
  if (req.url === '/stats' && req.method === 'GET') return reply(res, 200, { methods: calls, sessions: sessions.size });
  if (req.url !== '/mcp') return reply(res, 404, { error: 'unknown fixture path' });
  if (req.headers.authorization !== `Bearer ${token}`) return reply(res, 401, null);
  const modern = req.headers['mcp-protocol-version'] === '2026-07-28';
  const session = req.headers['mcp-session-id'];
  if (!modern && session && !sessions.has(session)) return reply(res, 404, null);
  if (req.method === 'DELETE') {
    if (modern) return reply(res, 405, null);
    sessions.delete(session); calls.push('DELETE'); return reply(res, 204, null);
  }
  if (req.method !== 'POST') return reply(res, 405, null);
  let length = 0; const chunks = [];
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 1024 * 1024) return reply(res, 413, null);
    chunks.push(chunk);
  }
  let frame;
  try { frame = JSON.parse(Buffer.concat(chunks)); }
  catch { return reply(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
  calls.push(frame.method);
  if (modern && (req.headers['mcp-method'] !== frame.method
      || frame.params?._meta?.['io.modelcontextprotocol/protocolVersion'] !== '2026-07-28')) {
    return reply(res, 400, { jsonrpc: '2.0', id: frame.id, error: { code: -32020, message: 'Header mismatch' } });
  }
  const send = (result, headers) => reply(res, 200, { jsonrpc: '2.0', id: frame.id, result }, headers);
  if (frame.method === 'initialize') {
    const id = randomUUID(); sessions.add(id);
    return send({ protocolVersion: '2025-11-25', capabilities: { tools: {} },
      serverInfo: { name: 'AIGuardFabric local MCP fixture', version: '1' } }, { 'mcp-session-id': id });
  }
  if (frame.method === 'server/discover') return send({ serverInfo: { name: 'AIGuardFabric local MCP fixture', version: '1' }, capabilities: { tools: {} } });
  if (frame.method === 'notifications/initialized') return reply(res, 202, null);
  if (frame.method === 'tools/list') return send({ tools });
  if (frame.method === 'tools/call' && frame.params?.name === 'readonly_echo') {
    const args = frame.params.arguments || {};
    const text = String(args.text || 'Hello from the local MCP fixture')
      + (args.redact ? ' sk-proj-abcdefghijklmnopqrstuvwx' : '');
    const result = { content: [{ type: 'text', text }], _meta: { fixture: 'loopback-only' } };
    if (!args.stream) return send(result);
    res.writeHead(200, { 'content-type': 'text/event-stream', 'x-accel-buffering': 'no' });
    res.write(': local fixture\n\n');
    res.write('event: message\ndata: ' + JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'probe', progress: 1 } }) + '\n\n');
    return res.end('event: message\ndata: ' + JSON.stringify({ jsonrpc: '2.0', id: frame.id, result }) + '\n\n');
  }
  reply(res, 404, { jsonrpc: '2.0', id: frame.id, error: { code: -32601, message: 'Method not found' } });
}).listen(port, '127.0.0.1', () => process.stdout.write(`Local MCP fixture listening on 127.0.0.1:${port}\n`));

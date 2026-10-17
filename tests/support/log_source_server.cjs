// Loopback-only HTTP Pull fixture. No external requests or production credentials.
const http = require('node:http');
let requests = 0;
const server = http.createServer((req, res) => {
  if (req.url === '/status') {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ requests }));
  }
  if (req.url !== '/logs') { res.writeHead(404); return res.end(); }
  if (req.headers.authorization !== 'Bearer source-local-test') {
    res.writeHead(401); return res.end();
  }
  requests += 1;
  const cursor = Number(req.headers['x-agf-cursor'] || 0);
  if (!Number.isInteger(cursor) || cursor < 0) { res.writeHead(400); return res.end(); }
  const next = Math.min(cursor + 1, 3);
  res.writeHead(200, { 'Content-Type': 'application/json', 'X-AGF-Next-Cursor': String(next) });
  res.end(JSON.stringify(cursor >= 3 ? [] : [{
    time: new Date().toISOString(), host: 'local-verification.example.test',
    real_client_ip: '192.0.2.25', request_method: 'GET', request_uri: '/validation/' + next,
    rule_id: 'local-only-' + next, acl_action: 'block', status: 403,
  }]));
});
server.listen(Number(process.env.AGF_TEST_PULL_PORT || 18083), '127.0.0.1');
process.on('SIGTERM', () => server.close());


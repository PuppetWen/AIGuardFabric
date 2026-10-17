/** Local-only OIDC test service. Never use its public test key or accounts in production. */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const port = Number(process.env.AGF_TEST_OIDC_PORT || 18082);
const issuer = `http://127.0.0.1:${port}`;
const browserOrigin = process.env.AGF_TEST_OIDC_BROWSER_ORIGIN || issuer;
const callback = process.env.AGF_TEST_OIDC_REDIRECT_URI || 'http://127.0.0.1:8081/login/oidc/callback';
const fixture = path.resolve(__dirname, '../../crates/agf-api/tests/fixtures');
const key = fs.readFileSync(path.join(fixture, 'oidc-test-only.pem'));
const jwks = JSON.parse(fs.readFileSync(path.join(fixture, 'oidc-test-jwks.json'), 'utf8'));
const codes = new Map();
const json = (res, status, value) => {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(value));
};
function token(claims) {
  const encode = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const input = `${encode({ alg: 'ES256', typ: 'JWT', kid: 'local-test-key' })}.${encode(claims)}`;
  return `${input}.${crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}
http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, issuer);
    const now = Math.floor(Date.now() / 1000);
    for (const [code, record] of codes) if (record.expires <= now) codes.delete(code);
    if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, { issuer, authorization_endpoint: `${browserOrigin}/authorize`,
        token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'], subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['ES256'], code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'], scopes_supported: ['openid', 'profile', 'email'] });
    }
    if (req.method === 'GET' && url.pathname === '/jwks') return json(res, 200, jwks);
    if (req.method === 'GET' && url.pathname === '/authorize') {
      const p = url.searchParams;
      if (p.get('client_id') !== 'console' || p.get('redirect_uri') !== callback
        || p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256'
        || !p.get('state') || !p.get('nonce') || !p.get('code_challenge')) return json(res, 400, { error: 'invalid_request' });
      if (!p.has('approve')) {
        url.searchParams.set('approve', '1');
        const target = url.pathname + url.search;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'" });
        return res.end(`<html lang="zh"><meta charset="utf-8"><title>本地 OIDC 验收</title>
          <body style="font:18px sans-serif;max-width:650px;margin:15vh auto"><h1>本地模拟企业身份中心</h1>
          <p>仅用于功能验收；不连接真实企业账号，不输入真实密码。</p>
          <p>测试用户：企业测试员工 · browser-employee@example.test</p>
          <a href="${target.replaceAll('&', '&amp;').replaceAll('"', '&quot;')}">使用测试企业身份继续</a></body></html>`);
      }
      const code = crypto.randomBytes(24).toString('base64url');
      codes.set(code, { nonce: p.get('nonce'), challenge: p.get('code_challenge'), expires: now + 120 });
      const redirect = new URL(callback);
      redirect.searchParams.set('state', p.get('state'));
      redirect.searchParams.set('code', code);
      res.writeHead(302, { Location: redirect.toString(), 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
      return res.end();
    }
    if (req.method === 'POST' && url.pathname === '/token') {
      let data = '';
      for await (const part of req) { data += part; if (data.length > 16384) return json(res, 413, { error: 'too_large' }); }
      const p = new URLSearchParams(data);
      const record = codes.get(p.get('code')); codes.delete(p.get('code'));
      const challenge = crypto.createHash('sha256').update(p.get('code_verifier') || '').digest('base64url');
      if (p.get('grant_type') !== 'authorization_code' || p.get('client_id') !== 'console'
        || p.get('client_secret') !== 'local-test-secret' || p.get('redirect_uri') !== callback
        || !record || record.expires <= now || challenge !== record.challenge) return json(res, 400, { error: 'invalid_grant' });
      return json(res, 200, { token_type: 'Bearer', access_token: 'local-test-only', id_token: token({
        iss: issuer, aud: 'console', sub: 'browser-employee', iat: now, exp: now + 300,
        nonce: record.nonce, email: 'browser-employee@example.test', email_verified: true, name: '企业测试员工' }) });
    }
    return json(res, 404, { error: 'not_found' });
  } catch { return json(res, 500, { error: 'test_provider_error' }); }
}).listen(port, '127.0.0.1', () => process.stdout.write(`Local test IdP listening on ${issuer}\n`));

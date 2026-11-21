// Proof Gatekeeper agent — local dev server (same logic as api/agent.js).
// Listens on 127.0.0.1 only. HMAC is enforced exactly like in production:
// set AGENT_GAMES_HMAC_SECRET to a TEST value and sign requests with it
// (see test-local.js). No secret configured = 401 for every request.
// There is deliberately no placeholder secret.
//
//   export AGENT_GAMES_HMAC_SECRET="$(openssl rand -hex 16)"  # test value, local only
//   node server.js
//   node test-local.js   # starts this server, runs the signed curl cases

const http = require('http');
const { handleTask, verifyHmac, getHmacSecret } = require('./lib/gatekeeper');

const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = '127.0.0.1';

const server = http.createServer((req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };

  if (req.method === 'GET' && req.url === '/agent') {
    return send(200, { ok: true, protocolVersion: 'v1', mode: 'local' });
  }
  if (req.method !== 'POST' || req.url !== '/agent') {
    return send(404, { error: 'not found' });
  }

  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 1e6) req.destroy(); });
  req.on('end', async () => {
    const raw = Buffer.from(body, 'utf8');
    const check = verifyHmac(raw, req.headers['x-agent-games-signature']);
    if (!check.ok) {
      if (check.error === 'hmac_secret_not_configured') {
        return send(401, {
          error: 'hmac_secret_not_configured',
          detail: 'AGENT_GAMES_HMAC_SECRET is not set. Set it (test value locally, platform secret in production) — no request is processed without it.',
        });
      }
      return send(401, { error: check.error, detail: 'Request signature did not verify. Rejecting without processing (fail closed).' });
    }
    let envelope;
    try { envelope = JSON.parse(body); } catch { return send(400, { error: 'invalid JSON' }); }
    try {
      return send(200, await handleTask(envelope));
    } catch (e) {
      return send(e.status || 500, { error: e.message || 'internal error' });
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`gatekeeper listening on http://${HOST}:${PORT}/agent (localhost only)`);
  console.log(`HMAC secret configured: ${getHmacSecret() ? 'yes' : 'NO - all requests will 401'}`);
});

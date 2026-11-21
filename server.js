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
const { handleTask, verifyHmac, signResponse, getHmacSecret } = require('./lib/gatekeeper');

const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = '127.0.0.1';

const server = http.createServer((req, res) => {
  // Every response is signed with the HMAC secret when one is configured
  // (x-agent-games-signature over the exact response bytes, mirroring the
  // encoding the platform used for its request signature). The platform
  // preflight requires a signed protocol-v1 response; unsigned responses
  // fail the protocol check even with HTTP 200.
  const send = (code, obj, encoding) => {
    const body = JSON.stringify(obj);
    const sig = signResponse(Buffer.from(body, 'utf8'), encoding);
    const headers = { 'Content-Type': 'application/json' };
    if (sig) headers['x-agent-games-signature'] = sig;
    res.writeHead(code, headers);
    res.end(body);
  };

  if (req.method === 'GET' && req.url === '/agent') {
    return send(200, { ok: true, protocolVersion: 'v1' });
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

    // Signed-preflight tolerance (dashboard diagnostic 2026-11-21 18:12 WIB:
    // the signed preflight got HTTP 400 here). The preflight is a
    // connectivity check, not a task: its body is empty, non-JSON, or a JSON
    // object without task fields. Answer those with 200 so the preflight
    // passes instead of 400. Real tasks always carry task_id and go through
    // the full decide+prove path below; a task envelope in another shape
    // will surface as a preflight ack + a keys-only log line, so the shape
    // can be fixed from the log instead of failing the preflight.
    let envelope = null;
    let parsed = false;
    if (body.length > 0) {
      try { envelope = JSON.parse(body); parsed = true; } catch { parsed = false; }
    }
    const t = envelope && typeof envelope === 'object' ? (envelope.input || envelope.task || envelope) : null;
    // A task is recognized by task_id OR taskId (the platform may use
    // camelCase); anything else signed is the preflight connectivity check.
    const hasId = (v) => v !== undefined && v !== null && v !== '';
    const looksLikeTask = !!(t && (hasId(t.task_id) || hasId(t.taskId)));
    if (!looksLikeTask) {
      // Diagnostic log: keys only, never values and never headers (the
      // signature header must never be logged).
      try {
        console.log(JSON.stringify({
          route: 'POST /agent', preflight_ack: true, parsed,
          keys: envelope && typeof envelope === 'object' ? Object.keys(envelope) : [],
          bodyLen: body.length,
        }));
      } catch { /* logging must never break the response */ }
      return send(200, { ok: true, protocolVersion: 'v1' }, check.encoding);
    }

    try {
      return send(200, await handleTask(envelope), check.encoding);
    } catch (e) {
      // Diagnostic log for task failures: which field is missing + the
      // envelope's keys (keys only, never values, never headers), so a
      // field-naming mismatch can be fixed from the log.
      try {
        const envObj = envelope && typeof envelope === 'object' ? envelope : null;
        console.log(JSON.stringify({
          route: 'POST /agent', error: String(e.message || e), status: e.status || 500,
          keys: envObj ? Object.keys(envObj) : [],
          taskKeys: envObj && envObj.task && typeof envObj.task === 'object' ? Object.keys(envObj.task) : [],
          inputKeys: envObj && envObj.input && typeof envObj.input === 'object' ? Object.keys(envObj.input) : [],
        }));
      } catch { /* logging must never break the response */ }
      return send(e.status || 500, { error: e.message || 'internal error' }, check.encoding);
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`gatekeeper listening on http://${HOST}:${PORT}/agent (localhost only)`);
  console.log(`HMAC secret configured: ${getHmacSecret() ? 'yes' : 'NO - all requests will 401'}`);
});

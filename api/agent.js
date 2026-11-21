// Proof Gatekeeper agent — Vercel Serverless Function (Node runtime).
// POST /api/agent receives a signed task envelope from Agent Games,
// verifies the HMAC, decides APPROVE/REJECT with the 7 trap rules, and
// returns the decision with a locally generated Groth16 proof.
//
// Environment (set in the Vercel dashboard, never committed):
//   AGENT_GAMES_HMAC_SECRET — the platform-generated secret from the
//     Agent Games dashboard ("Rotate Secret"). No placeholder is used:
//     if it is unset, every request fails closed with 401.
//
// Vercel notes:
//   - Hobby plan functions cap at 10 s; a proof takes ~0.3-1.2 s, so this
//     fits comfortably inside the limit (see vercel.json maxDuration).
//   - Circuit files (gatekeeper.wasm / .zkey) live in this same api/
//     directory so they ship with the function; vercel.json includeFiles
//     is a second guarantee.
//   - The raw request body is read from the stream for HMAC verification
//     (Vercel KB: "How do I get the raw body of a Serverless Function?").
//     If the runtime ever pre-parses the body, verification fails closed.

const { handleTask, verifyHmac, readRawBody } = require('../lib/gatekeeper');

function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

module.exports = async (req, res) => {
  // Health probe.
  if (req.method === 'GET') {
    return send(res, 200, { ok: true, protocolVersion: 'v1', mode: 'vercel' });
  }
  if (req.method !== 'POST') {
    return send(res, 405, { error: 'method not allowed' });
  }

  // 1. Raw body first — the signature covers the exact bytes sent.
  let raw;
  try {
    const r = await readRawBody(req);
    if (r.parsed) {
      return send(res, 401, {
        error: 'body_already_parsed',
        detail: 'Request body was already parsed by the runtime, so the raw signed bytes cannot be recovered and the HMAC cannot be verified honestly.',
      });
    }
    raw = r.raw;
  } catch (e) {
    return send(res, 400, { error: 'unreadable_body', detail: String(e.message || e) });
  }

  // 2. HMAC verification, fail closed. No secret configured = 401 for all.
  const check = verifyHmac(raw, req.headers['x-agent-games-signature']);
  if (!check.ok) {
    if (check.error === 'hmac_secret_not_configured') {
      return send(res, 401, {
        error: 'hmac_secret_not_configured',
        detail: 'AGENT_GAMES_HMAC_SECRET is not set on this deployment. Set the platform-generated secret (dashboard -> Rotate Secret) as an env var and redeploy. No request is processed without it.',
      });
    }
    return send(res, 401, { error: check.error, detail: 'Request signature did not verify. Rejecting without processing (fail closed).' });
  }

  // 3. Parse + decide + prove (must finish inside the 60 s platform deadline).
  let envelope;
  try {
    envelope = JSON.parse(raw.toString('utf8'));
  } catch {
    return send(res, 400, { error: 'invalid JSON' });
  }
  try {
    const out = await handleTask(envelope);
    return send(res, 200, out);
  } catch (e) {
    return send(res, e.status || 500, { error: e.message || 'internal error' });
  }
};

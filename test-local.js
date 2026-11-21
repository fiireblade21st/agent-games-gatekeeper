// Local end-to-end test for the Proof Gatekeeper agent.
// Starts server.js on a test port with a TEST HMAC secret, sends HMAC-signed
// requests for the 3 required cases (+ PROOF_REUSED replay + an unsigned
// request that must 401), and verifies every returned Groth16 proof with
// snarkjs against verification_key.json. Exits 0 only if all checks pass.
//
//   node test-local.js
//
// No real secret is used here: a throwaway secret is generated fresh on
// every run and only ever signs requests to localhost.

const { spawn } = require('child_process');
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');

const PORT = 18787;
// Throwaway secret generated fresh on every run — it only ever signs
// requests to localhost. No real platform secret is ever stored here.
const SECRET = crypto.randomBytes(16).toString('hex');
const VK = path.join(__dirname, 'api', 'verification_key.json');

const BASE = {
  task_id: 'gk_24_9d1',
  minimum: '1000',
  public_balance: '1460',
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: '12345',
  condition_recipient: '12345',
  amount: '500',
  max_transfer: '1000',
  proof_tx: 'tx_valid_001',
};

const CASES = [
  {
    name: '1 VALID -> APPROVE / VALID_CONDITION',
    body: { ...BASE },
    expect: { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proof: true },
  },
  {
    name: '2 VK_SUBSTITUTION -> REJECT (proof_vk != registered_vk)',
    body: { ...BASE, task_id: 'gk_24_9d2', proof_vk: '0x0000000000000000000000000000000000000000000000000000000000000001', proof_tx: 'tx_vk_002' },
    expect: { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof: true },
  },
  {
    name: '3 EXPIRED_CONDITION -> REJECT (current_block == expiry_block)',
    body: { ...BASE, task_id: 'gk_24_9d3', current_block: 19842201, proof_tx: 'tx_exp_003' },
    expect: { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', proof: true },
  },
  {
    name: '4 PROOF_REUSED -> REJECT, proof null (replay of case 1 proof_tx)',
    body: { ...BASE },
    expect: { decision: 'REJECT', reason_code: 'PROOF_REUSED', proof: false },
  },
];

function post(bodyObj, { sign = true } = {}) {
  const body = JSON.stringify(bodyObj);
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
  if (sign) {
    headers['x-agent-games-signature'] = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/agent', method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function postRaw(body, { sign = true } = {}) {
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
  if (sign) {
    headers['x-agent-games-signature'] = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/agent', method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function get() {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/agent', method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

function validSig(r) {
  return r.headers
    && r.headers['x-agent-games-signature'] === crypto.createHmac('sha256', SECRET).update(r.body).digest('hex');
}

async function main() {
  const server = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  // Wait for the listen line.
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server did not start in 15s. Log:\n' + serverLog)), 15000);
    const iv = setInterval(() => {
      if (serverLog.includes('listening on')) { clearTimeout(t); clearInterval(iv); resolve(); }
    }, 100);
  });

  let failures = 0;
  try {
    for (const c of CASES) {
      const r = await post(c.body);
      let json = null;
      try { json = JSON.parse(r.body); } catch { /* fall through */ }
      const okStatus = r.status === 200;
      const okDecision = json && json.decision === c.expect.decision && json.reason_code === c.expect.reason_code;
      let okProof = false;
      let proofDetail = '';
      if (c.expect.proof) {
        if (json && json.proof && json.public_signals) {
          try {
            okProof = await snarkjs.groth16.verify(
              require(VK), json.public_signals, json.proof,
            );
            proofDetail = `proof verify=${okProof}, proof_ms=${json.proof_ms}`;
          } catch (e) { proofDetail = 'proof verify threw: ' + e.message; }
        } else {
          proofDetail = 'no proof returned';
        }
      } else {
        okProof = json && json.proof === null && json.public_signals === null;
        proofDetail = 'proof=null as expected';
      }
      const pass = okStatus && okDecision && okProof && validSig(r);
      if (!pass) failures += 1;
      console.log(`${pass ? 'PASS' : 'FAIL'}  ${c.name}  [http=${r.status} ${proofDetail} sig=${validSig(r)}]`);
      if (!pass) console.log('      response:', r.body.slice(0, 500));
    }

    // 5. Unsigned request must 401 (fail closed).
    const r5 = await post({ ...BASE, task_id: 'gk_24_9d5', proof_tx: 'tx_unsigned_005' }, { sign: false });
    const pass5 = r5.status === 401;
    if (!pass5) failures += 1;
    console.log(`${pass5 ? 'PASS' : 'FAIL'}  5 UNSIGNED -> 401 fail-closed  [http=${r5.status}]`);

    // 7. Signed empty body (platform preflight ping) must 200 with the exact
    // signed protocol-v1 JSON, not 400.
    const r7 = await postRaw('');
    const pass7 = r7.status === 200 && r7.body === '{"ok":true,"protocolVersion":"v1"}' && validSig(r7);
    if (!pass7) failures += 1;
    console.log(`${pass7 ? 'PASS' : 'FAIL'}  7 SIGNED EMPTY BODY (preflight) -> 200 signed {"ok":true,"protocolVersion":"v1"}  [http=${r7.status} sig=${validSig(r7)}]`);
    if (!pass7) console.log('      response:', r7.body.slice(0, 300));

    // 8. Signed {} (preflight without task fields) must 200 the same way.
    const r8 = await postRaw('{}');
    const pass8 = r8.status === 200 && r8.body === '{"ok":true,"protocolVersion":"v1"}' && validSig(r8);
    if (!pass8) failures += 1;
    console.log(`${pass8 ? 'PASS' : 'FAIL'}  8 SIGNED {} (preflight) -> 200 signed {"ok":true,"protocolVersion":"v1"}  [http=${r8.status} sig=${validSig(r8)}]`);
    if (!pass8) console.log('      response:', r8.body.slice(0, 300));

    // 9. GET /agent health must return the exact signed protocol-v1 JSON.
    const r9 = await get();
    const pass9 = r9.status === 200 && r9.body === '{"ok":true,"protocolVersion":"v1"}' && validSig(r9);
    if (!pass9) failures += 1;
    console.log(`${pass9 ? 'PASS' : 'FAIL'}  9 GET /agent -> 200 signed {"ok":true,"protocolVersion":"v1"}  [http=${r9.status} sig=${validSig(r9)}]`);
    if (!pass9) console.log('      response:', r9.body.slice(0, 300));

    // 10. camelCase envelope (platform field naming) must decide like case 1.
    const r10 = await post({
      taskId: 'gk_24_9d10', minimum: '1000', publicBalance: '1460',
      expiryBlock: 19842201, currentBlock: 19832000, recipient: '12345',
      conditionRecipient: '12345', amount: '500', maxTransfer: '1000',
      proof_tx: 'tx_camel_010',
    });
    let json10 = null;
    try { json10 = JSON.parse(r10.body); } catch { /* fall through */ }
    const pass10 = r10.status === 200 && json10 && json10.decision === 'APPROVE'
      && json10.reason_code === 'VALID_CONDITION' && validSig(r10);
    if (!pass10) failures += 1;
    console.log(`${pass10 ? 'PASS' : 'FAIL'}  10 CAMELCASE ENVELOPE -> APPROVE / VALID_CONDITION  [http=${r10.status} sig=${validSig(r10)}]`);
    if (!pass10) console.log('      response:', r10.body.slice(0, 300));

    // 11. Signed envelope with task_id but missing other fields must still 400.
    const r11 = await post({ task_id: 'gk_24_9d11' });
    const pass11 = r11.status === 400 && r11.body.includes('missing field');
    if (!pass11) failures += 1;
    console.log(`${pass11 ? 'PASS' : 'FAIL'}  11 TASK_ID ONLY -> 400 missing field  [http=${r11.status}]`);
    if (!pass11) console.log('      response:', r11.body.slice(0, 300));

    // 6. No-secret server must 401 everything (spawn a second server w/o env).
    const server2 = spawn(process.execPath, ['server.js'], {
      cwd: __dirname,
      env: { ...process.env, PORT: '18788', AGENT_GAMES_HMAC_SECRET: '' },
      stdio: 'ignore',
    });
    // Wait for server2 to listen (poll GET /agent; fixed sleeps are flaky
    // when the VM is busy — proof generation on this box can take seconds).
    await new Promise((resolve, reject) => {
      const deadline = Date.now() + 15000;
      const tick = () => {
        const req = http.request({ host: '127.0.0.1', port: 18788, path: '/agent', method: 'GET' }, (res) => { res.resume(); resolve(); });
        req.on('error', () => { if (Date.now() > deadline) reject(new Error('second server did not start in 15s')); else setTimeout(tick, 200); });
        req.end();
      };
      tick();
    });
    const r6 = await new Promise((resolve, reject) => {
      const body = JSON.stringify({ ...BASE, task_id: 'gk_24_9d6', proof_tx: 'tx_nosecret_006' });
      const req = http.request({
        host: '127.0.0.1', port: 18788, path: '/agent', method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'x-agent-games-signature': crypto.createHmac('sha256', SECRET).update(body).digest('hex'),
        },
      }, (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    server2.kill();
    const pass6 = r6.status === 401 && r6.body.includes('hmac_secret_not_configured');
    if (!pass6) failures += 1;
    console.log(`${pass6 ? 'PASS' : 'FAIL'}  6 NO-SECRET SERVER -> 401 hmac_secret_not_configured  [http=${r6.status}]`);
  } finally {
    server.kill();
  }

  console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('TEST HARNESS ERROR:', e.message); process.exit(2); });

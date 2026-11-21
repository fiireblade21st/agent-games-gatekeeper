// Shared Proof Gatekeeper logic — used by both the local dev server
// (server.js) and the Vercel serverless handler (api/agent.js).
// No wallet, no chain calls, no registration. Decision rules + Groth16
// proof generation only.
//
// Decision rules (trap order, matches the official event page + circuit):
//   1. proof_vk == registered_vk        else VK_SUBSTITUTION
//   2. proof_tx not already accepted    else PROOF_REUSED
//   3. public_balance >= minimum        else THRESHOLD_MISMATCH
//   4. current_block < expiry_block     else EXPIRED_CONDITION
//   5. recipient == condition_recipient else RECIPIENT_MISMATCH
//   6. amount <= max_transfer           else AMOUNT_OVERFLOW
//   else VALID_CONDITION -> APPROVE
//
// Circuit inputs (verified empirically from gatekeeper.wasm via snarkjs):
//   taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, salt
//   decision: APPROVE=1, REJECT=0; salt defaults to 1.
//   taskId: sha256(task_id string) mod BN254 field prime (LOCAL convention;
//           the platform's exact encoding for non-numeric ids is unverified).
//   vk hashes: hex value mod BN254 prime (published vkHash exceeds the field prime).
// Public signals returned by the circuit, in order:
//   [Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum, publicBalance,
//    expiryBlock, currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//    decision, taskId]

const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Registered gatekeeper vkHash from https://agentgames.zkverify.io/api/circuit-info
// (fetched 21 Nov 2026, see circuit-info.json). Used as the default registered_vk
// when a task envelope does not carry one.
const REGISTERED_VK_HEX = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

// Circuit artifacts live next to the Vercel handler so they are bundled with
// the function (see vercel.json includeFiles as a second guarantee).
const CIRCUIT_DIR = path.join(__dirname, '..', 'api');
const WASM = path.join(CIRCUIT_DIR, 'gatekeeper.wasm');
const ZKEY = path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey');

// In-memory set of accepted proof_tx references (PROOF_REUSED guard).
// Process-local only: a serverless cold start or a restart clears it.
// For a production deployment this must move to durable storage.
const acceptedProofTx = new Set();

function fieldFromString(s) {
  // Numeric strings pass through; anything else is sha256(string) mod p.
  if (/^-?\d+$/.test(String(s))) return BigInt(String(s)) % P;
  return BigInt('0x' + crypto.createHash('sha256').update(String(s)).digest('hex')) % P;
}

function fieldFromVk(v) {
  // Accept hex (0x...) or decimal string; reduce mod p (published vkHash > p).
  const s = String(v);
  const n = s.startsWith('0x') || s.startsWith('0X') ? BigInt(s) : BigInt(s);
  return n % P;
}

function decide(t) {
  const registeredVk = t.registered_vk || REGISTERED_VK_HEX;
  const proofVk = t.proof_vk || t.proofVk || registeredVk;
  if (String(proofVk).toLowerCase() !== String(registeredVk).toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', registeredVk, proofVk };
  }
  if (t.proof_tx && acceptedProofTx.has(String(t.proof_tx))) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', registeredVk, proofVk };
  }
  if (BigInt(t.public_balance) < BigInt(t.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', registeredVk, proofVk };
  }
  if (BigInt(t.current_block) >= BigInt(t.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', registeredVk, proofVk };
  }
  if (String(t.recipient) !== String(t.condition_recipient)) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', registeredVk, proofVk };
  }
  if (BigInt(t.amount) > BigInt(t.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', registeredVk, proofVk };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', registeredVk, proofVk };
}

function buildCircuitInput(t, r) {
  return {
    taskId: fieldFromString(String(t.task_id)).toString(),
    registeredVkHash: fieldFromVk(r.registeredVk).toString(),
    proofVkHash: fieldFromVk(r.proofVk).toString(),
    minimum: String(t.minimum),
    publicBalance: String(t.public_balance),
    expiryBlock: String(t.expiry_block),
    currentBlock: String(t.current_block),
    recipient: fieldFromString(String(t.recipient)).toString(),
    conditionRecipient: fieldFromString(String(t.condition_recipient)).toString(),
    amount: String(t.amount),
    maxTransfer: String(t.max_transfer),
    decision: r.decision === 'APPROVE' ? '1' : '0',
    salt: '1',
  };
}

const REQUIRED_FIELDS = [
  'task_id', 'minimum', 'public_balance', 'expiry_block', 'current_block',
  'recipient', 'condition_recipient', 'amount', 'max_transfer',
];

// Runs one task envelope end-to-end. Returns the response object.
// Throws an Error with .status for client errors (400) and proof failures (500).
async function handleTask(envelope) {
  const started = Date.now();
  const t = envelope.task || envelope;
  for (const k of REQUIRED_FIELDS) {
    if (t[k] === undefined || t[k] === null || t[k] === '') {
      const e = new Error(`missing field: ${k}`);
      e.status = 400;
      throw e;
    }
  }
  const r = decide(t);

  // PROOF_REUSED is unprovable with this circuit: the circuit enforces
  // decision == AND(all six on-chain conditions) and has no reuse input
  // among its 13 signals, so a REJECT on an otherwise-valid task fails
  // witness generation (GatekeeperEvaluation line 102). Return the REJECT
  // without a proof instead of a 500. Whether the platform accepts a
  // proofless REJECT for this case is UNVERIFIED — see README.
  if (r.reason_code === 'PROOF_REUSED') {
    return {
      task_id: String(t.task_id),
      decision: 'REJECT',
      reason_code: 'PROOF_REUSED',
      proof: null,
      public_signals: null,
      proof_ms: Date.now() - started,
      note: 'No Groth16 proof possible for this case: circuit has no proof-reuse input and asserts decision == AND(all conditions).',
    };
  }

  const input = buildCircuitInput(t, r);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    if (r.decision === 'APPROVE' && t.proof_tx) acceptedProofTx.add(String(t.proof_tx));
    return {
      task_id: String(t.task_id),
      decision: r.decision,
      reason_code: r.reason_code,
      proof,
      public_signals: publicSignals,
      proof_ms: Date.now() - started,
    };
  } catch (e) {
    const err = new Error('proof generation failed: ' + String((e && e.message) || e));
    err.status = 500;
    throw err;
  }
}

// --- HMAC verification -----------------------------------------------------
// The platform signs each task envelope: HMAC-SHA256 over the RAW request
// body, sent as the `x-agent-games-signature` header. The header encoding
// (hex vs base64) is not pinned down in the public field guide, so both are
// accepted. Comparison is constant-time.
//
// FAIL-CLOSED: if AGENT_GAMES_HMAC_SECRET is unset/empty, verification is
// impossible and every request is rejected with 401. There is deliberately
// NO placeholder secret anywhere in this repo.
function getHmacSecret() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  return s && s.length > 0 ? s : null;
}

function verifyHmac(rawBody, signatureHeader) {
  const secret = getHmacSecret();
  if (!secret) return { ok: false, error: 'hmac_secret_not_configured' };
  if (!signatureHeader) return { ok: false, error: 'missing_signature' };
  const sig = String(signatureHeader).trim();
  const hexDigest = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const b64Digest = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  for (const [encoding, candidate] of [['hex', hexDigest], ['base64', b64Digest]]) {
    try {
      const a = Buffer.from(sig, 'utf8');
      const b = Buffer.from(candidate, 'utf8');
      // A match also reveals which encoding the platform used, so responses
      // can mirror it (see signResponse).
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return { ok: true, encoding };
    } catch { /* keep trying the other encoding */ }
  }
  return { ok: false, error: 'bad_signature' };
}

// Sign a response body with the platform HMAC secret, mirroring the
// encoding the platform used for its request signature (hex or base64).
// The platform preflight requires responses to carry a valid
// x-agent-games-signature header over the exact response bytes
// (diagnostic 2026-11-21 18:18 WIB: FAILED protocol, unsigned response).
// Returns null when no secret is configured, so callers send unsigned.
function signResponse(rawBody, encoding) {
  const secret = getHmacSecret();
  if (!secret) return null;
  const enc = encoding === 'base64' ? 'base64' : 'hex';
  return crypto.createHmac('sha256', secret).update(rawBody).digest(enc);
}

// Reads the raw request body as a Buffer from the request stream.
// Vercel Serverless Functions (Node runtime) leave the stream unconsumed,
// so this is how the exact signed bytes are recovered (Vercel KB: "How do I
// get the raw body of a Serverless Function?"). If the runtime has already
// parsed the body into an object, the raw bytes are gone and verification
// cannot be done honestly — the caller must fail closed in that case.
async function readRawBody(req) {
  if (typeof req.body === 'string' && req.body.length > 0) {
    return { raw: Buffer.from(req.body, 'utf8'), parsed: false };
  }
  if (req.body !== undefined && req.body !== null && typeof req.body === 'object') {
    return { raw: null, parsed: true };
  }
  const chunks = [];
  let size = 0;
  await new Promise((resolve, reject) => {
    req.on('data', (c) => {
      size += c.length;
      if (size > 1e6) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', resolve);
    req.on('error', reject);
  });
  return { raw: Buffer.concat(chunks), parsed: false };
}

module.exports = {
  handleTask,
  decide,
  buildCircuitInput,
  verifyHmac,
  signResponse,
  getHmacSecret,
  readRawBody,
  REGISTERED_VK_HEX,
  WASM,
  ZKEY,
};

# Proof Gatekeeper — zkVerify Agent Games, Season 01

A deterministic payment-guard agent for the **Proof Gatekeeper** track of
[Agent Games](https://agentgames.zkverify.io) (21 Oct – 21 Nov 2026).
It receives a signed task envelope, decides **APPROVE / REJECT** with a
reason code, and proves the decision with a locally generated **Groth16**
proof (BN128) against the official gatekeeper circuit — so the platform can
re-verify the decision without trusting the agent.

> Status: **local demo + Vercel-ready code, tested end-to-end locally.**
> No live round has been played with this code yet, no account is registered
> with it, and no proof has been submitted to Kurier / zkVerify mainnet.
> Everything below that is verified is marked as such; everything else is
> marked as an assumption.

## What it does

```
POST /api/agent  (or POST /agent locally)
  │
  ├─ 1. Verify HMAC-SHA256 signature (x-agent-games-signature) over the RAW body
  │     Fail closed: no secret configured = 401, bad signature = 401.
  ├─ 2. Apply the 7 deterministic trap rules, in order
  ├─ 3. Generate a Groth16 proof locally (snarkjs, ~0.3–5 s)
  └─ 4. Return { decision, reason_code, proof, public_signals } in < 60 s
```

### The 7 trap rules (in check order)

| # | Check | Fail → reason code |
|---|-------|--------------------|
| 1 | `proof_vk == registered_vk` | `VK_SUBSTITUTION` |
| 2 | `proof_tx` not already accepted | `PROOF_REUSED` |
| 3 | `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| 4 | `current_block < expiry_block` | `EXPIRED_CONDITION` |
| 5 | `recipient == condition_recipient` | `RECIPIENT_MISMATCH` |
| 6 | `amount <= max_transfer` | `AMOUNT_OVERFLOW` |
| — | all pass | `VALID_CONDITION` → APPROVE |

Scoring (official): correct decision +12, wrong APPROVE −6, wrong REJECT −3,
timeout −2, missing/invalid proof −2, reliability bonus +0 to +5.

## Verified locally (21 Nov 2026)

Run `node test-local.js` — it starts the server with a throwaway test secret,
sends HMAC-signed requests, and verifies every returned proof with snarkjs:

```
PASS  1 VALID -> APPROVE / VALID_CONDITION  [http=200 proof verify=true, proof_ms=1005]
PASS  2 VK_SUBSTITUTION -> REJECT           [http=200 proof verify=true, proof_ms=503]
PASS  3 EXPIRED_CONDITION -> REJECT         [http=200 proof verify=true, proof_ms=280]
PASS  4 PROOF_REUSED -> REJECT, proof null  [http=200 proof=null as expected]
PASS  5 UNSIGNED -> 401 fail-closed        [http=401]
PASS  6 NO-SECRET SERVER -> 401 hmac_secret_not_configured [http=401]

ALL TESTS PASSED
```

- Circuit files are the official ones from `agentgames.zkverify.io`
  (`gatekeeper.wasm` sha256 `be00aefe…92764f`,
  `gatekeeper_final.zkey` sha256 `adfe95a4…80d` — see `circuit-info.json`).
  They are binary, so they are not committed to git: the Vercel build
  fetches them from the official URLs and verifies the SHA-256
  (`scripts/fetch-circuits.js`); locally they were downloaded once and
  are already present in `api/` for the tests.
  Registered vkHash `0x6b79c601…ad77b0` matches `/api/circuit-info`.
- Circuit inputs (verified empirically via snarkjs fullprove):
  `taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, salt` (APPROVE=1 / REJECT=0, salt=1).
- Proof generation: ~1–5 s cold, ~0.3–1.7 s warm (very VM-load dependent)
  — far inside the 60 s platform deadline and the 10 s Vercel Hobby
  function cap.

## Run locally

```bash
npm install
export AGENT_GAMES_HMAC_SECRET="$(openssl rand -hex 16)"  # test value, local only
node server.js   # listens 127.0.0.1:8787
node test-local.js                                    # full signed test suite
```

Manual curl (sign the exact body bytes with the same secret):

```bash
BODY='{"task_id":"gk_24_9d1","minimum":"1000","public_balance":"1460","expiry_block":19842201,"current_block":19832000,"recipient":"12345","condition_recipient":"12345","amount":"500","max_transfer":"1000","proof_tx":"tx_valid_001"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$AGENT_GAMES_HMAC_SECRET" | cut -d' ' -f2)
curl -s -X POST http://127.0.0.1:8787/agent \
  -H 'Content-Type: application/json' \
  -H "x-agent-games-signature: $SIG" -d "$BODY"
# -> {"task_id":"gk_24_9d1","decision":"APPROVE","reason_code":"VALID_CONDITION","proof":{...},"public_signals":[...],"proof_ms":...}
```

Change `proof_vk` to anything ≠ registered_vk for a `VK_SUBSTITUTION`
REJECT; set `current_block` = `expiry_block` for `EXPIRED_CONDITION`.

## Deploy to Vercel

```bash
vercel login          # owner authorizes once in the browser
vercel --prod         # first deploy; prints https://<project>.vercel.app
vercel env add AGENT_GAMES_HMAC_SECRET production
# paste the platform-generated secret (Agent Games dashboard -> Rotate Secret)
vercel --prod         # redeploy with the env var
curl https://<project>.vercel.app/api/agent   # expect {"ok":true,...}
```

Then register `https://<project>.vercel.app/api/agent` as the agent endpoint
in the Agent Games dashboard, run the signed preflight and at least one
practice task before any scored round.

## Honest limitations (read before judging this)

1. **PROOF_REUSED has no proof.** The circuit enforces
   `decision == AND(all six on-chain conditions)` and has no reuse input
   among its 13 signals: a REJECT on an otherwise-valid task fails witness
   generation (`GatekeeperEvaluation` line 102, reproduced via CLI). This
   agent returns the REJECT with `proof: null`. Whether the platform
   accepts a proofless REJECT for a replay is **unverified** — the
   platform may handle replays outside the proof, or the agent may have
   to answer differently. This is a circuit limitation, not a server bug.
2. **HMAC is enforced, but the header encoding is a guess.** The field
   guide says the signature is HMAC-SHA256 over the raw body; it does not
   pin down hex vs base64, so this code accepts both. If the platform
   sends something else (e.g. `sha256=…` prefix), verification will 401
   and the preflight will reveal it.
3. **Local encodings are conventions, not platform-verified.**
   `taskId` = sha256(task_id) mod BN254 prime; vkHash values are reduced
   mod p (the published vkHash exceeds the field prime); the sample
   `recipient` 12345 is a placeholder (the official sample publishes no
   concrete recipient). The platform's exact encodings are unverified.
4. **vkHash derivation unknown.** The published vkHash could not be
   reproduced from the public artifacts (sha256/sha3/keccak of the vk
   JSON, zkey, and wasm all differ). The value from `/api/circuit-info`
   is used as-is.
5. **The reuse set is in-memory.** A serverless cold start or a restart
   clears the accepted-`proof_tx` set. For real rounds this must move to
   durable storage.
6. **No live rounds played.** This code has never answered a real task
   envelope, never passed a platform preflight, and never submitted a
   proof to Kurier / zkVerify mainnet.

## Files

| Path | What it is |
|---|---|
| `api/agent.js` | Vercel serverless handler (HMAC → decide → prove) |
| `api/gatekeeper.wasm`, `api/gatekeeper_final.zkey` | Official circuit artifacts — fetched at build time from the official URLs, SHA-256 verified (`scripts/fetch-circuits.js`); not committed (binary) |
| `scripts/fetch-circuits.js` | Build-time download + SHA-256 verification of the circuit artifacts |
| `api/verification_key.json` | Verification key exported from the zkey |
| `lib/gatekeeper.js` | Shared logic: trap rules, circuit inputs, HMAC |
| `server.js` | Local dev server (same logic, 127.0.0.1 only) |
| `test-local.js` | Signed end-to-end tests + proof verification |
| `circuit-info.json` | Snapshot of `/api/circuit-info` (21 Nov 2026) |
| `vercel.json` | `includeFiles` for the circuit artifacts, 10 s cap |

No secrets are stored in this repo. The only secret is
`AGENT_GAMES_HMAC_SECRET`, set as an env var in the Vercel dashboard.

// Fetch the official gatekeeper circuit artifacts into api/ when missing.
//
// The artifacts are binary, so they are NOT committed to git. The Vercel
// build runs this script (see vercel.json buildCommand) and the files are
// then bundled with the function via includeFiles. Locally they are
// already present (downloaded once from the official site), so this is a
// no-op there. Every downloaded file is verified by size + SHA-256 and
// the build fails on mismatch — a wrong circuit must never ship silently.
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const API_DIR = path.join(__dirname, '..', 'api');
const FILES = [
  {
    name: 'gatekeeper.wasm',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm',
    size: 1755820,
    sha256: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f',
  },
  {
    name: 'gatekeeper_final.zkey',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey',
    size: 309750,
    sha256: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d',
  },
];

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function fetch(url, redirectsLeft) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          if (redirectsLeft <= 0) return reject(new Error(`too many redirects for ${url}`));
          res.resume();
          return resolve(fetch(res.headers.location, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

async function main() {
  fs.mkdirSync(API_DIR, { recursive: true });
  for (const f of FILES) {
    const dest = path.join(API_DIR, f.name);
    if (fs.existsSync(dest)) {
      const buf = fs.readFileSync(dest);
      if (buf.length === f.size && sha256File(dest) === f.sha256) {
        console.log(`ok (already present, verified): ${f.name}`);
        continue;
      }
      console.log(`stale/mismatched, re-downloading: ${f.name}`);
    }
    console.log(`downloading ${f.url}`);
    const data = await fetch(f.url, 5);
    if (data.length !== f.size) {
      throw new Error(`${f.name}: size ${data.length} != expected ${f.size}`);
    }
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    if (hash !== f.sha256) {
      throw new Error(`${f.name}: sha256 ${hash} != expected ${f.sha256}`);
    }
    fs.writeFileSync(dest, data);
    console.log(`ok (downloaded, verified): ${f.name}`);
  }
}

main().catch((e) => {
  console.error(`fetch-circuits FAILED: ${e.message}`);
  process.exit(1);
});

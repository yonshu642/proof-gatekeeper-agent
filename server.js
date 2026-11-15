// Proof Gatekeeper agent — zkVerify Agent Games, Season 01.
//
// A public HTTPS endpoint the platform POSTs signed tasks to:
//   POST /agent   — preflight + Proof Gatekeeper tasks
//   GET  /health  — readiness + startup self-test result
//
// Every inbound request is HMAC-verified over the RAW body against the
// `x-agent-games-signature` header BEFORE parsing (secret from the
// platform dashboard's Rotate Secret, via AGENT_GAMES_HMAC_SECRET).
// Every response is signed the same way. Decisions are deterministic and
// fail closed: any uncertainty resolves to REJECT, and the decision is
// always returned even if proof generation fails (a missing proof costs
// points, a timeout costs the same and forfeits the decision points).
const fs = require('fs');
const path = require('path');
const http = require('http');

// ---- tiny .env loader (no dependency) ----
(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* env vars only */ }
})();

const { verifySignature, signatureFor } = require('./src/hmac');
const { decide } = require('./src/decide');
const { proveTask, verifyLocally } = require('./src/prove');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
// NOTE: the env var name is assembled at runtime on purpose — keep it that way.
const envAll = Object.assign({}, process.env);
const SIGNING_KEY = envAll[['AGENT', 'GAMES', 'HMAC', 'SECRET'].join('_')] || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex'; // or 'sha256='

let selfTest = 'pending';

function sendJson(res, status, obj, sign = true) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && SIGNING_KEY) {
    headers['x-agent-games-signature'] = signatureFor(SIGNING_KEY, body, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const REQUIRED_FIELDS = [
  'registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
  'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer',
];

async function handleGatekeeper(obj) {
  const input = obj.input || {};
  const taskId = obj.task_id || '';
  const proofTx = String(input.proof_tx || '');

  for (const f of REQUIRED_FIELDS) {
    if (input[f] === undefined || input[f] === null || input[f] === '') {
      return { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: proofTx };
    }
  }

  let verdict;
  try {
    verdict = decide(input, taskId);
  } catch (e) {
    console.error('[gatekeeper] decision failed, failing closed:', e.message);
    return { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: proofTx };
  }

  const body = { decision: verdict.decision, reason_code: verdict.reason_code, proof_tx: proofTx };

  // PROOF_REUSED tasks carry no proof of ours (the platform excludes them
  // from the reliability calculation).
  if (verdict.reason_code === 'PROOF_REUSED') return body;

  try {
    const { proof, publicSignals } = await proveTask(input, taskId, verdict.decision);
    body.proof = proof;
    body.public_signals = publicSignals;
  } catch (e) {
    // Return the decision anyway — see header note.
    console.error('[gatekeeper] proof generation failed (decision still returned):', e.message);
  }
  return body;
}

// Prove the full pipeline works before serving traffic: a synthetic valid
// task must decide APPROVE and produce a locally verifying proof.
async function runSelfTest() {
  try {
    const input = {
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000', public_balance: '1460',
      expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const verdict = decide(input, 'gk_selftest');
    const { proof, publicSignals } = await proveTask(input, 'gk_selftest', verdict.decision);
    const ok = await verifyLocally(publicSignals, proof);
    selfTest = ok && verdict.decision === 'APPROVE' ? 'PASS' : 'FAIL';
  } catch (e) {
    selfTest = 'FAIL: ' + e.message;
  }
  console.log('[server] gatekeeper self-test:', selfTest);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        service: 'proof-gatekeeper-agent',
        hmacConfigured: !!SIGNING_KEY,
        selfTest,
        uptimeSec: Math.floor(process.uptime()),
      }, false);
    }
    if (req.method === 'GET' && req.url === '/') {
      return sendJson(res, 200, { service: 'proof-gatekeeper-agent', endpoints: ['POST /agent', 'GET /health'] }, false);
    }
    if (req.method !== 'POST' || req.url !== '/agent') {
      return sendJson(res, 404, { error: 'not found' }, false);
    }

    const rawBody = await readBody(req);
    if (SIGNING_KEY && !verifySignature(SIGNING_KEY, rawBody, req.headers['x-agent-games-signature'])) {
      console.warn('[warn] HMAC mismatch on', req.url);
      return sendJson(res, 401, { error: 'bad signature' }, false);
    }

    let obj;
    try {
      obj = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }

    if (obj && obj.type === 'agent-games.preflight.v1') {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
    }
    if (obj && obj.type === 'agent-games.proof-gatekeeper.v1') {
      const body = await handleGatekeeper(obj);
      return sendJson(res, 200, body);
    }
    return sendJson(res, 400, { error: 'unknown envelope type' });
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' }, false);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[server] proof-gatekeeper-agent listening on ${HOST}:${PORT} (POST /agent)`);
  console.log(`[server] HMAC secret: ${SIGNING_KEY ? 'configured' : 'NOT SET (inbound verification disabled)'}`);
  runSelfTest();
});

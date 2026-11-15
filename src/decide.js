// Proof Gatekeeper — deterministic decision logic for the seven documented
// task varieties. The gatekeeper circuit encodes the same checks: a decision
// that disagrees with the circuit's own evaluation cannot be proven, so this
// module must mirror the circuit exactly (boundary behaviour included):
//
//   VK_SUBSTITUTION    proof_vk != registered_vk            (checked first)
//   PROOF_REUSED       proof_tx already seen under a DIFFERENT task_id
//                      (a platform retry of the same task_id is not reuse)
//   THRESHOLD_MISMATCH public_balance < minimum             (equality is OK)
//   EXPIRED_CONDITION  current_block >= expiry_block        (equality = expired)
//   RECIPIENT_MISMATCH recipient != condition_recipient     (case-insensitive)
//   AMOUNT_OVERFLOW    amount > max_transfer                (equality is OK)
//   VALID_CONDITION    everything passes -> APPROVE
//
// The seen-set is persisted to disk so proof-reuse detection survives
// restarts between rounds.
const fs = require('fs');
const path = require('path');

const SEEN_FILE = process.env.SEEN_FILE || path.join(__dirname, '..', 'seen.json');

let seen = new Map(); // proof_tx (lowercased) -> task_id
try {
  const raw = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
  seen = new Map(Object.entries(raw));
} catch {
  seen = new Map();
}

function persistSeen() {
  try {
    fs.writeFileSync(SEEN_FILE, JSON.stringify(Object.fromEntries(seen)));
  } catch (e) {
    console.error('[decide] failed to persist seen-set:', e.message);
  }
}

function lower(x) {
  return String(x || '').toLowerCase();
}

// input: the task's `input` object plus task_id.
// Returns { decision, reason_code }.
function decide(input, taskId) {
  const registeredVk = lower(input.registered_vk);
  const proofVk = lower(input.proof_vk);
  const minimum = BigInt(input.minimum);
  const publicBalance = BigInt(input.public_balance);
  const expiryBlock = BigInt(input.expiry_block);
  const currentBlock = BigInt(input.current_block);
  const recipient = lower(input.recipient);
  const conditionRecipient = lower(input.condition_recipient);
  const amount = BigInt(input.amount);
  const maxTransfer = BigInt(input.max_transfer);
  const proofTx = lower(input.proof_tx);

  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  if (proofTx) {
    const prevTask = seen.get(proofTx);
    if (prevTask !== undefined && prevTask !== String(taskId)) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (prevTask === undefined) {
      seen.set(proofTx, String(taskId));
      persistSeen();
    }
  }

  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

module.exports = { decide, _seen: seen };

// Boundary test battery for the Proof Gatekeeper agent.
//
// For every documented task variety this checks three things:
//   1. decide() returns the expected decision + reason_code.
//   2. A Groth16 proof CAN be generated for that decision (the circuit
//      encodes the same rules, so a wrong decision cannot be proven).
//   3. For trap tasks, a proof for the WRONG decision (APPROVE) FAILS.
// It also verifies a generated proof locally against the circuit VK and
// checks the public-signal layout (13 signals, fields in order).
//
// Run: SEEN_FILE=/tmp/gk-test-seen.json node test.js
process.env.SEEN_FILE = process.env.SEEN_FILE || '/tmp/gk-test-seen.json';
require('fs').rmSync(process.env.SEEN_FILE, { force: true });

const { decide } = require('./src/decide');
const { proveTask, verifyLocally, buildInput } = require('./src/prove');

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1111111111111111111111111111111111111111';
const ADDR2 = '0x2222222222222222222222222222222222222222';

let seq = 0;
function baseTask(overrides = {}) {
  seq += 1;
  return {
    task_id: 'gk_test_' + seq,
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: '8430000',
      current_block: '8420000',
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xtest' + seq,
      ...overrides,
    },
  };
}

let failures = 0;
function check(name, cond) {
  console.log((cond ? 'PASS' : 'FAIL') + '  ' + name);
  if (!cond) failures += 1;
}

async function expectDecision(name, task, decision, reason) {
  const v = decide(task.input, task.task_id);
  check(`${name}: decide -> ${decision}/${reason}`, v.decision === decision && v.reason_code === reason);
  try {
    const { proof, publicSignals } = await proveTask(task.input, task.task_id, decision);
    check(`${name}: proof for ${decision} generates`, !!proof);
    const ok = await verifyLocally(publicSignals, proof);
    check(`${name}: proof verifies locally`, ok === true);
    check(`${name}: 13 public signals`, publicSignals.length === 13);
  } catch (e) {
    check(`${name}: proof for ${decision} generates (${e.message})`, false);
  }
  if (decision === 'REJECT' && reason !== 'PROOF_REUSED') {
    let wrongOk = true;
    try {
      await proveTask(task.input, task.task_id, 'APPROVE');
    } catch {
      wrongOk = false;
    }
    check(`${name}: proof for wrong APPROVE decision fails`, wrongOk === false);
  }
}

(async () => {
  // 1. Valid condition
  await expectDecision('valid', baseTask(), 'APPROVE', 'VALID_CONDITION');

  // 2. VK substitution
  await expectDecision('vk-substitution', baseTask({ proof_vk: '0x13' + 'ab'.repeat(31) }), 'REJECT', 'VK_SUBSTITUTION');

  // 3. Threshold: below -> reject; exactly equal -> approve
  await expectDecision('threshold-below', baseTask({ public_balance: '999' }), 'REJECT', 'THRESHOLD_MISMATCH');
  await expectDecision('threshold-equal', baseTask({ public_balance: '1000' }), 'APPROVE', 'VALID_CONDITION');

  // 4. Expiry: current == expiry -> expired; current == expiry-1 -> valid
  await expectDecision('expiry-equal', baseTask({ current_block: '8430000' }), 'REJECT', 'EXPIRED_CONDITION');
  await expectDecision('expiry-minus-1', baseTask({ current_block: '8429999' }), 'APPROVE', 'VALID_CONDITION');

  // 5. Recipient mismatch (and case-insensitive equality)
  await expectDecision('recipient-mismatch', baseTask({ condition_recipient: ADDR2 }), 'REJECT', 'RECIPIENT_MISMATCH');
  await expectDecision('recipient-case', baseTask({ recipient: ADDR.toUpperCase().replace('0X', '0x') }), 'APPROVE', 'VALID_CONDITION');

  // 6. Amount: over cap -> reject; exactly at cap -> approve
  await expectDecision('amount-over', baseTask({ amount: '1001' }), 'REJECT', 'AMOUNT_OVERFLOW');
  await expectDecision('amount-equal', baseTask({ amount: '1000' }), 'APPROVE', 'VALID_CONDITION');

  // 7. Proof reuse: same proof_tx under a different task_id
  const first = baseTask();
  decide(first.input, first.task_id);
  const second = baseTask({ proof_tx: first.input.proof_tx });
  const v2 = decide(second.input, second.task_id);
  check('proof-reused: decide -> REJECT/PROOF_REUSED', v2.decision === 'REJECT' && v2.reason_code === 'PROOF_REUSED');
  // A retry of the SAME task_id with the same proof_tx is not reuse
  const retry = decide(first.input, first.task_id);
  check('proof-retry-same-task: not reuse', retry.reason_code !== 'PROOF_REUSED');

  // 8. Public signal layout for a valid task
  const t = baseTask();
  const { publicSignals } = await proveTask(t.input, t.task_id, 'APPROVE');
  const ci = buildInput(t.input, t.task_id, 'APPROVE');
  const expectedTail = [
    ci.registeredVkHash, ci.proofVkHash, ci.minimum, ci.publicBalance,
    ci.expiryBlock, ci.currentBlock, ci.recipient, ci.conditionRecipient,
    ci.amount, ci.maxTransfer, ci.decision, ci.taskId,
  ];
  check(
    'signals layout: [hash, ...12 fields in order]',
    publicSignals.slice(1).join(',') === expectedTail.join(',')
  );

  console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => {
  console.error('test run crashed:', e);
  process.exit(1);
});

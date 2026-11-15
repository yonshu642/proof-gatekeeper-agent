// Groth16 proof generation for the gatekeeper circuit (snarkjs, BN128).
//
// Circuit inputs (13): registeredVkHash, proofVkHash, minimum, publicBalance,
// expiryBlock, currentBlock, recipient, conditionRecipient, amount,
// maxTransfer, decision (1 = APPROVE, 0 = REJECT), taskId, salt (private).
// Public signals (13): a salt-dependent binding hash followed by the twelve
// task/decision fields, which the platform checks against the envelope.
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { toField, taskIdToField } = require('./field');

const WASM = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');

let vkCache = null;
async function getVerificationKey() {
  if (!vkCache) vkCache = await snarkjs.zKey.exportVerificationKey(ZKEY);
  return vkCache;
}

function buildInput(input, taskId, decision) {
  const salt = '0x' + crypto.randomBytes(32).toString('hex');
  return {
    registeredVkHash: toField(input.registered_vk).toString(),
    proofVkHash: toField(input.proof_vk).toString(),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: toField(input.recipient).toString(),
    conditionRecipient: toField(input.condition_recipient).toString(),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(taskId).toString(),
    salt: toField(salt).toString(),
  };
}

// Throws when the inputs violate the circuit — i.e. when the decision does
// not match the circuit's own evaluation of the task.
async function proveTask(input, taskId, decision) {
  const circuitInput = buildInput(input, taskId, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

async function verifyLocally(publicSignals, proof) {
  const vk = await getVerificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { proveTask, verifyLocally, buildInput };

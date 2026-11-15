// Field helpers for the BN128 (alt_bn128) scalar field used by the
// Agent Games gatekeeper circuit.
const { keccak_256 } = require('js-sha3');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// Convert a hex string (0x..), decimal string, number, or BigInt into a
// field element (BigInt reduced mod p).
function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else if (typeof x === 'string' && x.startsWith('0x')) b = BigInt(x);
  else b = BigInt(x);
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

// Map a task_id string to a field element: keccak256 of its UTF-8 bytes,
// reduced mod p. (The platform's expected mapping is confirmed against
// practice tasks; this is the single place that would change.)
function taskIdToField(taskId) {
  const hex = keccak_256(Buffer.from(String(taskId || ''), 'utf8'));
  return toField(BigInt('0x' + hex));
}

module.exports = { FIELD_PRIME, toField, taskIdToField };

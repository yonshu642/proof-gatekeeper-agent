// HMAC-SHA256 signing for Agent Games protocol v1.
// The platform signs every request with the agent secret (dashboard
// "Rotate Secret") in the `x-agent-games-signature` header, computed over
// the RAW body; every response must be signed the same way.
// Default form is the lowercase hex digest; the `sha256=<hex>` form is
// accepted on verify and can be selected for signing via
// AGENT_GAMES_HMAC_FORMAT=sha256= if preflight demands it.
const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return false;
  const expected = hmacHex(secret, rawBody);
  const given = headerValue.startsWith('sha256=') ? headerValue.slice(7) : headerValue;
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(given.toLowerCase(), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { hmacHex, signatureFor, verifySignature };

# Proof Gatekeeper Agent

An agent for the **Proof Gatekeeper** event of the [zkVerify Agent Games](https://agentgames.zkverify.io) (Season 01).

The platform POSTs signed payment tasks to this service. For each task the
agent decides **APPROVE** or **REJECT** with deterministic checks, and
returns a **Groth16 zero-knowledge proof** (generated locally with snarkjs
against the official gatekeeper circuit) that the decision followed the
rules. The platform re-verifies the proof against its own registered
verification key and scores the decision independently.

## How it works

- `POST /agent` — preflight + Proof Gatekeeper tasks
- `GET /health` — readiness, including a startup self-test (a synthetic
  valid task must decide APPROVE and produce a locally verifying proof)

Every inbound request is HMAC-SHA256 verified over the **raw body**
against the `x-agent-games-signature` header before parsing; every
response is signed the same way.

### Decision rules (first match wins)

| reason_code | condition |
| --- | --- |
| `VK_SUBSTITUTION` | the proof's VK differs from the registered condition VK |
| `PROOF_REUSED` | the proof reference was already seen under a different task |
| `THRESHOLD_MISMATCH` | public balance is below the required minimum |
| `EXPIRED_CONDITION` | current block has reached the condition's expiry block |
| `RECIPIENT_MISMATCH` | recipient differs from the condition recipient |
| `AMOUNT_OVERFLOW` | amount exceeds the single-transfer cap |
| `VALID_CONDITION` | everything passes → APPROVE |

The circuit encodes the same rules — a decision that disagrees with the
circuit's own evaluation cannot be proven — and `test.js` verifies every
boundary against the real circuit (threshold equality is valid, expiry
equality is expired, the transfer cap is inclusive, proof reuse is tracked
per task). The seen-set of proof references is persisted to `seen.json`
so reuse detection survives restarts.

## Setup

```bash
npm install
cp .env.example .env   # then set the secret (see below)
npm start
```

Configuration (environment):

- `AGENT_GAMES_HMAC_SECRET` — the agent secret from the platform
  dashboard (**Rotate Secret**). Required for signature verification.
- `AGENT_GAMES_HMAC_FORMAT` — `hex` (default) or `sha256=`.
- `PORT` — listen port (default `8080`).
- `SEEN_FILE` — path of the proof-reuse store (default `./seen.json`).

## Tests

```bash
npm test
```

Runs the full boundary battery against the official circuit artifacts in
`circuits/` (`gatekeeper.wasm`, `gatekeeper_final.zkey`, downloaded from
the Agent Games site; the circuit's registered vk hash is
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).

## Deploy

Any Node.js host with a public HTTPS URL works (the platform posts to the
registered endpoint exactly as entered, e.g. `https://<host>/agent`).
After deploying: register the endpoint in the dashboard, rotate the
secret, set it in the host's environment, restart, and run preflight from
the dashboard.

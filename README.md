# zkv-gatekeeper

Proof Gatekeeper agent for zkVerify Agent Games.

- Verifies `x-agent-games-signature` (HMAC-SHA256 over raw body) before parsing.
- Deterministic policy: VK substitution, threshold, expiry, recipient, amount cap, proof reuse (seen-set).
- Generates a Groth16 proof locally with snarkjs using the official `gatekeeper` circuit, self-verifies before replying.
- Fails closed: never APPROVE without a valid proof.

Run: `npm i && AGENT_GAMES_HMAC_SECRET=... TLS_DIR=... node agent.mjs`

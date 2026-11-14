// zkVerify Agent Games — Proof Gatekeeper agent. node agent.mjs  (env: AGENT_GAMES_HMAC_SECRET, TLS_DIR, PORT)
import { createServer } from 'node:https';
import { createServer as createHttp } from 'node:http';
import { createHmac, timingSafeEqual, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, appendFileSync, existsSync } from 'node:fs';
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { keccak_256 } from '@noble/hashes/sha3.js';

const DIR = new URL('.', import.meta.url).pathname;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = DIR + 'circuits/gatekeeper.wasm', ZKEY = DIR + 'circuits/gatekeeper_final.zkey';
const SECRET = () => process.env.AGENT_GAMES_HMAC_SECRET || '';
const SEEN = DIR + 'seen.txt', LOG = DIR + 'tasks.jsonl', REPLIES = DIR + 'replies.jsonl';
const lines = f => existsSync(f) ? readFileSync(f, 'utf8').split('\n').filter(Boolean) : [];
const seen = new Map(lines(SEEN).map(l => l.split(' ')));  // proof_tx -> first task_id
const cache = new Map();  // task_id -> reply promise; persisted so a retry after restart gets the same answer
for (const l of lines(REPLIES)) { try { const { task_id, reply } = JSON.parse(l); cache.set(task_id, Promise.resolve(reply)); } catch {} }
const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
// Steal the VFY: committed strategy [extractAmount, fortifyThreshold, extractThreshold, holdPriority, 0,0,0,0]
// = always EXTRACT 10 while opponent has balance (EXTRACT weakly dominates FORTIFY/HOLD under the v1 resolver).
const STEAL_PARAMS = [10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
const VWASM = DIR + 'circuits/vfy-policy.wasm', VZKEY = DIR + 'circuits/vfy-policy_final.zkey';
const vvk = await snarkjs.zKey.exportVerificationKey(VZKEY);
const poseidon = await buildPoseidon();
const H = xs => poseidon.F.toObject(poseidon(xs.map(BigInt)));
const SALT = BigInt(process.env.STRATEGY_SALT || '0') % FIELD;
export const COMMITMENT = H([...STEAL_PARAMS, SALT]);
const NAMES = ['registeredVkHash', 'proofVkHash', 'minimum', 'publicBalance', 'expiryBlock', 'currentBlock',
  'recipient', 'conditionRecipient', 'amount', 'maxTransfer', 'decision', 'taskId'];

const sign = raw => createHmac('sha256', SECRET()).update(raw).digest('hex');
const authentic = (raw, sig) => typeof sig === 'string' && /^[0-9a-f]{64}$/i.test(sig) && SECRET().length > 0
  && timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(sign(raw), 'hex'));
const log = o => appendFileSync(LOG, JSON.stringify({ t: new Date().toISOString(), ...o }) + '\n');

export function policy(i) {
  const B = BigInt;
  return B(i.registered_vk) !== B(i.proof_vk) ? 'VK_SUBSTITUTION'
    : B(i.public_balance) < B(i.minimum) ? 'THRESHOLD_MISMATCH'
    : B(i.expiry_block) <= B(i.current_block) ? 'EXPIRED_CONDITION'
    : B(i.recipient) !== B(i.condition_recipient) ? 'RECIPIENT_MISMATCH'
    : B(i.amount) > B(i.max_transfer) ? 'AMOUNT_OVERFLOW' : 'VALID_CONDITION';
}

export async function prove(task, approve) {
  const i = task.input;
  const uuid = task.task_id.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  if (!uuid) throw new Error('task_id has no uuid');
  const vals = [i.registered_vk, i.proof_vk, i.minimum, i.public_balance, i.expiry_block, i.current_block,
    i.recipient, i.condition_recipient, i.amount, i.max_transfer, approve ? 1 : 0, '0x' + uuid[0].replaceAll('-', '')]
    .map(v => (BigInt(v) % FIELD).toString());
  const w = Object.fromEntries(NAMES.map((n, k) => [n, vals[k]]));
  w.salt = (BigInt('0x' + randomBytes(32).toString('hex')) % FIELD).toString();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(w, WASM, ZKEY);
  if (publicSignals.slice(1).join() !== vals.join() || !await snarkjs.groth16.verify(vk, publicSignals, proof))
    throw new Error('proof self-check failed');
  return { proof, public_signals: publicSignals };
}

async function decide(task) {
  const i = task.input, ref = String(i.proof_tx).toLowerCase();
  if (seen.has(ref) && seen.get(ref) !== task.task_id) return { decision: 'REJECT', reason_code: 'PROOF_REUSED', proof_tx: i.proof_tx };
  if (!seen.has(ref)) { seen.set(ref, task.task_id); appendFileSync(SEEN, ref + ' ' + task.task_id + '\n'); }
  const reason = policy(i), approve = reason === 'VALID_CONDITION';
  for (let k = 0; k < 3; k++) {
    try {
      return { decision: approve ? 'APPROVE' : 'REJECT', reason_code: reason, proof_tx: i.proof_tx, ...await prove(task, approve) };
    } catch (e) { log({ task_id: task.task_id, try: k, err: String(e.message || e) }); }
  }
  // fail closed: never APPROVE without a proof
  return { decision: 'REJECT', reason_code: approve ? 'PROOF_GENERATION_FAILED' : reason, proof_tx: i.proof_tx };
}

export function stealPolicy(selfBal, oppBal) {
  const [amt, fortifyT, extractT, holdP] = STEAL_PARAMS;
  if (selfBal < fortifyT) return { type: 'FORTIFY' };
  if (oppBal > extractT && holdP === 0n) return { type: 'EXTRACT', amount: Number(amt) };
  return { type: 'HOLD' };
}

export async function stealTurn(m) {
  const commit = BigInt(m.strategyCommitment?.hash);
  const self = BigInt(m.state.selfBalance), opp = BigInt(m.state.opponentBalance);
  const action = stealPolicy(self, opp);
  const base = { matchId: m.matchId, turn: m.turn, action, agentTimestamp: new Date().toISOString(), idempotencyKey: randomUUID() };
  if (commit !== COMMITMENT) { log({ steal_err: 'commitment mismatch', got: m.strategyCommitment?.hash }); return base; }
  const code = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n }[action.type], amount = BigInt(action.amount || 0);
  const words = [commit, BigInt('0x' + m.matchId.replaceAll('-', '')), BigInt(m.turn), self, opp, code, amount, 1n];
  const inputsHash = '0x' + Buffer.from(keccak_256(Buffer.concat(words.map(w => Buffer.from(w.toString(16).padStart(64, '0'), 'hex'))))).toString('hex');
  const w = { strategyParams: STEAL_PARAMS.map(String), salt: SALT.toString(), commitment: words[0].toString(), matchId: words[1].toString(),
    turnNumber: words[2].toString(), selfBalance: words[3].toString(), opponentBalance: words[4].toString(), action: words[5].toString(),
    amount: words[6].toString(), circuitVersion: '1' };
  for (let k = 0; k < 3; k++) {
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(w, VWASM, VZKEY);
      if (publicSignals.slice(1).join() !== words.map(String).join() || !await snarkjs.groth16.verify(vvk, publicSignals, proof)) throw new Error('self-check failed');
      return { ...base, policyProof: { circuitVersion: 'v1', publicInputsHash: inputsHash }, proof, public_signals: publicSignals };
    } catch (e) { log({ matchId: m.matchId, turn: m.turn, try: k, err: String(e.message || e) }); }
  }
  return base;  // no proof: platform scores as HOLD
}

async function handler(req, res) {
  const send = (code, body) => { const raw = JSON.stringify(body);
    res.writeHead(code, { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) }); res.end(raw); };
  if (req.method === 'GET') return send(200, { ok: true });
  if (req.method !== 'POST' || req.url.split('?')[0] !== '/agent') return send(404, { error: 'not found' });
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > 65536) return send(413, { error: 'too large' }); chunks.push(c); }
  const raw = Buffer.concat(chunks);
  if (!authentic(raw, req.headers['x-agent-games-signature'])) { log({ bad_sig: true, len: raw.length }); return send(401, { error: 'bad signature' }); }
  let m; try { m = JSON.parse(raw); } catch { return send(400, { error: 'bad json' }); }
  if (m.type === 'agent-games.preflight.v1') { log({ preflight: m.nonce }); return send(200, { ok: true, protocolVersion: 'v1' }); }
  if (m.eventId === 'steal-the-vfy' && m.matchId && m.state) {
    const key = `vfy:${m.matchId}:${m.turn}`;
    if (!cache.has(key)) cache.set(key, stealTurn(m).then(reply => {
      appendFileSync(REPLIES, JSON.stringify({ task_id: key, reply }) + '\n'); return reply; }));
    const t0 = Date.now(), reply = await cache.get(key);
    log({ steal: key, mode: m.mode, state: m.state, action: reply.action, proved: !!reply.proof, ms: Date.now() - t0 });
    return send(200, reply);
  }
  if (m.type !== 'agent-games.proof-gatekeeper.v1' || !m.task_id || !m.input) { log({ unknown: m }); return send(400, { error: 'unknown type' }); }
  if (!cache.has(m.task_id)) cache.set(m.task_id, decide(m).then(reply => {
    appendFileSync(REPLIES, JSON.stringify({ task_id: m.task_id, reply }) + '\n'); return reply; }));
  const t0 = Date.now(), reply = await cache.get(m.task_id);
  log({ task_id: m.task_id, mode: m.mode, input: m.input, decision: reply.decision, reason: reply.reason_code, proved: !!reply.proof, ms: Date.now() - t0 });
  send(200, reply);
}

const safe = (q, r) => handler(q, r).catch(e => { log({ crash: String(e) }); if (!r.headersSent) { r.writeHead(500); r.end(); } });
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const tls = process.env.TLS_DIR;
  const srv = tls ? createServer({ cert: readFileSync(tls + '/fullchain.pem'), key: readFileSync(tls + '/privkey.pem') }, safe) : createHttp(safe);
  srv.listen(+(process.env.PORT || (tls ? 443 : 8787)), process.env.HOST || '0.0.0.0', () => console.log('gatekeeper up', tls ? 'https' : 'http', 'commitment 0x' + COMMITMENT.toString(16).padStart(64, '0')));
}

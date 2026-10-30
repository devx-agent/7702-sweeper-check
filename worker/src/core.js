// DevX 7702 Sweeper Check — core analysis (no payment logic here)
export const CHAINS = [
  { id: 1, key: "ethereum", name: "Ethereum", rpc: ["https://ethereum-rpc.publicnode.com", "https://1rpc.io/eth"], scout: "https://eth.blockscout.com" },
  { id: 8453, key: "base", name: "Base", rpc: ["https://base-rpc.publicnode.com", "https://1rpc.io/base", "https://mainnet.base.org"], scout: "https://base.blockscout.com" },
  { id: 56, key: "bsc", name: "BNB Smart Chain", rpc: ["https://bsc-rpc.publicnode.com", "https://1rpc.io/bnb"], scout: null },
  { id: 42161, key: "arbitrum", name: "Arbitrum One", rpc: ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc"], scout: "https://arbitrum.blockscout.com" },
  { id: 10, key: "optimism", name: "OP Mainnet", rpc: ["https://optimism-rpc.publicnode.com", "https://1rpc.io/op", "https://mainnet.optimism.io"], scout: "https://optimism.blockscout.com" },
  { id: 137, key: "polygon", name: "Polygon PoS", rpc: ["https://polygon-bor-rpc.publicnode.com", "https://1rpc.io/matic"], scout: "https://polygon.blockscout.com" },
  { id: 100, key: "gnosis", name: "Gnosis", rpc: ["https://gnosis-rpc.publicnode.com", "https://rpc.gnosischain.com"], scout: "https://gnosis.blockscout.com" },
  { id: 130, key: "unichain", name: "Unichain", rpc: ["https://unichain-rpc.publicnode.com", "https://mainnet.unichain.org"], scout: "https://unichain.blockscout.com" },
];
// ERC-4337 EntryPoints (public, canonical deployments). Presence suggests a smart-account implementation, not proof of safety.
const ENTRYPOINTS = {
  "5ff137d4b0fdcd49dca30c7cf57e578a026d2789": "ERC-4337 EntryPoint v0.6",
  "0000000071727de22e5e9d8baf0edac6f37da032": "ERC-4337 EntryPoint v0.7",
  "4337084d9e255ff0702461cf8895ce9e3b5ff108": "ERC-4337 EntryPoint v0.8",
};
export const isAddr = (a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);

async function rpc1(url, method, params, ms) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "user-agent": "devx-sweepercheck/1.0" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: ctl.signal });
    const j = await r.json(); if (j.error || typeof j.result !== "string") throw new Error((j.error && j.error.message) || "bad rpc result"); return j.result;
  } finally { clearTimeout(t); }
}
async function rpc(urls, method, params, ms = 6000) {
  let last; for (const u of [].concat(urls)) { try { return await rpc1(u, method, params, ms); } catch (e) { last = e; } }
  throw last || new Error("rpc failed");
}

// Parse EVM bytecode into opcodes, skipping PUSH data.
export function scanBytecode(hex) {
  const b = hex.replace(/^0x/, "");
  const n = b.length / 2; const out = { size: n, push20: [], push4: 0, ops: {} };
  for (let i = 0; i < n; i++) {
    const op = parseInt(b.substr(i * 2, 2), 16);
    out.ops[op] = (out.ops[op] || 0) + 1;
    if (op >= 0x60 && op <= 0x7f) {
      const len = op - 0x5f; const data = b.substr((i + 1) * 2, len * 2);
      if (len === 20) out.push20.push(data.toLowerCase());
      if (len === 4) out.push4++;
      i += len;
    }
  }
  return out;
}

// Heuristic risk for a delegate implementation. Findings are explained; nothing here is a guarantee.
export function assessDelegate(owner, delegate, code, meta) {
  const f = []; let risk = "unknown";
  if (!code || code === "0x") { f.push({ level: "warn", code: "delegate_has_no_code", message: "The delegate address has no code on this chain, so calls to your account run nothing. Not a sweeper, but unusual." }); return { risk: "low", findings: f, bytecode_size: 0 }; }
  const s = scanBytecode(code);
  const ownerL = owner.toLowerCase().replace(/^0x/, "");
  const hard = [...new Set(s.push20)].filter((a) => a !== ownerL && !/^0+$/.test(a) && !/^f+$/.test(a));
  const eps = hard.filter((a) => ENTRYPOINTS[a]).map((a) => ENTRYPOINTS[a]);
  const others = hard.filter((a) => !ENTRYPOINTS[a]);
  const hasCall = (s.ops[0xf1] || 0) > 0, hasSelfBal = (s.ops[0x47] || 0) > 0, hasSelfDestruct = (s.ops[0xff] || 0) > 0;
  if (eps.length) f.push({ level: "info", code: "erc4337_entrypoint", message: `Bytecode references ${eps.join(", ")}: looks like a smart-account implementation.` });
  if (meta && meta.verified) f.push({ level: "info", code: "verified_source", message: `Source code is verified (${meta.source})${meta.name ? ` as "${meta.name}"` : ""}. Verified does not mean safe.` });
  else if (meta) f.push({ level: "warn", code: "unverified_source", message: `Delegate source is not verified on ${meta.source} (it may be verified elsewhere, e.g. Etherscan). Unverified code is hard to audit.` });
  else f.push({ level: "info", code: "verification_unavailable", message: "Could not fetch source-verification status for this chain right now." });
  if (hasSelfDestruct) f.push({ level: "warn", code: "selfdestruct_opcode", message: "Contains SELFDESTRUCT." });
  const tiny = s.size < 1200;
  if (others.length && hasCall && tiny && !eps.length) {
    f.push({ level: "danger", code: "sweeper_pattern", message: `Small contract (${s.size} bytes) with a CALL and hard-coded address(es) ${others.slice(0, 3).map((a) => "0x" + a).join(", ")}. This is the typical shape of a "sweeper" that forwards funds sent to your wallet to a fixed address.` });
    risk = "high";
  } else if (others.length && hasCall && hasSelfBal && !eps.length) {
    f.push({ level: "warn", code: "hardcoded_destination", message: `Uses SELFBALANCE + CALL and hard-codes address(es) ${others.slice(0, 3).map((a) => "0x" + a).join(", ")}. Check what they are.` });
    risk = "medium";
  } else if (eps.length || (meta && meta.verified)) risk = "low";
  else if (meta && !meta.verified) risk = "medium";
  else risk = "unknown";
  if (risk !== "high") f.push({ level: "info", code: "no_sweeper_pattern", message: "No small hard-coded-forwarder (sweeper) pattern detected in the bytecode." });
  return { risk, findings: f, bytecode_size: s.size, hardcoded_addresses: others.map((a) => "0x" + a).slice(0, 10), function_selectors_approx: s.push4 };
}

async function getJson(u, ms = 6000) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), ms);
  try { const r = await fetch(u, { headers: { "user-agent": "devx-sweepercheck/1.0", accept: "application/json" }, signal: ctl.signal }); if (!r.ok && r.status !== 404) return null; return await r.json(); }
  catch { return null; } finally { clearTimeout(t); }
}
// Source verification: Sourcify first (open, all chains), Blockscout as fallback.
async function scoutMeta(chain, addr) {
  const sf = await getJson(`https://sourcify.dev/server/v2/contract/${chain.id}/${addr}?fields=compilation`);
  if (sf && sf.match) return { verified: true, name: (sf.compilation && sf.compilation.name) || null, source: "sourcify", explorer: `https://repo.sourcify.dev/${chain.id}/${addr}` };
  if (chain.scout) {
    const j = await getJson(`${chain.scout}/api/v2/addresses/${addr}`);
    if (j && j.is_verified) return { verified: true, name: j.name || null, source: "blockscout", explorer: `${chain.scout}/address/${addr}` };
    if (j) return { verified: false, name: j.name || null, source: "sourcify+blockscout" };
  }
  if (sf) return { verified: false, name: null, source: "sourcify" };
  return null;
}

// Basic per-chain status (free tier).
export async function basic(addr) {
  const res = await Promise.all(CHAINS.map(async (c) => {
    try {
      const [code, nonce] = await Promise.all([rpc(c.rpc, "eth_getCode", [addr, "latest"]), rpc(c.rpc, "eth_getTransactionCount", [addr, "latest"])]);
      const lc = (code || "0x").toLowerCase();
      let kind = "eoa"; let delegate = null;
      if (lc.startsWith("0xef0100") && lc.length === 48) { kind = "eoa_delegated_7702"; delegate = "0x" + lc.slice(8); }
      else if (lc !== "0x") kind = "contract";
      return { chain: c.key, chain_id: c.id, name: c.name, kind, delegated: kind === "eoa_delegated_7702", delegate, nonce: parseInt(nonce, 16) };
    } catch (e) { return { chain: c.key, chain_id: c.id, name: c.name, error: "rpc unavailable" }; }
  }));
  const delegated = res.filter((r) => r.delegated);
  return { address: addr.toLowerCase(), checked_at: new Date().toISOString(), delegated_on: delegated.map((r) => r.chain), chains: res };
}

// Full report (paid tier): basic + delegate bytecode analysis + Blockscout metadata + advice.
export async function full(addr) {
  const b = await basic(addr);
  for (const r of b.chains) {
    if (!r.delegated) continue;
    const c = CHAINS.find((x) => x.key === r.chain);
    try {
      const [code, meta] = await Promise.all([rpc(c.rpc, "eth_getCode", [r.delegate, "latest"]), scoutMeta(c, r.delegate)]);
      r.delegate_meta = meta; r.assessment = assessDelegate(addr, r.delegate, code, meta);
    } catch { r.assessment = { risk: "unknown", findings: [{ level: "warn", code: "analysis_failed", message: "Could not read delegate code." }] }; }
  }
  const risks = b.chains.filter((r) => r.assessment).map((r) => r.assessment.risk);
  const worst = risks.includes("high") ? "high" : risks.includes("medium") ? "medium" : risks.includes("unknown") ? "unknown" : risks.length ? "low" : "none";
  b.overall_risk = worst;
  b.advice = worst === "high"
    ? "Treat this private key as compromised: a delegation can only be set with your signature. Do NOT send funds to this address. Move remaining assets to a NEW wallet from a clean device. Clearing the delegation (signing a 7702 authorization to address 0x0) does not help if an attacker holds the key."
    : worst === "medium" ? "Find out who set this delegation and why. If you did not knowingly upgrade this wallet (e.g. in MetaMask/Coinbase/Ambire smart-account settings), assume the key is compromised and move funds to a new wallet."
    : worst === "low" ? "Delegation found that looks like a smart-account implementation. If you set it yourself in your wallet app, this is normal."
    : worst === "unknown" ? "Delegation found; no sweeper pattern detected, but the code could not be fully classified. If you did not knowingly upgrade this wallet, assume the key is compromised and move funds to a new wallet." : "No EIP-7702 delegation found on the checked chains.";
  b.disclaimer = "Heuristic, read-only analysis of public chain data at the time of the call. Not a security guarantee. Never share your seed phrase; this tool never asks for it.";
  return b;
}

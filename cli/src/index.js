// devx-7702-check: tiny client for the DevX 7702 Sweeper Check API.
// Free endpoint: delegation status on 8 EVM chains. Paid full report: x402 (0.01 USDC on Base).
export const DEFAULT_BASE = "https://sweeper-check.nextill-pos.workers.dev";
export const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

/** Free check. Returns the JSON from GET /api/basic. */
export async function checkDelegation(address, { baseUrl = DEFAULT_BASE, fetch: f = globalThis.fetch } = {}) {
  if (!ADDR_RE.test(String(address || "").trim())) throw new Error("address must be 0x + 40 hex characters");
  const res = await f(`${baseUrl.replace(/\/$/, "")}/api/basic?address=${String(address).trim().toLowerCase()}`, { headers: { accept: "application/json", "user-agent": "devx-7702-check" } });
  const body = await res.json();
  if (!res.ok) throw new Error(body && body.error ? body.error : `HTTP ${res.status}`);
  return body;
}

/** Human-readable summary of a free check result. */
export function summarize(r) {
  const lines = [];
  const d = r.delegated_on || [];
  lines.push(d.length ? `EIP-7702 delegation found on ${d.length} chain(s): ${d.join(", ")}` : "No EIP-7702 delegation found on the checked chains.");
  for (const c of r.chains || []) {
    const s = c.error ? "rpc unavailable" : c.delegated ? `DELEGATED -> ${c.delegate}` : c.kind === "contract" ? "contract account" : `plain EOA (nonce ${c.nonce})`;
    lines.push(`  ${c.name.padEnd(16)} ${s}`);
  }
  if (d.length) {
    lines.push("");
    lines.push("A delegation is normal if you upgraded to a smart wallet yourself (MetaMask, Coinbase, Ambire...).");
    lines.push("If you did not, assume the key is compromised and move funds to a new wallet from a clean device.");
    lines.push(`Full sweeper analysis (bytecode heuristic, source verification, risk, advice): ${r.full_report || DEFAULT_BASE + "/v1/check?address=" + r.address}`);
    lines.push("  costs 0.01 USDC on Base via x402, or pay in the browser at " + DEFAULT_BASE + "/");
  }
  return lines.join("\n");
}

// Minimal stateless MCP (Streamable HTTP, JSON responses) for the free check.
import { basic, isAddr } from "./core.js";
const TOOLS = [
  { name: "check_7702_delegation", description: "Free, read-only: is an EIP-7702 delegation (possible wallet sweeper) set on this EVM address on Ethereum, Base, BNB Chain, Arbitrum, OP, Polygon, Gnosis, Unichain? Returns delegate addresses and a link to the paid full report (0.01 USDC via x402).",
    inputSchema: { type: "object", properties: { address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$", description: "EVM address" } }, required: ["address"] }, annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: "full_report_info", description: "How to buy the full sweeper report (bytecode heuristic, source verification, risk, advice) via x402. Does not pay.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
];
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
async function handle(m, origin) {
  const { id, method, params } = m || {};
  if (id === undefined || id === null) return null; // notification
  if (method === "initialize") return ok(id, { protocolVersion: (params && params.protocolVersion) || "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "devx-7702-sweeper-check", version: "1.0.0" }, instructions: "EIP-7702 delegation check on 8 EVM chains. Read-only; never asks for keys." });
  if (method === "ping") return ok(id, {});
  if (method === "tools/list") return ok(id, { tools: TOOLS });
  if (method === "tools/call") {
    const name = params && params.name, a = (params && params.arguments) || {};
    if (name === "full_report_info") return ok(id, { content: [{ type: "text", text: `GET ${origin}/v1/check?address=0x..[,0x..] (1-20 addresses) answers HTTP 402 with an x402 v2 PAYMENT-REQUIRED header: exact, eip155:8453, USDC, 10000 units = 0.01 USDC. Settled only after the report is produced. Docs ${origin}/openapi.json. Humans can pay in the browser at ${origin}/` }] });
    if (name === "check_7702_delegation") {
      const addr = String(a.address || "").trim().toLowerCase();
      if (!isAddr(addr)) return ok(id, { isError: true, content: [{ type: "text", text: "address must be 0x + 40 hex characters" }] });
      const r = await basic(addr); r.full_report = `${origin}/v1/check?address=${addr}`; r.full_report_price_usdc = 0.01;
      const s = r.delegated_on.length ? `Delegation found on: ${r.delegated_on.join(", ")}. Normal if the owner upgraded to a smart wallet; otherwise treat the key as compromised. Full sweeper report: ${r.full_report} (0.01 USDC, x402).` : "No EIP-7702 delegation found on the checked chains.";
      return ok(id, { content: [{ type: "text", text: s + "\n\n" + JSON.stringify(r) }], structuredContent: r });
    }
    return err(id, -32602, "unknown tool");
  }
  return err(id, -32601, "method not found");
}
export async function mcp(req, origin) {
  const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-expose-headers": "mcp-session-id" };
  if (req.method === "GET") return new Response(JSON.stringify({ name: "devx-7702-sweeper-check", transport: "streamable-http (POST JSON-RPC)", tools: TOOLS.map((t) => t.name) }), { status: 200, headers: H });
  if (req.method !== "POST") return new Response(null, { status: 405, headers: H });
  let body; try { body = await req.json(); } catch { return new Response(JSON.stringify(err(null, -32700, "parse error")), { status: 400, headers: H }); }
  if (Array.isArray(body)) { const out = (await Promise.all(body.map((m) => handle(m, origin)))).filter(Boolean); return out.length ? new Response(JSON.stringify(out), { headers: H }) : new Response(null, { status: 202, headers: H }); }
  const r = await handle(body, origin);
  return r ? new Response(JSON.stringify(r), { headers: H }) : new Response(null, { status: 202, headers: H });
}

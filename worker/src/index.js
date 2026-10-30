import { basic, full, isAddr, CHAINS } from "./core.js";
import PAGE from "./page.html";
import EXPLAINER from "./explainer.html";
import { mcp } from "./mcp.js";

const VERSION = "1.1.0";
const SERVICE = "DevX 7702 Sweeper Check";
const PAY_TO = "0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247";
const FACILITATOR = "https://facilitator.payai.network";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PRICE = "10000"; // 0.01 USDC per report (1-20 addresses)
const ROUTE = "/v1/check";
const MAX = 20;
const DESC = "EIP-7702 delegation & sweeper check for EVM wallets across 8 chains (Ethereum, Base, BSC, Arbitrum, OP, Polygon, Gnosis, Unichain). Paid report adds delegate bytecode analysis (sweeper/hard-coded forwarder heuristic), source-verification status, risk level and remediation advice. 1-20 addresses per call.";
const enc = new TextEncoder();
const b64 = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))));
const EXAMPLE = { address: "0x75e732608bc17b23d01f01728562ee844196dcc3", delegated_on: ["ethereum", "base"], overall_risk: "medium", chains: [{ chain: "base", delegated: true, delegate: "0x78608e7a956fe1ca4af4a31138fd67779b08f9b5", assessment: { risk: "unknown", findings: [{ level: "info", code: "no_sweeper_pattern" }], bytecode_size: 11603 } }], advice: "..." };

function requirements() { return { scheme: "exact", network: "eip155:8453", amount: PRICE, asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }; }
function advertised(resUrl) { return { ...requirements(), maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json" }; }
function paymentRequired(origin, error, resUrl) {
  resUrl = resUrl || origin + ROUTE;
  return { x402Version: 2, error: error || "PAYMENT-SIGNATURE header is required",
    resource: { url: resUrl, description: DESC, mimeType: "application/json", serviceName: SERVICE, tags: ["security", "eip-7702", "wallet", "agents", "x402"] },
    accepts: [advertised(resUrl)],
    extensions: { bazaar: { info: { input: { type: "http", method: "GET", queryParams: { address: EXAMPLE.address } }, output: { type: "json", example: EXAMPLE } },
      schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object", properties: { input: { type: "object", properties: { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET"] }, queryParams: { type: "object", properties: { address: { type: "string", description: "one 0x address or up to 20 comma-separated" } }, required: ["address"] } }, required: ["type", "method"] }, output: { type: "object" } }, required: ["input"] } } } };
}
const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o, null, 2), { status, headers: { ...H, ...h } });
async function facil(op, body) { const r = await fetch(`${FACILITATOR}/${op}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); try { return await r.json(); } catch { return {}; } }
function parseAddrs(q) {
  const list = [...new Set(String(q || "").split(/[\s,]+/).filter(Boolean).map((a) => a.toLowerCase()))];
  if (!list.length) return { error: "address query parameter required (0x..., up to 20 comma-separated)" };
  if (list.length > MAX) return { error: `max ${MAX} addresses per call` };
  const bad = list.filter((a) => !isAddr(a)); if (bad.length) return { error: "invalid address: " + bad[0] };
  return { list };
}

const TERMS = `${SERVICE} - Terms of Service (v${VERSION}, effective 2026-10-30)
Operator: DevX / Made by DevX (madebydevx.com), contact madebydevx@gmail.com.
1. Service. Read-only lookups of public blockchain data. GET /api/basic?address=0x... (free) reports whether an address has an EIP-7702 delegation on ${CHAINS.length} EVM chains. GET ${ROUTE}?address=0x...[,0x...] (paid, 1-${MAX} addresses) adds analysis of the delegate contract: bytecode heuristics (e.g. a small contract with a hard-coded forwarding address, the usual "sweeper" shape), source-verification status where available, a risk level and advice. We never ask for, receive or store seed phrases or private keys, and never move funds.
2. Price. 0.01 USDC per paid call, x402 v2 "exact" on Base (eip155:8453), paid to ${PAY_TO}, settled through ${FACILITATOR}. In the browser you sign an EIP-3009 USDC authorization for exactly that amount; gas is paid by the facilitator.
3. Not charged on error. Payment is settled only after the report is produced. Invalid input or an internal error returns an error and the authorization is not settled.
4. Refunds. If you were charged but got no report, email madebydevx@gmail.com with the Base tx hash within 30 days; verified cases are refunded in USDC on Base to the paying address.
5. Not a guarantee. Results are heuristics on public data at the time of the call. "No sweeper pattern" does not prove a wallet is safe; "high" does not prove theft. If in doubt, move funds to a new wallet created on a clean device.
6. Data. We do not store queried addresses beyond Cloudflare's standard request logs.
7. Changes. Material changes bump the version; the price in the live 402 response is authoritative.`;

function docs(origin) {
  return { openapi: "3.1.0", info: { title: SERVICE, version: VERSION, description: DESC, termsOfService: origin + "/terms", contact: { name: "DevX", email: "madebydevx@gmail.com", url: "https://madebydevx.com" } },
    servers: [{ url: origin }],
    paths: {
      "/api/basic": { get: { summary: "Free: EIP-7702 delegation status on 8 chains for one address", parameters: [{ name: "address", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "status" } } } },
      [ROUTE]: { get: { summary: "Paid (0.01 USDC, x402): full sweeper/delegation report for 1-20 addresses", parameters: [{ name: "address", in: "query", required: true, schema: { type: "string" }, description: "0x address or comma-separated list (max 20)" }],
        "x-payment-info": { protocol: "x402", x402Version: 2, scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: PRICE, price_usd: 0.01, payTo: PAY_TO, facilitator: FACILITATOR },
        responses: { 200: { description: "report" }, 402: { description: "Payment required (PAYMENT-REQUIRED header, x402 v2)" } } } } } };
}

export default {
  async fetch(req) {
    const url = new URL(req.url), origin = url.origin, p = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { headers: { ...H, "access-control-allow-headers": "*", "access-control-allow-methods": "GET, HEAD, POST, OPTIONS" } });
    if (p === "/" ) return new Response(PAGE.replaceAll("__PAYTO__", PAY_TO), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" } });
    if (p === "/index.json") return J({ service: SERVICE, version: VERSION, by: "Made by DevX (madebydevx.com)", free: origin + "/api/basic?address=0x...", paid: origin + ROUTE + "?address=0x...", price_usdc: 0.01, protocol: "x402 v2 exact, USDC on Base", payTo: PAY_TO, docs: origin + "/openapi.json", terms: origin + "/terms", description: DESC });
    if (p === "/what-is-an-eip-7702-sweeper" || p === "/what-is-an-eip-7702-sweeper/") return new Response(EXPLAINER, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=3600" } });
    if (p === "/robots.txt") return new Response("User-agent: *\nAllow: /\nSitemap: https://sweeper-check.nextill-pos.workers.dev/sitemap.xml\n", { headers: { "content-type": "text/plain" } });
    if (p === "/sitemap.xml") return new Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://sweeper-check.nextill-pos.workers.dev/</loc><lastmod>2026-10-30</lastmod></url><url><loc>https://sweeper-check.nextill-pos.workers.dev/what-is-an-eip-7702-sweeper</loc><lastmod>2026-10-30</lastmod></url></urlset>', { headers: { "content-type": "application/xml" } });
    if (p === "/llms.txt") return new Response(`# DevX 7702 Sweeper Check
> Free check whether an EVM address has an EIP-7702 delegation (wallet sweeper) on 8 chains. Paid full report 0.01 USDC via x402 on Base.
- Explainer: https://sweeper-check.nextill-pos.workers.dev/what-is-an-eip-7702-sweeper
- Free API: GET /api/basic?address=0x...
- Paid API (x402): GET /v1/check?address=0x...,0x...
- MCP: https://sweeper-check.nextill-pos.workers.dev/mcp
- OpenAPI: /openapi.json
- Source: https://github.com/devx-agent/7702-sweeper-check
- Related: https://crypto-link-check.nextill-pos.workers.dev/how-to-spot-fake-crypto-links
`, { headers: { "content-type": "text/plain; charset=utf-8" } });
    if (p === "/terms") return new Response(TERMS, { headers: { "content-type": "text/plain; charset=utf-8", "access-control-allow-origin": "*" } });
    if (p === "/openapi.json") return J(docs(origin));
    if (p === "/.well-known/agent-tools-verify.txt") return new Response("atc_rZEoWe2lFdc8Gb39Ret-8EAAmVj0k-k-\n", { headers: { "content-type": "text/plain" } });
    if (p === "/.well-known/x402") return J({ version: 1, resources: [origin + ROUTE], description: SERVICE });
    if (p === "/.well-known/x402.json") return J({ x402Version: 2, name: SERVICE, provider: "Made by DevX (madebydevx.com)", resources: [{ url: origin + ROUTE, method: "GET", description: DESC, accepts: [requirements()] }] });
    if (p === "/mcp") return mcp(req, origin);
    if (p === "/.well-known/mcp.json" || p === "/.well-known/mcp/server-card.json") return J({ name: "devx-7702-sweeper-check", description: "EIP-7702 delegation / sweeper check on 8 EVM chains", url: origin + "/mcp", transport: "streamable-http", tools: ["check_7702_delegation", "full_report_info"], provider: "Made by DevX", repository: "https://github.com/devx-agent/7702-sweeper-check" });
    if (p === "/health") return J({ ok: true, version: VERSION });
    if (p === "/api/basic") {
      const a = (url.searchParams.get("address") || "").trim().toLowerCase();
      if (!isAddr(a)) return J({ error: "address must be a 0x 20-byte hex address" }, 400);
      const r = await basic(a); r.full_report = origin + ROUTE + "?address=" + a; r.full_report_price_usdc = 0.01; return J(r);
    }
    if (p !== ROUTE) return J({ error: "not found", see: origin + "/index.json" }, 404);
    if (req.method !== "GET" && req.method !== "HEAD") return J({ error: "use GET" }, 405);
    const pr = paymentRequired(origin, null, origin + ROUTE + url.search);
    const parsed = parseAddrs(url.searchParams.get("address"));
    const sig = req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("X-PAYMENT");
    if (!sig) return J(pr, 402, { "PAYMENT-REQUIRED": b64(pr) });
    if (parsed.error) return J({ error: parsed.error + " (you were not charged)" }, 400);
    let payload; try { payload = unb64(sig); } catch { return J({ ...pr, error: "malformed PAYMENT-SIGNATURE" }, 400, { "PAYMENT-REQUIRED": b64(pr) }); }
    const reqs = requirements(), acc = payload.accepted || {};
    if (payload.x402Version !== 2 || acc.network !== reqs.network || acc.payTo?.toLowerCase() !== PAY_TO.toLowerCase() || acc.amount !== reqs.amount || acc.asset?.toLowerCase() !== USDC_BASE.toLowerCase())
      return J({ ...pr, error: "payment does not match requirements (x402 v2, exact, eip155:8453 USDC 10000)" }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    const v = await facil("verify", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!v.isValid) return J({ ...pr, error: "payment invalid: " + (v.invalidReason || "unknown") }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    let reports; try { reports = await Promise.all(parsed.list.map(full)); } catch (e) { return J({ error: "internal error, you were not charged" }, 500); }
    const s = await facil("settle", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!s.success) return J({ ...pr, error: "settlement failed: " + (s.errorReason || "unknown") + " (report withheld, not charged)" }, 402, { "PAYMENT-REQUIRED": b64(pr), "PAYMENT-RESPONSE": b64(s) });
    return J({ service: SERVICE, version: VERSION, count: reports.length, reports, payment: { tx: s.transaction || null, network: s.network || "eip155:8453" } }, 200, { "PAYMENT-RESPONSE": b64(s) });
  },
};

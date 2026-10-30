import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkDelegation, summarize, DEFAULT_BASE } from "./index.js";
export const VERSION = "1.1.0";
const chainRow = z.object({
  chain: z.string().describe("short chain key, e.g. base"), chain_id: z.number(), name: z.string(),
  kind: z.string().optional().describe("eoa | eoa_delegated_7702 | contract"), delegated: z.boolean().optional(),
  delegate: z.string().nullable().optional().describe("contract the account delegates to (EIP-7702), else null"),
  nonce: z.number().optional(), error: z.string().optional().describe("set when that chain's RPC could not be read"),
}).passthrough();

export function createServer(options = {}) {
  const base = options.baseUrl || DEFAULT_BASE;
  const server = new McpServer({ name: "devx-7702-check", version: VERSION }, {
    instructions: "Use check_7702_delegation to see whether an EVM wallet has an EIP-7702 delegation set (its code points to another contract). Drainer 'sweeper' contracts use such delegations to empty compromised wallets. The check is read-only, free, never asks for keys and cannot move funds. It sends the address to the hosted DevX API. full_report_info only describes the optional paid analysis; it does not pay.",
  });

  server.registerTool("check_7702_delegation", {
    title: "Check an EVM address for EIP-7702 delegations",
    description: [
      "Checks whether an EVM address has an EIP-7702 delegation set on Ethereum, Base, BNB Chain, Arbitrum One, OP Mainnet, Polygon PoS, Gnosis and Unichain, and returns the delegate contract per chain.",
      "Use it before sending funds to a wallet or reusing one, when a wallet behaves oddly (incoming funds vanish), or when an incident-response flow needs to know if a key was abused to install a sweeper.",
      "It is free and read-only. It sends the address to the hosted DevX API (" + base + "/api/basic), which reads each chain's account code and nonce over public RPC. No keys, no signatures, no payment.",
      "Returns: address, checked_at, delegated_on (chain keys where a delegation is set; empty means none found), and chains (one row per chain with kind eoa, eoa_delegated_7702 or contract, delegated, delegate, nonce, or error if that chain's RPC was unavailable), plus the URL and price of the paid full report.",
      "A delegation is normal when the owner upgraded to a smart wallet on purpose (MetaMask, Coinbase, Ambire and others). This tool does not judge whether the delegate is malicious. full_report_info describes the paid report that does (bytecode heuristics, source verification, risk level, advice).",
    ].join(" "),
    inputSchema: {
      address: z.string().regex(/^0x[0-9a-fA-F]{40}$/).describe("EVM account to check: 0x followed by 40 hex characters, any letter case. One address per call. Example: 0x75e732608bc17b23d01f01728562ee844196dcc3"),
    },
    outputSchema: z.object({
      address: z.string(), checked_at: z.string().describe("ISO 8601 time of the check"),
      delegated_on: z.array(z.string()).describe("chain keys where an EIP-7702 delegation is set"),
      chains: z.array(chainRow),
      full_report: z.string().optional().describe("URL of the paid full report for this address"), full_report_price_usdc: z.number().optional(),
    }).passthrough(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, async ({ address }) => {
    try { const r = await checkDelegation(address, options); return { structuredContent: r, content: [{ type: "text", text: summarize(r) + "\n\n" + JSON.stringify(r) }] }; }
    catch (e) { return { isError: true, content: [{ type: "text", text: String(e.message || e) }] }; }
  });

  server.registerTool("full_report_info", {
    title: "How to buy the full sweeper report",
    description: [
      "Returns the endpoint, price and payment method of the optional paid sweeper report. It does not call the API and does not pay or sign anything.",
      "The paid report analyses each delegate found: bytecode heuristics for sweeper/drainer patterns, source verification, an overall risk level and plain-language advice. It accepts 1-20 addresses per call for 0.01 USDC on Base via x402.",
      "Use it after check_7702_delegation reports a delegation that the owner did not set up knowingly. If delegated_on is empty, the paid report adds little.",
      "Returns: method, url_template, price_usdc, network, asset, protocol, max_addresses, settles and docs.",
    ].join(" "),
    inputSchema: {},
    outputSchema: { method: z.string(), url_template: z.string(), price_usdc: z.number(), network: z.string(), asset: z.string(), protocol: z.string(), max_addresses: z.number(), settles: z.string(), docs: z.string() },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    const info = { method: "GET", url_template: `${base}/v1/check?address=0x...[,0x...]`, price_usdc: 0.01, network: "eip155:8453 (Base)", asset: "USDC", protocol: "x402 v2 exact (HTTP 402 with a PAYMENT-REQUIRED header; any x402 client can pay)", max_addresses: 20, settles: "only after the report is produced", docs: `${base}/openapi.json` };
    return { structuredContent: info, content: [{ type: "text", text: JSON.stringify(info) }] };
  });
  return server;
}

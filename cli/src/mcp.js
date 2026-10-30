import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkDelegation, summarize, DEFAULT_BASE } from "./index.js";

export function createServer(options = {}) {
  const server = new McpServer({ name: "devx-7702-check", version: "1.0.0" }, { instructions: "Check whether an EVM wallet has an EIP-7702 delegation (possible sweeper) on 8 chains. Free and read-only; never asks for keys." });
  server.tool("check_7702_delegation", "Free: is an EIP-7702 delegation set on this EVM address on Ethereum, Base, BNB Chain, Arbitrum, OP, Polygon, Gnosis, Unichain? Returns delegate addresses and a link to the paid full sweeper report.",
    { address: z.string().regex(/^0x[0-9a-fA-F]{40}$/).describe("EVM address, 0x...") },
    async ({ address }) => {
      try { const r = await checkDelegation(address, options); return { content: [{ type: "text", text: summarize(r) + "\n\n" + JSON.stringify(r) }] }; }
      catch (e) { return { isError: true, content: [{ type: "text", text: String(e.message || e) }] }; }
    });
  server.tool("full_report_info", "How to get the paid full sweeper report (x402, 0.01 USDC on Base, 1-20 addresses). Does not pay anything.", {},
    async () => ({ content: [{ type: "text", text: `GET ${options.baseUrl || DEFAULT_BASE}/v1/check?address=0x..[,0x..] returns HTTP 402 with an x402 v2 PAYMENT-REQUIRED header (exact, eip155:8453 USDC, 10000 units = 0.01 USDC). Pay with any x402 client; settlement only after the report is produced. Docs: ${options.baseUrl || DEFAULT_BASE}/openapi.json` }] }));
  return server;
}

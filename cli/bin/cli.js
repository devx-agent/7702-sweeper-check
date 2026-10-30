#!/usr/bin/env node
import { checkDelegation, summarize } from "../src/index.js";
const args = process.argv.slice(2);
if (args[0] === "mcp") {
  const { createServer } = await import("../src/mcp.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  await createServer({ baseUrl: process.env.SWEEPER_CHECK_URL || undefined }).connect(new StdioServerTransport());
} else if (!args.length || args[0] === "-h" || args[0] === "--help") {
  process.stdout.write("Usage:\n  devx-7702-check <0xaddress> [more...] [--json]   free EIP-7702 delegation check on 8 chains\n  devx-7702-check mcp                              run as an MCP server (stdio)\nRead-only. Never asks for keys or seed phrases.\n");
} else {
  const json = args.includes("--json"); let bad = 0;
  for (const a of args.filter((x) => x !== "--json")) {
    try { const r = await checkDelegation(a, { baseUrl: process.env.SWEEPER_CHECK_URL || undefined }); process.stdout.write((json ? JSON.stringify(r, null, 2) : `${a}\n${summarize(r)}`) + "\n\n"); if (r.delegated_on.length) bad = 2; }
    catch (e) { process.stderr.write(`${a}: ${e.message}\n`); bad = bad || 1; }
  }
  process.exitCode = bad; // 0 = no delegation, 2 = delegation found, 1 = error
}

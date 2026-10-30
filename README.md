# 7702 Sweeper Check

**Does your EVM wallet have an EIP-7702 delegation you didn't set?**

Since Ethereum's Pectra upgrade, one signature can attach contract code to an ordinary wallet (EIP-7702). Smart-wallet upgrades use this legitimately. Drainers use it to install **sweepers**: tiny contracts that forward anything sent to your wallet straight to the attacker.

This project checks **8 chains at once**: Ethereum, Base, BNB Chain, Arbitrum, OP, Polygon, Gnosis and Unichain.

- **Web (free):** https://sweeper-check.nextill-pos.workers.dev
- **CLI (free):** `npx devx-7702-check 0xYourAddress`
- **MCP server for AI agents (free):** remote `https://sweeper-check.nextill-pos.workers.dev/mcp`, or local `npx devx-7702-check mcp`
- **JSON API (free):** `GET /api/basic?address=0x...`
- **Full report (paid, 0.01 USDC on Base via [x402](https://x402.org)):** `GET /v1/check?address=0x..[,0x..]`, 1–20 addresses per call. It adds:
  - a delegate bytecode heuristic (a small contract with a hard-coded forwarding address = the sweeper shape);
  - source-verification status (Sourcify / Blockscout);
  - a risk level and what to do.
  You're charged only after the report is produced. Humans can pay with a browser wallet on the web page: you sign one USDC authorization and pay no gas.

Read-only. It never asks for or touches private keys or seed phrases.

## How detection works
A 7702-delegated account's code is exactly `0xef0100 ‖ <20-byte delegate address>`. The free check reads `eth_getCode` and the nonce on each chain. The paid report then fetches the delegate's bytecode and walks the opcodes (skipping PUSH data):
- `PUSH20` constants other than your own address and the ERC-4337 EntryPoints, combined with `CALL`, in a contract under 1.2 KB → **high** (sweeper pattern).
- `SELFBALANCE` + `CALL` + a hard-coded address → **medium**.
- Verified source or ERC-4337 smart-account shape → **low**.
- Otherwise → **medium/unknown**.

These are heuristics, not guarantees. If a delegation you didn't create shows up, treat the key as compromised and move funds to a **new** wallet made on a clean device. Re-delegating to `0x0` doesn't help if an attacker holds the key.

## CLI
```
npx devx-7702-check 0xabc... 0xdef...    # exit code 0 = none, 2 = delegation found, 1 = error
npx devx-7702-check 0xabc... --json
```

## MCP
Claude Desktop / Cursor config:
```json
{ "mcpServers": { "7702-sweeper-check": { "url": "https://sweeper-check.nextill-pos.workers.dev/mcp" } } }
```
or stdio: `{ "command": "npx", "args": ["-y", "devx-7702-check", "mcp"] }`

Tools: `check_7702_delegation(address)`, `full_report_info()`.

## x402 (agents)
`GET /v1/check?address=...` returns `402` with a `PAYMENT-REQUIRED` header (x402 v2, scheme `exact`, network `eip155:8453`, USDC `0x8335…2913`, amount `10000` = 0.01 USDC). Pay with any x402 client. Discovery: `/.well-known/x402.json`, `/openapi.json`. Terms: `/terms`.

## Layout
- `worker/`: Cloudflare Worker source (page, free API, x402 paid route, remote MCP)
- `cli/`: the npm package `devx-7702-check` (CLI + stdio MCP server)

Made by [DevX](https://madebydevx.com). MIT.

## Guide

- [What is an EIP-7702 sweeper?](https://sweeper-check.nextill-pos.workers.dev/what-is-an-eip-7702-sweeper)
- Related free tool: [Crypto Link Check](https://crypto-link-check.nextill-pos.workers.dev/) — is that wallet or exchange link real?

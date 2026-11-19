# AirdropGuard

**An agent that checks an airdrop before you connect your wallet.** Give it an airdrop link, a domain, an X handle or a project name, and optionally a contract address or a Concordium agent badge id. It returns a **risk score (0–100)**, a **verdict** (`likely legit` / `suspicious` / `likely scam`) and an **evidence list**, where every item says where its data came from.

Built for the Concordium *Trusted Agents* hackathon (Encode Club). Solo project. **Testnet only**: v0 reads public data and sends no transactions.

---

## The problem

Fake airdrops are one of the most common ways crypto users lose funds. The pattern rarely changes: a lookalike domain registered a few days ago (`concordium-airdrop-claim.xyz`), a lookalike X account (`@Concordium_Net`), a "Connect wallet → Claim now → 2 hours left" page, and sometimes a request for the seed phrase. AI agents now promote and "verify" airdrops too, so users also need to know **whether the agent itself can be trusted**. Concordium's Agent Registry answers that: badges are anchored on-chain and the agent card is pinned by its hash.

AirdropGuard combines both: chain-agnostic phishing checks, plus Concordium's on-chain agent identity as an extra trust signal.

## What it checks (v0)

| Check | Data source | Effect on risk |
|---|---|---|
| Official domain match | curated reference list `data/official-projects.json` | −35 |
| Lookalike / typosquat domain (edit distance, confusables `0→o`, `rn→m`, `l/i/1`; brand + extra words; same name on another TLD; punycode) | computed locally against the reference list | +40, **critical** |
| Airdrop bait words in domain (`airdrop`, `claim`, `reward`…) | local | +10 |
| Domain age and registrar | **RDAP** (`rdap.org`, the structured successor of WHOIS) | <30 days +25 · <180 days +10 · ≥2 years −10 · not found → `unknown`, 0 |
| Phishing content on the live page: seed phrase / private key / 助记词 (+35, critical), connect wallet (+5), claim now (+8), urgency / countdown (+10), drainer calls like `setApprovalForAll` / `permit2` (+15), connect wallet combined with urgency (+10) | real HTTP fetch of the link (≤1 MB) | as listed · fetch failed → `unknown` |
| Off-domain redirect | real fetch | +10 |
| X handle: official handle or lookalike | reference list | −20 / +40 critical |
| Contract address | format validation only in v0 | 0 (marked `unknown`) |
| **Concordium agent badge** | **Agent Registry REST** `GET /v1/check-badge/{id}` | see below |

**Badge scoring** (Concordium signal, one input among several):

- Valid, `Active`, card SHA-256 matches the on-chain `metadata_hash` → **−20**
- Valid badge whose agent card is hosted on a *different* domain from the link being checked → **+10 warning** (a real badge "borrowed" by another site)
- `409` revoked, or status not `Active` → **+40, critical**
- Card hash does **not** match the on-chain hash → **+35, critical** (card changed after registration)
- `404` no agent / no badge → **0, neutral** (most projects have no badge)
- `400` malformed id → +5 · `429` rate-limited or network error → `unknown`, 0
- Concordium account address given → lists the badges it owns (0 badges → neutral)

**Score** = 40 (base) + sum of weights, clamped to 0–100. Any *critical* finding raises the score to at least 60. Verdict: `<30` likely legit, `30–59` suspicious, `≥60` likely scam. Confidence is `high` with a critical finding or ≥3 scoring signals, `medium` with 1–2, `low` with none.

**Honesty rule:** nothing is guessed. If RDAP, the page or the registry can't be reached, the evidence item is `unknown` with weight 0 and says why.

## Architecture

```
            CLI (src/cli.ts)          HTTP API (src/server.ts)
                  │                POST /check · GET /healthz
                  │                   │  └─ x402 gate (src/x402.ts, STUB)
                  └──────► runCheck (src/guard.ts) ◄────┘
                               │ normalizeTarget → url | domain | x_handle | project_name
     ┌──────────────┬──────────┼──────────────┬────────────────┬───────────────┐
 typosquat.ts   domainAge.ts  content.ts     contract.ts      badge.ts
 (local, vs     (RDAP)        (page fetch +  (format only)    (Concordium Agent
 official list)               keyword scan)                   Registry REST)
                               │
                        score.ts → riskScore, verdict, confidence, evidence[]
```

- TypeScript on Node ≥20, no runtime dependencies (built-in `fetch`, `node:http`, `node:test`). Dev dependencies: `typescript`, `tsx`, `@types/node`.
- All network access goes through an injected `fetch`, so unit tests are fully offline and deterministic.

```
airdropguard/
├── src/
│   ├── cli.ts            CLI entry point
│   ├── server.ts         HTTP API (POST /check, GET /healthz)
│   ├── guard.ts          orchestrates the checks → report
│   ├── score.ts          weights → score / verdict / confidence
│   ├── normalize.ts      input parsing, registrable domain
│   ├── official.ts       loads the reference list
│   ├── x402.ts           x402 payment-gate STUB (interfaces + TODOs)
│   ├── config.ts         .env loader and config
│   ├── http.ts           fetch with timeout
│   ├── types.ts
│   └── checks/{typosquat,domainAge,content,contract,badge}.ts
├── data/official-projects.json   reference domains / X handles (hand-curated seed)
├── test/                 node:test unit tests (mocked network)
├── examples/             real outputs captured on 2026-11-19
├── .env.example
└── README.md
```

## Run it

```bash
npm install
cp .env.example .env

# CLI
npm run check -- https://www.concordium.com/
npm run check -- concordium.com --badge Mf22soLh1NuZYFgBK8iSs
npm run check -- @Concordium_Net
npm run check -- https://some-airdrop.xyz/claim --contract 0xabc... --json
#   flags: --badge/-b <badge token address | Concordium account>  --network testnet|mainnet|devnet
#          --contract/-c <addr>  --json  --no-fetch (skip downloading the page)
#   exit code 2 when the verdict is "likely scam"

# HTTP API
npm run serve            # http://localhost:8787
curl -s -X POST localhost:8787/check -H 'content-type: application/json' \
  -d '{"target":"https://www.concordium.com/","badgeId":"Mf22soLh1NuZYFgBK8iSs"}'

# Tests (offline)
npm test

# Compiled build
npm run build && node dist/cli.js concordium.com
```

`POST /check` body: `{ "target": string, "badgeId"?: string, "contract"?: string, "network"?: "testnet"|"mainnet"|"devnet", "fetchPage"?: boolean }`.

## Concordium components used

- **Agent Registry (CIS-8004 agent badges)** through the hosted service `https://agent-registry-mcp.concordium.com`. REST `GET /v1/check-badge/{id}` is the MCP twin of the `check_badge` tool. One call covers the on-chain record, `Active`/`Revoked` status, the agent-card fetch with its SHA-256 compared to the on-chain `metadata_hash`, and badge well-formedness. No auth needed; per-IP rate limit (`429` + `Retry-After` is handled).
- **Concordium accounts:** passing an account address lists the badges it owns (tested against the operator's testnet account).
- **x402** (planned): pay-per-check API with `OPERATOR_ACCOUNT` (testnet) as the pay-to address. **v0 has a stub only** (`src/x402.ts`): it returns a correct-shape `402` with payment requirements when `X402_ENABLED=true` and refuses every payment, because verification isn't implemented.
- Network note: the registry works out the network from the badge itself. The docs' example badge `Mf22soLh1NuZYFgBK8iSs` is on **mainnet** (read-only lookup); the operator account and the planned x402 flow are on **testnet**.

## Path to production

1. **Reference data:** replace the hand-made `official-projects.json` with an authoritative, signed source (project-published lists, Concordium-badged project agents, community lists such as known phishing feeds) and refresh it automatically.
2. **More signals:** contract checks through explorer APIs (deployment age, verified source, whether the address is on the project's official list), TLS certificate age, the full Public Suffix List, X account age through an API, and a known-phishing domain feed.
3. **Cross-chain agent lookup:** use `agent_by_external_reference` (MCP) to find a Concordium badge from an EVM/Solana address when no badge id is given.
4. **Self-anchoring:** register AirdropGuard itself in the Agent Registry on testnet (publish an agent card, sign the `build_register` payload in the wallet), so clients can verify the checker before trusting it.
5. **x402:** implement `PaymentVerifier.verify/settle` for Concordium testnet, settle only after a successful check, and add a rate-limit tier for paid calls. Then move to mainnet.
6. **Distribution:** expose AirdropGuard as an MCP tool and an A2A agent, add a browser extension or Telegram/X bot front end, and add caching, per-IP limits and request logging without storing personal data.

## Known limitations (v0)

- Several TLDs (`.io`, `.ag`, among others) have no public RDAP through rdap.org, so their domain age shows as `unknown`.
- Lookalike detection only covers the 10 projects in the reference list, and similar but unrelated names can trigger false positives (e.g. a domain one letter away from `optimism`).
- Exact X-handle match is checked by name only; follower count and account age aren't checked.
- Contract addresses are format-checked only.
- Page scanning reads raw HTML; content rendered by JavaScript after load isn't seen.

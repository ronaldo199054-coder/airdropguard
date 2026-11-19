#!/usr/bin/env node
import { parseArgs } from "node:util";
import { defaultDeps } from "./config.js";
import { runCheck } from "./guard.js";
import type { CheckReport, Network } from "./types.js";

const ICON: Record<string, string> = { pass: "✔", warn: "!", fail: "✖", info: "·", unknown: "?" };

export function formatReport(r: CheckReport): string {
  const lines = [
    `AirdropGuard v${r.version} — ${r.input.target}  (${r.target.kind})`,
    `Risk score: ${r.riskScore}/100   Verdict: ${r.verdict.toUpperCase()}   Confidence: ${r.confidence}`,
    "",
    r.summary,
    "",
    "Evidence:",
    ...r.evidence.map((e) => `  ${ICON[e.status]} [${e.status}${e.weight ? ` ${e.weight > 0 ? "+" : ""}${e.weight}` : ""}] ${e.check}: ${e.detail}${e.source ? `\n      source: ${e.source}` : ""}`),
  ];
  return lines.join("\n");
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      contract: { type: "string", short: "c" },
      badge: { type: "string", short: "b" },
      network: { type: "string", short: "n" },
      json: { type: "boolean" },
      "no-fetch": { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help || !positionals.length) {
    console.log("Usage: airdropguard <link | domain | @handle | project name> [--contract ADDR] [--badge BADGE_ID] [--network testnet|mainnet|devnet] [--json] [--no-fetch]");
    process.exit(values.help ? 0 : 1);
  }
  const report = await runCheck(
    { target: positionals.join(" "), contract: values.contract, badgeId: values.badge, network: values.network as Network | undefined, fetchPage: !values["no-fetch"] },
    defaultDeps(),
  );
  console.log(values.json ? JSON.stringify(report, null, 2) : formatReport(report));
  process.exitCode = report.verdict === "likely scam" ? 2 : 0;
}

main().catch((e) => {
  console.error("error:", e instanceof Error ? e.message : e);
  process.exit(1);
});

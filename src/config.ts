import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Deps } from "./types.js";

/** Minimal .env loader (no dependency). Existing process.env values win. */
export function loadDotEnv(path = resolve(process.cwd(), ".env")): void {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!m || line.trim().startsWith("#")) continue;
    const [, k, v] = m;
    if (process.env[k] === undefined) process.env[k] = v.replace(/^["']|["']$/g, "");
  }
}

export interface AppConfig {
  operatorAccount: string;
  network: string;
  registryUrl: string;
  rdapUrl: string;
  port: number;
  timeoutMs: number;
  x402Enabled: boolean;
  x402Price: string;
  x402Asset: string;
}

export function getConfig(): AppConfig {
  loadDotEnv();
  const e = process.env;
  return {
    operatorAccount: e.OPERATOR_ACCOUNT ?? "",
    network: e.CONCORDIUM_NETWORK ?? "testnet",
    registryUrl: (e.AGENT_REGISTRY_URL ?? "https://agent-registry-mcp.concordium.com").replace(/\/$/, ""),
    rdapUrl: (e.RDAP_URL ?? "https://rdap.org").replace(/\/$/, ""),
    port: Number(e.PORT ?? 8787),
    timeoutMs: Number(e.HTTP_TIMEOUT_MS ?? 10000),
    x402Enabled: (e.X402_ENABLED ?? "false").toLowerCase() === "true",
    x402Price: e.X402_PRICE ?? "0.01",
    x402Asset: e.X402_ASSET ?? "CCD",
  };
}

export function defaultDeps(cfg = getConfig()): Deps {
  return {
    fetch: (u, init) => fetch(u, init),
    registryUrl: cfg.registryUrl,
    rdapUrl: cfg.rdapUrl,
    timeoutMs: cfg.timeoutMs,
    now: () => new Date(),
  };
}

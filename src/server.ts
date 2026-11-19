import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { getConfig, defaultDeps } from "./config.js";
import { runCheck, VERSION } from "./guard.js";
import { x402Gate } from "./x402.js";
import type { CheckInput, Deps, Network } from "./types.js";

const MAX_BODY = 16 * 1024;

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*", ...headers });
  res.end(JSON.stringify(body, null, 2));
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw Object.assign(new Error("body too large"), { status: 413 });
    chunks.push(c as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw Object.assign(new Error("invalid JSON"), { status: 400 });
  }
}

export function parseCheckBody(b: any): CheckInput {
  if (!b || typeof b.target !== "string" || !b.target.trim()) throw Object.assign(new Error("`target` (string) is required"), { status: 400 });
  const net = b.network as Network | undefined;
  if (net && !["mainnet", "testnet", "devnet"].includes(net)) throw Object.assign(new Error("`network` must be mainnet|testnet|devnet"), { status: 400 });
  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim().slice(0, 300) : undefined);
  return { target: b.target.trim().slice(0, 2048), contract: str(b.contract), badgeId: str(b.badgeId ?? b.badge), network: net, fetchPage: b.fetchPage !== false };
}

export function buildServer(deps: Deps = defaultDeps(), cfg = getConfig()) {
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "OPTIONS") {
        res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-methods": "POST, GET", "access-control-allow-headers": "content-type, x-payment" });
        return res.end();
      }
      if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { ok: true, version: VERSION, x402: cfg.x402Enabled ? "stub-enabled" : "disabled" });
      if (req.method === "POST" && url.pathname === "/check") {
        const gate = await x402Gate(
          { enabled: cfg.x402Enabled, price: cfg.x402Price, asset: cfg.x402Asset, payTo: cfg.operatorAccount, network: cfg.network },
          "/check",
          req.headers["x-payment"] as string | undefined,
        );
        if (!gate.allowed) return send(res, gate.status, gate.body);
        const input = parseCheckBody(await readJson(req));
        return send(res, 200, await runCheck(input, deps));
      }
      return send(res, 404, { error: "not_found", routes: ["GET /healthz", "POST /check"] });
    } catch (e: any) {
      return send(res, e?.status ?? 500, { error: e?.message ?? "internal error" });
    }
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const cfg = getConfig();
  buildServer(defaultDeps(cfg), cfg).listen(cfg.port, () => {
    console.log(`AirdropGuard API v${VERSION} on http://localhost:${cfg.port}  (POST /check, GET /healthz; network=${cfg.network}; x402=${cfg.x402Enabled ? "stub" : "off"})`);
  });
}

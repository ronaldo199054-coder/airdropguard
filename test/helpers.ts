import type { Deps } from "../src/types.js";

type Route = { match: (url: string) => boolean; status?: number; json?: unknown; text?: string; headers?: Record<string, string> };

/** Deterministic fake fetch: unit tests never hit the network. */
export function mockDeps(routes: Route[], now = "2026-11-19T00:00:00Z"): Deps & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    registryUrl: "https://registry.test",
    rdapUrl: "https://rdap.test",
    timeoutMs: 1000,
    now: () => new Date(now),
    fetch: async (url: string) => {
      calls.push(url);
      const r = routes.find((x) => x.match(url));
      if (!r) throw new Error(`network blocked in test: ${url}`);
      const body = r.json !== undefined ? JSON.stringify(r.json) : r.text ?? "";
      const res = new Response(body, { status: r.status ?? 200, headers: { "content-type": r.json !== undefined ? "application/json" : "text/html", ...(r.headers ?? {}) } });
      Object.defineProperty(res, "url", { value: url });
      return res;
    },
  };
}

export const rdap = (registered: string) => ({ ldhName: "x", events: [{ eventAction: "registration", eventDate: registered }], entities: [] });

/** Shape copied from a real /v1/check-badge/Mf22soLh1NuZYFgBK8iSs response (2026-11-19), trimmed. */
export const VALID_BADGE = {
  token_id: 484,
  token_address: "Mf22soLh1NuZYFgBK8iSs",
  agent_uri: "https://tippingservice.co.uk/agents/vigilonmoltbook/.well-known/agent-card.json",
  on_chain: { owner_account: "4DDvjwdcLmTy1Ar9FCKKPMiABrS261TvyXJGr4n4ypuuogXeFF", status: "Active", agent_uri: "https://tippingservice.co.uk/agents/vigilonmoltbook/.well-known/agent-card.json" },
  checks: { on_chain_agent_found: true, status_active: true, card_fetched: true, hash_matches_on_chain: true, badge_embedding: "legacy" },
  badge_valid: true,
  issues: [{ severity: "warning", field: "embedding", message: "legacy" }],
  network: "mainnet",
};

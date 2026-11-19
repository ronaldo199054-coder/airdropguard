import type { Deps, Evidence, Network } from "../types.js";
import { errMsg, timedFetch } from "../http.js";
import { registrableDomain } from "../normalize.js";

/**
 * Concordium signal: hosted Agent Registry REST, GET /v1/check-badge/{id}.
 * Scoring (from the dev notes): valid + Active badge lowers risk; 409 revoked or card-hash mismatch is a
 * strong warning; 404 / no badge is neutral (most projects have none). It is one signal, not the verdict.
 */
export async function checkBadge(
  badgeId: string,
  deps: Deps,
  opts: { network?: Network; targetDomain?: string } = {},
): Promise<Evidence> {
  const q = opts.network ? `?network=${opts.network}` : "";
  const url = `${deps.registryUrl}/v1/check-badge/${encodeURIComponent(badgeId.trim())}${q}`;
  let res: Response;
  try {
    res = await timedFetch(deps, url, { headers: { accept: "application/json" } });
  } catch (e) {
    return { check: "concordium_badge", status: "unknown", weight: 0, detail: `Agent Registry unreachable (${errMsg(e)}); badge not checked.`, source: url };
  }
  let body: any = null;
  try {
    body = await res.json();
  } catch { /* non-JSON */ }
  const msg = body?.message ? `: ${body.message}` : "";

  switch (res.status) {
    case 404:
      return { check: "concordium_badge", status: "info", weight: 0, detail: `No agent registered at ${badgeId} (404). Neutral: most projects have no Concordium badge.`, source: url };
    case 409:
      return { check: "concordium_badge", status: "fail", weight: 40, critical: true, detail: `Badge ${badgeId} is REVOKED on the Concordium Agent Registry (409)${msg}. Do not trust an agent presenting it.`, source: url };
    case 400:
      return { check: "concordium_badge", status: "warn", weight: 5, detail: `Registry rejected "${badgeId}" as a badge id (400)${msg}. A fake or mistyped badge id.`, source: url };
    case 429:
      return { check: "concordium_badge", status: "unknown", weight: 0, detail: `Agent Registry rate-limited the request (429, Retry-After: ${res.headers.get("retry-after") ?? "?"}s); badge not checked.`, source: url };
  }
  if (!res.ok || !body) {
    return { check: "concordium_badge", status: "unknown", weight: 0, detail: `Agent Registry returned HTTP ${res.status}${msg}; badge not checked.`, source: url };
  }

  // Account form: an account address was given → every badge it owns.
  if (typeof body.agent_count === "number") {
    const valid = body.summary?.valid ?? 0;
    const invalid = body.summary?.invalid ?? 0;
    const data = { network: body.network, account: body.account, agent_count: body.agent_count, valid, invalid };
    if (body.agent_count === 0) return { check: "concordium_badge", status: "info", weight: 0, detail: `Account ${body.account} owns no agent badges on ${body.network}. Neutral.`, source: url, data };
    if (invalid > 0 && valid === 0) return { check: "concordium_badge", status: "warn", weight: 15, detail: `Account owns ${body.agent_count} badge(s) on ${body.network}, none valid.`, source: url, data };
    return { check: "concordium_badge", status: "pass", weight: -10, detail: `Account owns ${valid} valid badge(s) on ${body.network} (${invalid} invalid).`, source: url, data };
  }

  const checks = body.checks ?? {};
  const agentUri: string | undefined = body.agent_uri ?? body.on_chain?.agent_uri;
  const data: Record<string, unknown> = {
    network: body.network,
    token_id: body.token_id,
    token_address: body.token_address,
    badge_valid: body.badge_valid,
    status: body.on_chain?.status,
    owner_account: body.on_chain?.owner_account,
    agent_uri: agentUri,
    hash_matches_on_chain: checks.hash_matches_on_chain,
    badge_embedding: checks.badge_embedding,
    issues: (body.issues ?? []).map((i: any) => `${i.severity}: ${i.field}`),
  };

  if (checks.status_active === false || (body.on_chain?.status && body.on_chain.status !== "Active")) {
    return { check: "concordium_badge", status: "fail", weight: 40, critical: true, detail: `Badge ${badgeId} is not Active on-chain (status ${body.on_chain?.status ?? "unknown"}).`, source: url, data };
  }
  if (checks.hash_matches_on_chain === false) {
    return { check: "concordium_badge", status: "fail", weight: 35, critical: true, detail: `Agent card at ${agentUri} does NOT match the SHA-256 anchored on-chain — the card was altered after registration.`, source: url, data };
  }
  if (body.badge_valid !== true) {
    return { check: "concordium_badge", status: "warn", weight: 10, detail: `Badge ${badgeId} exists but failed validation (${(body.issues ?? []).filter((i: any) => i.severity === "error").map((i: any) => i.message).join("; ") || "see issues"}).`, source: url, data };
  }

  // Valid badge: is it bound to the domain being checked? A real badge "borrowed" by a phishing site is a red flag.
  if (opts.targetDomain && agentUri) {
    let badgeDomain: string | undefined;
    try { badgeDomain = registrableDomain(new URL(agentUri).hostname); } catch { /* ignore */ }
    data.badge_domain = badgeDomain;
    if (badgeDomain && badgeDomain !== opts.targetDomain) {
      return {
        check: "concordium_badge",
        status: "warn",
        weight: 10,
        detail: `Badge ${badgeId} is valid and Active on ${body.network}, but its agent card lives on ${badgeDomain}, not ${opts.targetDomain}. A badge only vouches for its own agent.`,
        source: url,
        data,
      };
    }
  }
  const warnings = (body.issues ?? []).filter((i: any) => i.severity === "warning").length;
  return {
    check: "concordium_badge",
    status: "pass",
    weight: -20,
    detail: `Badge ${badgeId} (token #${body.token_id}) is valid and Active on Concordium ${body.network}; agent card hash matches the on-chain metadata_hash${warnings ? ` (${warnings} non-blocking format warning(s))` : ""}.`,
    source: url,
    data,
  };
}

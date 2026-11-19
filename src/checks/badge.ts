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
    // A mismatch is only evidence of tampering if the owner ever pinned a hash with setAgentURI.
    // The official registry web app writes a RANDOM metadata_hash at registration (app.bundle.js,
    // generateMetadataHashHex), so a never-pinned agent mismatches by default.
    const pinned = await everPinned(deps, body.network ?? opts.network, body.token_id);
    data.hash_ever_pinned = pinned;
    if (pinned === true) {
      return { check: "concordium_badge", status: "fail", weight: 35, critical: true, detail: `Agent card at ${agentUri} does NOT match the SHA-256 the owner pinned on-chain with setAgentURI: the card changed after it was pinned.`, source: url, data };
    }
    if (pinned === false) {
      return { check: "concordium_badge", status: "warn", weight: 10, detail: `Badge ${badgeId} is UNVERIFIED: its card hash was never pinned on-chain (registered without setAgentURI; the registry web app stores a random hash). Not proof of tampering, but the badge vouches for nothing yet.`, source: url, data };
    }
    return { check: "concordium_badge", status: "warn", weight: 20, detail: `Badge ${badgeId} is UNVERIFIED: agent card does not match the on-chain hash, and the registry history could not be read to tell a never-pinned card from an altered one.`, source: url, data };
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

/** true = a URIUpdated event exists after registration; false = only registration events; undefined = unknown. */
async function everPinned(deps: Deps, network: string | undefined, tokenId: unknown): Promise<boolean | undefined> {
  if (tokenId === undefined || tokenId === null || !network) return undefined;
  const url = `${deps.registryUrl}/mcp`;
  try {
    const res = await timedFetch(deps, url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "agent_history", arguments: { network, token_id: Number(tokenId) } } }),
    });
    if (!res.ok) return undefined;
    let raw = await res.text();
    if (raw.startsWith("event:") || raw.includes("\ndata: ") || raw.startsWith("data: ")) {
      raw = raw.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).join("");
    }
    const text = JSON.parse(raw)?.result?.content?.[0]?.text;
    const events: Array<{ event_name?: string }> = JSON.parse(text)?.events;
    if (!Array.isArray(events)) return undefined;
    return events.some((e) => e.event_name === "URIUpdated");
  } catch {
    return undefined;
  }
}

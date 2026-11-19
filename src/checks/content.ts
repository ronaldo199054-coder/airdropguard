import type { Deps, Evidence } from "../types.js";
import { errMsg, timedFetch } from "../http.js";
import { registrableDomain } from "../normalize.js";

interface Rule { id: string; label: string; weight: number; critical?: boolean; patterns: RegExp[] }

export const PHISHING_RULES: Rule[] = [
  {
    id: "secret_request",
    label: "asks for a seed / recovery phrase or private key",
    weight: 35,
    critical: true,
    patterns: [/seed\s*phrase/, /recovery\s*phrase/, /secret\s*recovery/, /private\s*key/, /mnemonic/, /\b(12|24)[-\s]?word/, /助记词/, /私钥/],
  },
  {
    id: "connect_wallet",
    label: "connect-wallet prompt",
    weight: 5,
    patterns: [/connect\s*(your\s*)?wallet/, /wallet\s*connect/, /连接钱包/],
  },
  {
    id: "claim_now",
    label: "claim-now call to action",
    weight: 8,
    patterns: [/claim\s*(now|your|airdrop|tokens|reward)/, /立即领取/, /马上领取/],
  },
  {
    id: "urgency",
    label: "urgency / countdown pressure",
    weight: 10,
    patterns: [/limited\s*time/, /last\s*chance/, /hurry/, /expires?\s*in/, /only\s*\d+\s*(hours?|minutes?|mins?)\s*left/, /countdown/, /倒计时/, /\b\d{1,2}:\d{2}:\d{2}\b.*(left|remaining)/],
  },
  {
    id: "drainer_code",
    label: "token-approval / signature calls often used by wallet drainers",
    weight: 15,
    patterns: [/setapprovalforall/, /eth_signtypeddata/, /permit2/, /increaseallowance/, /seaport/],
  },
];

export interface KeywordHit { id: string; label: string; matches: string[] }

/** Pure keyword scan, exported for tests. Text should be the raw HTML or text of the page. */
export function scanText(raw: string): KeywordHit[] {
  const text = raw.toLowerCase();
  const hits: KeywordHit[] = [];
  for (const r of PHISHING_RULES) {
    const matches = new Set<string>();
    for (const p of r.patterns) {
      const m = text.match(p);
      if (m) matches.add(m[0].slice(0, 60));
    }
    if (matches.size) hits.push({ id: r.id, label: r.label, matches: [...matches] });
  }
  return hits;
}

export function evidenceFromHits(hits: KeywordHit[], source: string): Evidence[] {
  if (!hits.length) {
    return [{ check: "phishing_keywords", status: "pass", weight: 0, detail: "No phishing keywords found on the fetched page.", source }];
  }
  const out: Evidence[] = hits.map((h) => {
    const r = PHISHING_RULES.find((x) => x.id === h.id)!;
    return {
      check: `phishing_keywords.${h.id}`,
      status: r.weight >= 15 ? "fail" : "warn",
      weight: r.weight,
      critical: r.critical,
      detail: `Page ${r.label}: "${h.matches.join('", "')}".`,
      source,
    } as Evidence;
  });
  const ids = new Set(hits.map((h) => h.id));
  if (ids.has("connect_wallet") && (ids.has("urgency") || ids.has("claim_now"))) {
    out.push({ check: "phishing_keywords.combo", status: "warn", weight: 10, detail: "Connect-wallet prompt combined with claim/urgency pressure — the classic airdrop-drainer pattern.", source });
  }
  return out;
}

/** Fetch the page (bounded size) and scan it. Only real fetched content is scored. */
export async function checkPageContent(url: string, deps: Deps): Promise<Evidence[]> {
  let res: Response;
  try {
    res = await timedFetch(deps, url, { redirect: "follow", headers: { accept: "text/html,application/xhtml+xml,*/*;q=0.5" } });
  } catch (e) {
    return [{ check: "page_fetch", status: "unknown", weight: 0, detail: `Could not fetch ${url} (${errMsg(e)}); page content not checked.`, source: url }];
  }
  const out: Evidence[] = [];
  const finalUrl = res.url || url;
  try {
    const from = registrableDomain(new URL(url).hostname);
    const to = registrableDomain(new URL(finalUrl).hostname);
    if (from !== to) {
      out.push({ check: "redirect", status: "warn", weight: 10, detail: `Link redirects off-domain: ${from} → ${to}.`, source: url, data: { finalUrl } });
    }
  } catch { /* ignore */ }
  if (!res.ok) {
    out.push({ check: "page_fetch", status: "unknown", weight: 0, detail: `Page returned HTTP ${res.status}; content not checked.`, source: finalUrl });
    return out;
  }
  const buf = await res.arrayBuffer();
  const text = new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, 1_000_000));
  out.push(...evidenceFromHits(scanText(text), finalUrl));
  return out;
}

import type { Evidence, NormalizedTarget } from "../types.js";
import type { OfficialProject } from "../official.js";
import { registrableDomain, sldLabel } from "../normalize.js";

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** Collapse common visual confusables so "c0ncordlum" and "concordium" share a skeleton. */
export function skeleton(s: string): string {
  return s
    .toLowerCase()
    .replace(/[-_.]/g, "")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/cl/g, "d")
    .replace(/0/g, "o")
    .replace(/[1i|]/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/4/g, "a")
    .replace(/7/g, "t");
}

const AIRDROP_BAIT = ["airdrop", "claim", "reward", "rewards", "bonus", "giveaway", "drop", "free", "eligibility", "eligible", "gift"];

export interface LookalikeHit {
  project: string;
  official: string;
  reason: string;
}

/** Compare one label (domain SLD or X handle) against a brand/official label. */
export function lookalikeReason(label: string, officialLabel: string, brand: string): string | null {
  const l = label.toLowerCase();
  const o = officialLabel.toLowerCase();
  if (l === o) return null;
  const d = levenshtein(l, o);
  if (o.length >= 5 && d <= 2) return `edit distance ${d} from "${o}"`;
  if (skeleton(l) === skeleton(o)) return `visually identical to "${o}" after confusable normalisation`;
  if (brand.length >= 5) {
    const tokens = l.split(/[-_]/).filter(Boolean);
    for (const t of tokens) {
      if (t === brand) return `contains the brand "${brand}" plus extra words`;
      if (levenshtein(t, brand) <= 2 || skeleton(t) === skeleton(brand)) return `contains a misspelling of the brand "${brand}" ("${t}")`;
    }
    const flat = skeleton(l);
    if (flat.includes(skeleton(brand))) return `embeds the brand "${brand}" in a non-official name`;
  }
  return null;
}

export function checkDomainLookalike(t: NormalizedTarget, projects: OfficialProject[]): Evidence[] {
  const out: Evidence[] = [];
  if (!t.hostname || !t.registrableDomain) return out;
  const host = t.hostname;
  const reg = t.registrableDomain;

  for (const p of projects) {
    for (const d of p.domains) {
      if (reg === registrableDomain(d)) {
        out.push({
          check: "official_domain",
          status: "pass",
          weight: -35,
          detail: `${host} is on the official domain list for ${p.name} (${d}).`,
          data: { project: p.name, official: d },
        });
        return out;
      }
    }
  }

  if (host.split(".").some((x) => x.startsWith("xn--"))) {
    out.push({ check: "punycode", status: "warn", weight: 15, detail: `Hostname uses punycode (${host}); internationalised characters are a common homograph trick.` });
  }

  const label = sldLabel(reg);
  const hits: LookalikeHit[] = [];
  for (const p of projects) {
    for (const d of p.domains) {
      const officialLabel = sldLabel(d);
      if (label === officialLabel) {
        hits.push({ project: p.name, official: d, reason: `same name "${label}" on a different TLD (official: ${d})` });
        continue;
      }
      for (const brand of p.brands) {
        const r = lookalikeReason(label, officialLabel, brand);
        if (r) hits.push({ project: p.name, official: d, reason: r });
      }
    }
  }
  if (hits.length) {
    const h = hits[0];
    out.push({
      check: "lookalike_domain",
      status: "fail",
      weight: 40,
      critical: true,
      detail: `${reg} looks like an imitation of ${h.project}'s official domain ${h.official}: ${h.reason}.`,
      data: { matches: hits },
    });
  } else {
    out.push({ check: "lookalike_domain", status: "info", weight: 0, detail: `${reg} does not resemble any domain in the official reference list (${projects.length} projects).` });
  }

  const bait = AIRDROP_BAIT.filter((w) => label.split(/[-_]/).includes(w) || (w.length >= 6 && label.includes(w)));
  if (bait.length) {
    out.push({ check: "bait_words_in_domain", status: "warn", weight: 10, detail: `Domain name contains airdrop bait words: ${bait.join(", ")}.` });
  }
  return out;
}

export function checkXHandle(t: NormalizedTarget, projects: OfficialProject[]): Evidence[] {
  if (!t.handle) return [];
  const h = t.handle.toLowerCase();
  for (const p of projects) {
    if (p.x.some((x) => x.toLowerCase() === h)) {
      return [
        {
          check: "x_handle_official",
          status: "pass",
          weight: -20,
          detail: `@${t.handle} matches the official X handle of ${p.name}. Account age, verification and follower data were not checked (no X API in v0).`,
          data: { project: p.name },
        },
      ];
    }
  }
  const hits: LookalikeHit[] = [];
  for (const p of projects) {
    for (const x of p.x) {
      for (const brand of p.brands) {
        const r = lookalikeReason(h, x, brand);
        if (r) hits.push({ project: p.name, official: "@" + x, reason: r });
      }
    }
  }
  if (hits.length) {
    return [
      {
        check: "x_handle_lookalike",
        status: "fail",
        weight: 40,
        critical: true,
        detail: `@${t.handle} imitates ${hits[0].project}'s official account ${hits[0].official}: ${hits[0].reason}.`,
        data: { matches: hits },
      },
    ];
  }
  return [
    {
      check: "x_handle_lookalike",
      status: "unknown",
      weight: 0,
      detail: `@${t.handle} is not in the official reference list and does not imitate a listed account. Account age/history not checked (no X API in v0).`,
    },
  ];
}

export function checkProjectName(t: NormalizedTarget, projects: OfficialProject[]): Evidence[] {
  if (!t.projectName) return [];
  const n = t.projectName.toLowerCase().replace(/[^a-z0-9]/g, "");
  const p = projects.find((x) => x.name.toLowerCase().replace(/[^a-z0-9]/g, "") === n || x.brands.includes(n));
  if (p) {
    return [
      {
        check: "official_reference",
        status: "info",
        weight: 0,
        detail: `"${t.projectName}" is in the reference list. Only trust airdrop links on ${p.domains.join(", ")} or announced by @${p.x.join(", @")}. Submit the actual link to score it.`,
        data: { project: p.name, domains: p.domains, x: p.x },
      },
    ];
  }
  return [
    {
      check: "official_reference",
      status: "unknown",
      weight: 0,
      detail: `"${t.projectName}" is not in the reference list, so there is no official domain to compare against. Submit the airdrop link itself.`,
    },
  ];
}

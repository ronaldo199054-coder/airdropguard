import type { NormalizedTarget } from "./types.js";

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "com.cn", "net.cn", "org.cn", "com.hk", "org.hk",
  "co.jp", "com.au", "net.au", "com.br", "co.kr", "com.sg", "com.tw", "co.in",
]);

/** Registrable domain (eTLD+1) with a small built-in suffix list. TODO: use the full Public Suffix List. */
export function registrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const last2 = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(last2)) return parts.slice(-3).join(".");
  return last2;
}

/** Second-level label, e.g. "concordium" for "www.concordium.com". */
export function sldLabel(domain: string): string {
  const reg = registrableDomain(domain);
  return reg.split(".")[0];
}

const X_HOSTS = new Set(["x.com", "twitter.com", "www.x.com", "www.twitter.com", "mobile.twitter.com"]);
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;

export function normalizeTarget(input: string): NormalizedTarget {
  const raw = input.trim();
  if (/^@[A-Za-z0-9_]{1,15}$/.test(raw)) return { kind: "x_handle", raw, handle: raw.slice(1) };

  let candidate = raw;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate) && /^[^\s/]+\.[^\s/]+(\/.*)?$/.test(candidate)) {
    candidate = "https://" + candidate;
  }
  try {
    const u = new URL(candidate);
    if (u.protocol === "http:" || u.protocol === "https:") {
      const host = u.hostname.toLowerCase();
      if (X_HOSTS.has(host)) {
        const handle = u.pathname.split("/").filter(Boolean)[0];
        if (handle && /^[A-Za-z0-9_]{1,15}$/.test(handle)) return { kind: "x_handle", raw, handle, url: u.toString() };
      }
      if (DOMAIN_RE.test(host)) {
        const isBare = !/^[a-z]+:\/\//i.test(raw) && (u.pathname === "/" || u.pathname === "") && !u.search;
        return {
          kind: isBare ? "domain" : "url",
          raw,
          url: u.toString(),
          hostname: host,
          registrableDomain: registrableDomain(host),
        };
      }
    }
  } catch {
    /* not a URL */
  }
  return { kind: "project_name", raw, projectName: raw };
}

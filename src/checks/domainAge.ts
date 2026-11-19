import type { Deps, Evidence } from "../types.js";
import { errMsg, timedFetch } from "../http.js";

interface RdapEvent { eventAction?: string; eventDate?: string }
interface RdapEntity { roles?: string[]; vcardArray?: [string, Array<[string, unknown, string, unknown]>] }
interface RdapDomain { ldhName?: string; events?: RdapEvent[]; entities?: RdapEntity[]; status?: string[] }

function registrarName(d: RdapDomain): string | undefined {
  const ent = d.entities?.find((e) => e.roles?.includes("registrar"));
  const fn = ent?.vcardArray?.[1]?.find((x) => x[0] === "fn");
  return typeof fn?.[3] === "string" ? fn[3] : undefined;
}

/** Domain age and registrar via RDAP (the structured successor of WHOIS). Never guesses: failures are "unknown". */
export async function checkDomainAge(domain: string, deps: Deps): Promise<Evidence> {
  const url = `${deps.rdapUrl}/domain/${encodeURIComponent(domain)}`;
  let res: Response;
  try {
    res = await timedFetch(deps, url, { headers: { accept: "application/rdap+json, application/json" }, redirect: "follow" });
  } catch (e) {
    return { check: "domain_age", status: "unknown", weight: 0, detail: `RDAP/WHOIS lookup failed (${errMsg(e)}); domain age unknown.`, source: url };
  }
  if (res.status === 404) {
    return {
      check: "domain_age",
      status: "unknown",
      weight: 0,
      detail: `No RDAP record for ${domain} (domain may be unregistered, or its TLD has no public RDAP); age unknown.`,
      source: url,
    };
  }
  if (!res.ok) {
    return { check: "domain_age", status: "unknown", weight: 0, detail: `RDAP returned HTTP ${res.status}; domain age unknown.`, source: url };
  }
  let body: RdapDomain;
  try {
    body = (await res.json()) as RdapDomain;
  } catch {
    return { check: "domain_age", status: "unknown", weight: 0, detail: "RDAP response was not JSON; domain age unknown.", source: url };
  }
  const reg = body.events?.find((e) => e.eventAction === "registration")?.eventDate;
  const exp = body.events?.find((e) => e.eventAction === "expiration")?.eventDate;
  const registrar = registrarName(body);
  const data: Record<string, unknown> = { registered: reg ?? null, expires: exp ?? null, registrar: registrar ?? null, status: body.status ?? [] };
  if (!reg || Number.isNaN(Date.parse(reg))) {
    return { check: "domain_age", status: "unknown", weight: 0, detail: `RDAP record for ${domain} has no registration date; age unknown.`, source: url, data };
  }
  const ageDays = Math.floor((deps.now().getTime() - Date.parse(reg)) / 86_400_000);
  data.ageDays = ageDays;
  const when = reg.slice(0, 10);
  const by = registrar ? ` via ${registrar}` : "";
  if (ageDays < 30) return { check: "domain_age", status: "fail", weight: 25, detail: `${domain} was registered ${ageDays} day(s) ago (${when}${by}). Brand-new domains are typical for airdrop phishing.`, source: url, data };
  if (ageDays < 180) return { check: "domain_age", status: "warn", weight: 10, detail: `${domain} is young: registered ${ageDays} days ago (${when}${by}).`, source: url, data };
  if (ageDays >= 730) return { check: "domain_age", status: "pass", weight: -10, detail: `${domain} has existed for ${Math.floor(ageDays / 365)} years (registered ${when}${by}).`, source: url, data };
  return { check: "domain_age", status: "info", weight: 0, detail: `${domain} registered ${ageDays} days ago (${when}${by}).`, source: url, data };
}

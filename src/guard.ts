import type { CheckInput, CheckReport, Deps, Evidence } from "./types.js";
import { normalizeTarget } from "./normalize.js";
import { loadOfficialProjects, type OfficialProject } from "./official.js";
import { checkDomainLookalike, checkProjectName, checkXHandle } from "./checks/typosquat.js";
import { checkDomainAge } from "./checks/domainAge.js";
import { checkPageContent } from "./checks/content.js";
import { checkContractFormat } from "./checks/contract.js";
import { checkBadge } from "./checks/badge.js";
import { scoreEvidence } from "./score.js";

export const VERSION = "0.1.0";

export async function runCheck(input: CheckInput, deps: Deps, projects: OfficialProject[] = loadOfficialProjects()): Promise<CheckReport> {
  if (!input?.target || typeof input.target !== "string") throw new Error("target is required");
  const target = normalizeTarget(input.target);
  const evidence: Evidence[] = [];
  const pending: Promise<Evidence | Evidence[]>[] = [];

  if (target.kind === "url" || target.kind === "domain") {
    evidence.push(...checkDomainLookalike(target, projects));
    pending.push(checkDomainAge(target.registrableDomain!, deps));
    if (input.fetchPage !== false) pending.push(checkPageContent(target.url!, deps));
  } else if (target.kind === "x_handle") {
    evidence.push(...checkXHandle(target, projects));
  } else {
    evidence.push(...checkProjectName(target, projects));
  }

  if (input.contract) evidence.push(checkContractFormat(input.contract));

  if (input.badgeId) {
    pending.push(checkBadge(input.badgeId, deps, { network: input.network, targetDomain: target.registrableDomain }));
  } else {
    evidence.push({ check: "concordium_badge", status: "info", weight: 0, detail: "No Concordium agent badge supplied. Neutral: most projects have none." });
  }

  for (const r of await Promise.all(pending)) evidence.push(...(Array.isArray(r) ? r : [r]));

  const { riskScore, verdict, confidence } = scoreEvidence(evidence);
  const top = evidence.filter((e) => e.weight > 0).sort((a, b) => b.weight - a.weight).slice(0, 2).map((e) => e.detail);
  const good = evidence.filter((e) => e.weight < 0).map((e) => e.detail);
  const summary =
    verdict === "likely scam" ? `Likely scam. ${top.join(" ")}`
    : verdict === "suspicious" ? `Suspicious — verify through official channels before connecting a wallet. ${top.join(" ") || "Not enough positive evidence."}`
    : `Likely legit. ${good.slice(0, 2).join(" ")}`;

  return { tool: "AirdropGuard", version: VERSION, checkedAt: deps.now().toISOString(), input, target, riskScore, verdict, confidence, summary: summary.trim(), evidence };
}

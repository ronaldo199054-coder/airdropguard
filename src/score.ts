import type { Evidence, Verdict } from "./types.js";

export const BASE_RISK = 40;
export const THRESHOLDS = { legitBelow: 30, scamFrom: 60 } as const;
export const CRITICAL_FLOOR = 60;

export function scoreEvidence(evidence: Evidence[]): { riskScore: number; verdict: Verdict; confidence: "low" | "medium" | "high" } {
  let score = BASE_RISK + evidence.reduce((s, e) => s + e.weight, 0);
  const critical = evidence.some((e) => e.critical);
  if (critical) score = Math.max(score, CRITICAL_FLOOR);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const verdict: Verdict = score >= THRESHOLDS.scamFrom ? "likely scam" : score < THRESHOLDS.legitBelow ? "likely legit" : "suspicious";
  const informative = evidence.filter((e) => e.status !== "unknown" && e.weight !== 0).length;
  const confidence = critical || informative >= 3 ? "high" : informative >= 1 ? "medium" : "low";
  return { riskScore: score, verdict, confidence };
}

export type EvidenceStatus = "pass" | "warn" | "fail" | "info" | "unknown";

/** One finding. weight > 0 adds risk, weight < 0 lowers risk, 0 is neutral. */
export interface Evidence {
  check: string;
  status: EvidenceStatus;
  weight: number;
  detail: string;
  /** A finding strong enough that the verdict can never be "likely legit". */
  critical?: boolean;
  /** Where the data came from (URL queried). Absent = computed locally from the input. */
  source?: string;
  data?: Record<string, unknown>;
}

export type Network = "mainnet" | "testnet" | "devnet";

export interface CheckInput {
  /** Airdrop link, bare domain, project name, or X handle (@name / x.com/name). */
  target: string;
  /** Optional contract address (EVM 0x… or Concordium <index,subindex>). */
  contract?: string;
  /** Optional Concordium agent badge token address (base58) or Concordium account address. */
  badgeId?: string;
  /** Optional network override for the badge lookup (the registry resolves it from the badge otherwise). */
  network?: Network;
  /** Fetch the page and scan it for phishing content (default true). */
  fetchPage?: boolean;
}

export type TargetKind = "url" | "domain" | "x_handle" | "project_name";

export interface NormalizedTarget {
  kind: TargetKind;
  raw: string;
  url?: string;
  hostname?: string;
  registrableDomain?: string;
  handle?: string;
  projectName?: string;
}

export type Verdict = "likely legit" | "suspicious" | "likely scam";

export interface CheckReport {
  tool: "AirdropGuard";
  version: string;
  checkedAt: string;
  input: CheckInput;
  target: NormalizedTarget;
  riskScore: number;
  verdict: Verdict;
  confidence: "low" | "medium" | "high";
  summary: string;
  evidence: Evidence[];
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface Deps {
  fetch: FetchLike;
  registryUrl: string;
  rdapUrl: string;
  timeoutMs: number;
  now: () => Date;
}

import type { Evidence } from "../types.js";

/** v0: format validation only. Nothing about the contract's behaviour is claimed. */
export function checkContractFormat(contract: string): Evidence {
  const c = contract.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(c)) {
    return { check: "contract", status: "unknown", weight: 0, detail: `EVM address ${c} is well-formed. Deployment age, verification and official-list match are not checked in v0 (TODO: explorer API).`, data: { chain: "evm" } };
  }
  if (/^<?\s*\d+\s*,\s*\d+\s*>?$/.test(c)) {
    return { check: "contract", status: "unknown", weight: 0, detail: `Concordium contract address ${c} is well-formed. On-chain lookup not done in v0 (TODO: gRPC/CCDScan).`, data: { chain: "concordium" } };
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(c)) {
    return { check: "contract", status: "unknown", weight: 0, detail: `${c} looks like a base58 (e.g. Solana) address. Not verified in v0.`, data: { chain: "base58" } };
  }
  return { check: "contract", status: "warn", weight: 5, detail: `"${c}" is not a recognisable contract address format.` };
}

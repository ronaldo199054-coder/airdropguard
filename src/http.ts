import type { Deps } from "./types.js";

export async function timedFetch(deps: Deps, url: string, init: RequestInit = {}): Promise<Response> {
  return deps.fetch(url, {
    ...init,
    signal: AbortSignal.timeout(deps.timeoutMs),
    headers: { "user-agent": "AirdropGuard/0.1 (+hackathon testnet build)", ...(init.headers ?? {}) },
  });
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.name === "TimeoutError" ? "timed out" : e.message;
  return String(e);
}

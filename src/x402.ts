/**
 * x402 paid-API STUB. No payment is created, verified or settled in v0.
 *
 * Intended flow (HTTP 402 "Payment Required" pattern):
 *   1. Client calls POST /check without payment  -> 402 + PaymentRequirements (price, asset, payTo, network).
 *   2. Client pays / signs a payment payload with its own wallet and retries with header `X-PAYMENT: <payload>`.
 *   3. Server verifies the payload (facilitator or own node), runs the check, settles, and returns
 *      `X-PAYMENT-RESPONSE` with the settlement receipt.
 * The operator never holds a client's key; AirdropGuard only receives funds at OPERATOR_ACCOUNT (testnet).
 */

export interface PaymentRequirements {
  scheme: "exact";
  network: string; // e.g. "concordium-testnet"
  maxAmountRequired: string; // decimal string in `asset` units
  asset: string; // "CCD" (TODO: confirm asset id format for the Concordium x402 scheme)
  payTo: string; // OPERATOR_ACCOUNT
  resource: string;
  description: string;
  maxTimeoutSeconds: number;
}

export interface PaymentVerification {
  ok: boolean;
  reason?: string;
  receipt?: string;
}

export interface PaymentVerifier {
  /** TODO(x402): decode X-PAYMENT, check amount/payTo/network/expiry, verify signature with the facilitator. */
  verify(header: string, req: PaymentRequirements): Promise<PaymentVerification>;
  /** TODO(x402): settle on Concordium testnet and return the tx hash for X-PAYMENT-RESPONSE. */
  settle(header: string, req: PaymentRequirements): Promise<PaymentVerification>;
}

export interface X402Config {
  enabled: boolean;
  price: string;
  asset: string;
  payTo: string;
  network: string;
}

export function paymentRequirements(cfg: X402Config, resource: string): PaymentRequirements {
  return {
    scheme: "exact",
    network: `concordium-${cfg.network}`,
    maxAmountRequired: cfg.price,
    asset: cfg.asset,
    payTo: cfg.payTo,
    resource,
    description: "AirdropGuard risk check (one request)",
    maxTimeoutSeconds: 120,
  };
}

/** Placeholder verifier: always refuses, so enabling x402 before it is implemented can't give away free "paid" results by accident. */
export const notImplementedVerifier: PaymentVerifier = {
  async verify() {
    return { ok: false, reason: "x402 verification not implemented in v0 (stub)" };
  },
  async settle() {
    return { ok: false, reason: "x402 settlement not implemented in v0 (stub)" };
  },
};

export type GateResult =
  | { allowed: true; receipt?: string }
  | { allowed: false; status: 402; body: { x402Version: 1; error: string; accepts: PaymentRequirements[] } };

/** Gate one request. With X402_ENABLED=false (default) everything is allowed. */
export async function x402Gate(
  cfg: X402Config,
  resource: string,
  paymentHeader: string | undefined,
  verifier: PaymentVerifier = notImplementedVerifier,
): Promise<GateResult> {
  if (!cfg.enabled) return { allowed: true };
  const req = paymentRequirements(cfg, resource);
  if (!paymentHeader) return { allowed: false, status: 402, body: { x402Version: 1, error: "X-PAYMENT header is required", accepts: [req] } };
  const v = await verifier.verify(paymentHeader, req);
  if (!v.ok) return { allowed: false, status: 402, body: { x402Version: 1, error: v.reason ?? "payment invalid", accepts: [req] } };
  // TODO(x402): settle after the check succeeds, not before.
  return { allowed: true, receipt: v.receipt };
}

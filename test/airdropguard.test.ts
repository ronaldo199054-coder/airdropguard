import { test } from "node:test";
import assert from "node:assert/strict";
import { runCheck } from "../src/guard.js";
import { lookalikeReason, levenshtein } from "../src/checks/typosquat.js";
import { scanText } from "../src/checks/content.js";
import { normalizeTarget } from "../src/normalize.js";
import { x402Gate } from "../src/x402.js";
import { mockDeps, rdap, VALID_BADGE } from "./helpers.js";

const BENIGN_PAGE = "<html><title>Concordium</title><body>Layer-1 blockchain with identity at the protocol level. Developers docs.</body></html>";
const PHISH_PAGE = `<html><body><h1>Concordium Airdrop is LIVE</h1>
<button>Connect Wallet</button> <p>Claim now — only 2 hours left!</p>
<p>Enter your 12-word seed phrase to verify eligibility</p>
<script>contract.setApprovalForAll(attacker,true)</script></body></html>`;

test("1. legit: official domain, old registration, clean page → likely legit", async () => {
  const deps = mockDeps([
    { match: (u) => u.startsWith("https://rdap.test/domain/concordium.com"), json: rdap("2002-04-02T17:49:24Z") },
    { match: (u) => u.startsWith("https://www.concordium.com"), text: BENIGN_PAGE },
  ]);
  const r = await runCheck({ target: "https://www.concordium.com/" }, deps);
  assert.equal(r.verdict, "likely legit");
  assert.ok(r.riskScore < 30, `score ${r.riskScore}`);
  assert.ok(r.evidence.some((e) => e.check === "official_domain" && e.status === "pass"));
  assert.ok(r.evidence.some((e) => e.check === "domain_age" && e.status === "pass"));
});

test("2. typosquat: lookalike domain, 5 days old, drainer page → likely scam", async () => {
  const deps = mockDeps([
    { match: (u) => u.startsWith("https://rdap.test/domain/concordlum-airdrop.xyz"), json: rdap("2026-11-14T08:00:00Z") },
    { match: (u) => u.startsWith("https://concordlum-airdrop.xyz"), text: PHISH_PAGE },
  ]);
  const r = await runCheck({ target: "https://concordlum-airdrop.xyz/claim" }, deps);
  assert.equal(r.verdict, "likely scam");
  assert.ok(r.riskScore >= 90, `score ${r.riskScore}`);
  const ids = r.evidence.map((e) => e.check);
  for (const id of ["lookalike_domain", "domain_age", "phishing_keywords.secret_request", "phishing_keywords.combo", "bait_words_in_domain"]) {
    assert.ok(ids.includes(id), `missing ${id}`);
  }
});

test("3a. badge valid + Active (shape of real Mf22soLh1NuZYFgBK8iSs) lowers risk", async () => {
  const deps = mockDeps([{ match: (u) => u.startsWith("https://registry.test/v1/check-badge/Mf22soLh1NuZYFgBK8iSs"), json: VALID_BADGE }]);
  const r = await runCheck({ target: "VigilOnMoltbook", badgeId: "Mf22soLh1NuZYFgBK8iSs" }, deps);
  const b = r.evidence.find((e) => e.check === "concordium_badge")!;
  assert.equal(b.status, "pass");
  assert.equal(b.weight, -20);
});

test("3b. badge revoked (409) → critical, never 'likely legit' even on official domain", async () => {
  const deps = mockDeps([
    { match: (u) => u.includes("/v1/check-badge/"), status: 409, json: { error: "revoked", message: "agent is revoked" } },
    { match: (u) => u.startsWith("https://rdap.test/"), json: rdap("2002-04-02T17:49:24Z") },
  ]);
  const r = await runCheck({ target: "concordium.com", badgeId: "Mf22soLh1NuZYFgBK8iSs", fetchPage: false }, deps);
  const b = r.evidence.find((e) => e.check === "concordium_badge")!;
  assert.equal(b.status, "fail");
  assert.equal(b.critical, true);
  assert.notEqual(r.verdict, "likely legit");
  assert.ok(r.riskScore >= 60);
});

test("3c. badge 404 is neutral; hash mismatch is a strong warning; borrowed badge is flagged", async () => {
  const d404 = mockDeps([{ match: (u) => u.includes("/v1/check-badge/"), status: 404, json: { error: "not_found" } }]);
  const r404 = await runCheck({ target: "SomeProject", badgeId: "Mf22soLh1NuZYFgBK8iSs" }, d404);
  assert.equal(r404.evidence.find((e) => e.check === "concordium_badge")!.weight, 0);

  const mismatch = { ...VALID_BADGE, badge_valid: false, checks: { ...VALID_BADGE.checks, hash_matches_on_chain: false } };
  const dmm = mockDeps([{ match: (u) => u.includes("/v1/check-badge/"), json: mismatch }]);
  const rmm = await runCheck({ target: "SomeProject", badgeId: "Mf22soLh1NuZYFgBK8iSs" }, dmm);
  const bm = rmm.evidence.find((e) => e.check === "concordium_badge")!;
  assert.equal(bm.status, "fail");
  assert.equal(bm.critical, true);

  const dborrow = mockDeps([
    { match: (u) => u.includes("/v1/check-badge/"), json: VALID_BADGE },
    { match: (u) => u.startsWith("https://rdap.test/"), status: 404, json: {} },
  ]);
  const rb = await runCheck({ target: "claim-agent.io", badgeId: "Mf22soLh1NuZYFgBK8iSs", fetchPage: false }, dborrow);
  const bb = rb.evidence.find((e) => e.check === "concordium_badge")!;
  assert.equal(bb.status, "warn");
  assert.match(bb.detail, /tippingservice\.co\.uk/);
});

test("unknowns stay unknown: RDAP + page fetch failures are reported, not invented", async () => {
  const deps = mockDeps([]); // every request throws
  const r = await runCheck({ target: "https://example-unknown-project.io/drop" }, deps);
  assert.equal(r.evidence.find((e) => e.check === "domain_age")!.status, "unknown");
  assert.equal(r.evidence.find((e) => e.check === "page_fetch")!.status, "unknown");
});

test("helpers: similarity, keyword scan, input normalisation, x402 stub", async () => {
  assert.equal(levenshtein("concordium", "concordlum"), 1);
  assert.ok(lookalikeReason("c0ncordium", "concordium", "concordium"));
  assert.ok(lookalikeReason("concordium-claim", "concordium", "concordium"));
  assert.equal(lookalikeReason("example", "concordium", "concordium"), null);
  assert.deepEqual(scanText("Please enter your seed phrase").map((h) => h.id), ["secret_request"]);
  assert.equal(normalizeTarget("@ConcordiumNet").kind, "x_handle");
  assert.equal(normalizeTarget("https://x.com/ConcordiumNet").handle, "ConcordiumNet");
  assert.equal(normalizeTarget("concordium.com").kind, "domain");
  assert.equal(normalizeTarget("Concordium").kind, "project_name");
  const off = await x402Gate({ enabled: false, price: "0.01", asset: "CCD", payTo: "3bUU", network: "testnet" }, "/check", undefined);
  assert.equal(off.allowed, true);
  const on = await x402Gate({ enabled: true, price: "0.01", asset: "CCD", payTo: "3bUU", network: "testnet" }, "/check", undefined);
  assert.equal(on.allowed, false);
});

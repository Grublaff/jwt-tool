import { test } from "node:test";
import assert from "node:assert/strict";
import { annotateClaims, isExpired } from "../src/claims.js";

test("annotateClaims surfaces iat/exp/nbf as ISO timestamps", () => {
  const a = annotateClaims({ iat: 1700000000, exp: 1700003600, nbf: 1699999000, sub: "x" });
  assert.equal(a.iat_iso, new Date(1700000000 * 1000).toISOString());
  assert.equal(a.exp_iso, new Date(1700003600 * 1000).toISOString());
  assert.equal(a.nbf_iso, new Date(1699999000 * 1000).toISOString());
});

test("annotateClaims ignores non-timestamp claims", () => {
  const a = annotateClaims({ sub: "x", role: "admin" });
  assert.equal(a.iat_iso, undefined);
});

test("isExpired returns true when exp < now", () => {
  assert.equal(isExpired({ exp: 1000 }, 2000), true);
});

test("isExpired returns false when exp > now", () => {
  assert.equal(isExpired({ exp: 3000 }, 2000), false);
});

test("isExpired returns false when exp is missing", () => {
  assert.equal(isExpired({}, 2000), false);
});

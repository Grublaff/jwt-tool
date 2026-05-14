import { test } from "node:test";
import assert from "node:assert/strict";
import { decode } from "../src/codec.js";

// Header: {"alg":"HS256","typ":"JWT"}
// Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
const FIXTURE =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

test("decode returns header, payload, signature for a valid token", () => {
  const r = decode(FIXTURE);
  assert.equal(r.error, undefined);
  assert.deepEqual(r.header, { alg: "HS256", typ: "JWT" });
  assert.equal(r.payload.sub, "1234567890");
  assert.equal(r.payload.name, "John Doe");
  assert.equal(r.payload.iat, 1516239022);
  assert.equal(r.signature, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
  assert.equal(r.raw.length, 3);
});

test("decode returns error for non-string input", () => {
  assert.match(decode(null).error, /three dot-separated segments/);
  assert.match(decode(42).error, /three dot-separated segments/);
});

test("decode returns error for tokens without three segments", () => {
  assert.match(decode("a.b").error, /three dot-separated segments/);
  assert.match(decode("a.b.c.d").error, /three dot-separated segments/);
});

test("decode returns error for non-base64 segments", () => {
  assert.match(decode("!!!.!!!.!!!").error, /Failed to decode/);
});

test("decode returns error when header/payload are not JSON", () => {
  // base64url("not json").base64url("not json").sig
  const t = "bm90IGpzb24.bm90IGpzb24.sig";
  assert.match(decode(t).error, /Failed to decode/);
});

import { verify } from "../src/codec.js";
import { fixture, HMAC_ALGS, ASYM_ALGS } from "./fixtures.js";

for (const alg of [...HMAC_ALGS, ...ASYM_ALGS]) {
  test(`verify accepts a valid ${alg} token`, async () => {
    const { token, verifyKey } = await fixture(alg);
    const r = await verify(token, verifyKey);
    assert.equal(r.ok, true);
    assert.equal(r.payload.sub, "test");
  });

  test(`verify rejects a tampered ${alg} token`, async () => {
    const { token, verifyKey } = await fixture(alg);
    const parts = token.split(".");
    // Replace the payload with a different one; keep the original signature
    const bad = parts[0] + "." + Buffer.from(JSON.stringify({ sub: "evil" })).toString("base64url") + "." + parts[2];
    const r = await verify(bad, verifyKey);
    assert.equal(r.ok, false);
    assert.ok(r.error);
  });
}

test("verify reports unsigned tokens (alg=none) as not ok", async () => {
  // "alg":"none" — header.payload. (empty signature)
  const t = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";
  const r = await verify(t, null);
  assert.equal(r.ok, false);
});

import { sign } from "../src/codec.js";

for (const alg of [...HMAC_ALGS, ...ASYM_ALGS]) {
  test(`sign + decode round-trips for ${alg}`, async () => {
    const { signKey, verifyKey } = await fixture(alg);
    const r = await sign({
      header: { alg, typ: "JWT" },
      payload: { sub: "round-trip", iat: 1700000000 },
      key: signKey,
    });
    assert.equal(r.error, undefined);
    assert.ok(r.token);
    const v = await verify(r.token, verifyKey);
    assert.equal(v.ok, true);
    assert.equal(v.payload.sub, "round-trip");
  });
}

test("sign returns error when key does not match alg", async () => {
  const { signKey } = await fixture("HS256");
  const r = await sign({
    header: { alg: "RS256", typ: "JWT" },
    payload: { sub: "x" },
    key: signKey,
  });
  assert.ok(r.error);
});

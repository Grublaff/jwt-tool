import { test } from "node:test";
import assert from "node:assert/strict";
import { exportSPKI, exportPKCS8, exportJWK, generateKeyPair } from "jose";
import { parseKey } from "../src/keys.js";
import { sign } from "../src/codec.js";

test("parseKey: HMAC plain string", async () => {
  const k = await parseKey("super-secret-test-value-32-bytes!", "HS256", { base64: false });
  const r = await sign({ alg: "HS256" }, { x: 1 }, k);
  assert.equal(r.error, undefined);
});

test("parseKey: HMAC base64-encoded string", async () => {
  const raw = Buffer.from("hello world this is a secret!!").toString("base64");
  const k = await parseKey(raw, "HS256", { base64: true });
  const r = await sign({ alg: "HS256" }, { x: 1 }, k);
  assert.equal(r.error, undefined);
});

test("parseKey: SPKI PEM public key (RS256)", async () => {
  const kp = await generateKeyPair("RS256", { extractable: true });
  const pem = await exportSPKI(kp.publicKey);
  const k = await parseKey(pem, "RS256");
  assert.ok(k);
});

test("parseKey: PKCS8 PEM private key (RS256)", async () => {
  const kp = await generateKeyPair("RS256", { extractable: true });
  const pem = await exportPKCS8(kp.privateKey);
  const k = await parseKey(pem, "RS256");
  const r = await sign({ alg: "RS256" }, { x: 1 }, k);
  assert.equal(r.error, undefined);
});

test("parseKey: JWK JSON public key (ES256)", async () => {
  const kp = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(kp.publicKey);
  const k = await parseKey(JSON.stringify(jwk), "ES256");
  assert.ok(k);
});

test("parseKey: empty input rejects", async () => {
  await assert.rejects(() => parseKey("", "HS256"));
  await assert.rejects(() => parseKey("   ", "HS256"));
});

test("parseKey: malformed PEM rejects", async () => {
  await assert.rejects(() => parseKey("not a real key", "RS256"));
});

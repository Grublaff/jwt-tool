import { importJWK, importPKCS8, importSPKI } from "jose";

const enc = new TextEncoder();

/**
 * Turn user-pasted text into a key suitable for jose.
 *
 * - HS* algs: text is the secret. If opts.base64 is true, base64-decode first.
 * - RS* / PS* / ES* / Ed25519:
 *     * starts with -----BEGIN PUBLIC KEY----- → importSPKI
 *     * starts with -----BEGIN PRIVATE KEY---- → importPKCS8
 *     * else JSON.parse + importJWK
 *
 * @param {string} text
 * @param {string} alg
 * @param {{base64?: boolean}} [opts]
 * @returns {Promise<Uint8Array | CryptoKey | object>}
 */
export async function parseKey(text, alg, opts = {}) {
  if (typeof text !== "string" || text.trim() === "") {
    throw new Error("Key is empty");
  }
  if (alg.startsWith("HS")) {
    if (opts.base64) {
      const stripped = text.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
      const padded = stripped + "=".repeat((4 - (stripped.length % 4)) % 4);
      return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    }
    return enc.encode(text);
  }
  const trimmed = text.trim();
  if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
    return importSPKI(trimmed, alg);
  }
  if (trimmed.startsWith("-----BEGIN PRIVATE KEY-----")) {
    return importPKCS8(trimmed, alg);
  }
  if (trimmed.startsWith("-----BEGIN ")) {
    // Some other PEM type (X.509 certificate, PKCS#1, EC PRIVATE KEY, ENCRYPTED, …)
    throw new Error("Unsupported PEM type — use SPKI public key or PKCS8 private key");
  }
  let jwk;
  try {
    jwk = JSON.parse(trimmed);
  } catch {
    throw new Error("Key is not a recognised PEM or JWK");
  }
  return importJWK(jwk, alg);
}

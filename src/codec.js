import { base64url, jwtVerify } from "jose";

const dec = new TextDecoder();

/**
 * Decode a JWS-format JWT into its three parts without verifying the signature.
 * Never throws — returns { error } on bad input.
 *
 * @param {string} token
 * @returns {{header: object, payload: object, signature: string, raw: [string,string,string]} | {error: string}}
 */
export function decode(token) {
  if (typeof token !== "string" || token.split(".").length !== 3) {
    return { error: "Token must have three dot-separated segments" };
  }
  try {
    const [rawHeader, rawPayload, rawSignature] = token.split(".");
    const header = JSON.parse(dec.decode(base64url.decode(rawHeader)));
    const payload = JSON.parse(dec.decode(base64url.decode(rawPayload)));
    return { header, payload, signature: rawSignature, raw: [rawHeader, rawPayload, rawSignature] };
  } catch (e) {
    return { error: "Failed to decode: " + e.message };
  }
}

/**
 * Verify a JWT signature with the supplied key.
 * Never throws — returns { ok: false, error } on any failure including alg=none.
 *
 * @param {string} token
 * @param {CryptoKey|Uint8Array|object} key  CryptoKey, raw HMAC bytes, or a JWK
 * @param {{algorithms?: string[]}} [opts]
 * @returns {Promise<{ok:true, alg:string, payload:object} | {ok:false, alg?:string, error:string}>}
 */
export async function verify(token, key, opts = {}) {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, key, opts);
    return { ok: true, alg: protectedHeader.alg, payload };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

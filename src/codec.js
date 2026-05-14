import { base64url, jwtVerify, SignJWT } from "jose";

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
 * @returns {Promise<{ok:true, alg:string, payload:object} | {ok:false, error:string}>}
 */
export async function verify(token, key, opts = {}) {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, key, opts);
    return { ok: true, alg: protectedHeader.alg, payload };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Sign a JWT. The header object is used verbatim as the protected header
 * (caller controls alg, typ, kid). Payload used as-is.
 *
 * For alg "none", assembles an unsigned JWS Unencoded Payload manually
 * because jose.SignJWT refuses to sign with alg: none.
 *
 * @param {object} header
 * @param {object} payload
 * @param {CryptoKey | Uint8Array | object | null} key  Ignored when alg is "none"
 * @returns {Promise<{token:string} | {error:string}>}
 */
export async function sign(header, payload, key) {
  try {
    if (header && header.alg === "none") {
      const h = base64url.encode(JSON.stringify(header));
      const p = base64url.encode(JSON.stringify(payload));
      return { token: `${h}.${p}.` };
    }
    const token = await new SignJWT(payload).setProtectedHeader(header).sign(key);
    return { token };
  } catch (e) {
    return { error: e.message };
  }
}

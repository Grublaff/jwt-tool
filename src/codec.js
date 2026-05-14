import { base64url } from "jose";

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

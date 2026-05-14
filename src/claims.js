const TIMESTAMP_KEYS = ["iat", "exp", "nbf"];

/**
 * Return a shallow copy of `payload` with `<key>_iso` fields added for any
 * numeric claim in TIMESTAMP_KEYS.
 *
 * @param {object} payload
 */
export function annotateClaims(payload) {
  const out = { ...payload };
  for (const k of TIMESTAMP_KEYS) {
    if (typeof payload[k] === "number") {
      out[`${k}_iso`] = new Date(payload[k] * 1000).toISOString();
    }
  }
  return out;
}

/**
 * @param {object} payload
 * @param {number} [nowSec] — defaults to current time in seconds
 */
export function isExpired(payload, nowSec) {
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  return typeof payload.exp === "number" && payload.exp < now;
}

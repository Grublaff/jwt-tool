const TIMESTAMP_KEYS = ["iat", "exp", "nbf"];

/**
 * Return a shallow copy of `payload` with `<key>_iso` fields added for any
 * finite numeric claim in TIMESTAMP_KEYS. Non-numeric or NaN values are
 * silently ignored (RFC 7519 §2 defines these as JSON numbers; we don't
 * coerce strings or guess).
 *
 * @param {object} payload
 * @returns {object}
 */
export function annotateClaims(payload) {
  const out = { ...payload };
  for (const k of TIMESTAMP_KEYS) {
    if (Number.isFinite(payload[k])) {
      out[`${k}_iso`] = new Date(payload[k] * 1000).toISOString();
    }
  }
  return out;
}

/**
 * RFC 7519 §4.1.4: the current date/time MUST be **before** `exp`. So
 * `exp === now` is treated as expired.
 *
 * @param {object} payload
 * @param {number} [nowSec] — defaults to current time in seconds
 * @returns {boolean}
 */
export function isExpired(payload, nowSec) {
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  return Number.isFinite(payload.exp) && payload.exp <= now;
}

/**
 * RFC 7519 §4.1.5: the JWT MUST NOT be processed before `nbf`. So
 * `nbf > now` means "not yet valid".
 *
 * @param {object} payload
 * @param {number} [nowSec] — defaults to current time in seconds
 * @returns {boolean}
 */
export function isNotYetValid(payload, nowSec) {
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  return Number.isFinite(payload.nbf) && payload.nbf > now;
}

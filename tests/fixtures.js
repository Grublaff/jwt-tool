import { generateKeyPair, generateSecret, SignJWT } from "jose";

/**
 * Generate a fresh key + a JWT signed with it for the given alg.
 * Returns { token, signKey, verifyKey }.
 */
export async function fixture(alg) {
  let signKey, verifyKey;
  if (alg.startsWith("HS")) {
    signKey = await generateSecret(alg, { extractable: true });
    verifyKey = signKey;
  } else {
    const kp = await generateKeyPair(alg, { extractable: true });
    signKey = kp.privateKey;
    verifyKey = kp.publicKey;
  }
  const token = await new SignJWT({ sub: "test", iat: 1700000000 })
    .setProtectedHeader({ alg, typ: "JWT" })
    .sign(signKey);
  return { token, signKey, verifyKey };
}

export const ASYM_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "Ed25519"];
export const HMAC_ALGS = ["HS256", "HS384", "HS512"];

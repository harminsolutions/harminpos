// All hashing here uses the Web Crypto API, which is built into
// Cloudflare Workers -- no external packages needed.

const PBKDF2_ITERATIONS = 100000; // Workers' Web Crypto implementation caps PBKDF2 at 100,000 -- this is the platform maximum, not a security choice

function bufferToHex(buffer) {
  return Array.from(buffer).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// ---- Passwords ----

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  // Store salt alongside the hash -- both are needed to verify later.
  return `${bufferToHex(salt)}:${bufferToHex(new Uint8Array(hashBuffer))}`;
}

export async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const salt = hexToBuffer(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufferToHex(new Uint8Array(hashBuffer)) === hashHex;
}

// ---- OTP codes ----

export function generateOTP() {
  const values = crypto.getRandomValues(new Uint32Array(6));
  return Array.from(values, (v) => v % 10).join("");
}

export async function hashOTP(otp) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(otp));
  return bufferToHex(new Uint8Array(hashBuffer));
}

// ---- Session tokens (signed, self-verifying -- no sessions table) ----

async function hmacSign(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bufferToHex(new Uint8Array(sig));
}

export async function createSessionToken(userId, secret) {
  const payload = JSON.stringify({ uid: userId, exp: Date.now() + 12 * 60 * 60 * 1000 }); // 12 hour session
  const payloadB64 = btoa(payload);
  const sig = await hmacSign(payloadB64, secret);
  return `${payloadB64}.${sig}`;
}

export async function verifySessionToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [payloadB64, sig] = token.split(".");
  const expectedSig = await hmacSign(payloadB64, secret);
  if (sig !== expectedSig) return null; // tampered or forged
  const payload = JSON.parse(atob(payloadB64));
  if (payload.exp < Date.now()) return null; // expired
  return payload.uid;
}

// ---- Trusted device tokens ----

export function generateDeviceToken() {
  return bufferToHex(crypto.getRandomValues(new Uint8Array(32)));
}
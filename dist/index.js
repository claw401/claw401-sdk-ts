import nacl2 from 'tweetnacl';
import { PublicKey } from '@solana/web3.js';

var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/utils.ts
var PROTOCOL_VERSION = "x401/1.0";
var DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1e3;
var DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1e3;
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16);
    if (isNaN(byte)) throw new Error(`Invalid hex byte at position ${i}`);
    bytes[i / 2] = byte;
  }
  return bytes;
}
function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  return btoa(String.fromCharCode(...bytes));
}
function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function stringToBytes(str) {
  return new TextEncoder().encode(str);
}
function generateNonce() {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    const nodeCrypto = __require("crypto");
    const buf = nodeCrypto.randomBytes(32);
    bytes.set(buf);
  }
  return bytesToHex(bytes);
}
async function sha256Hex(data) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hashBuffer));
}
async function deriveSessionId(nonce, publicKey, domain, createdAt) {
  const raw = `${nonce}:${publicKey}:${domain}:${createdAt}`;
  return sha256Hex(stringToBytes(raw));
}
async function deriveAttestationId(agentKey, operatorKey, issuedAt, nonce) {
  const raw = `${agentKey}:${operatorKey}:${issuedAt}:${nonce}`;
  return sha256Hex(stringToBytes(raw));
}
function canonicalize(obj) {
  const sorted = sortObjectKeys(obj);
  return stringToBytes(JSON.stringify(sorted));
}
function sortObjectKeys(obj) {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  const sorted = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortObjectKeys(obj[key]);
  }
  return sorted;
}

// src/auth.ts
function generateChallenge(options) {
  const { domain, ttlMs = DEFAULT_CHALLENGE_TTL_MS } = options;
  if (!domain || domain.trim() === "") {
    throw new Claw401AuthError("INVALID_DOMAIN", "Domain must not be empty");
  }
  const now = Date.now();
  return {
    nonce: generateNonce(),
    domain: domain.trim().toLowerCase(),
    issuedAt: now,
    expiresAt: now + ttlMs,
    version: PROTOCOL_VERSION
  };
}
function verifySignature(options) {
  const { signedChallenge, expectedDomain, nonceCache, clockSkewMs = 3e4 } = options;
  const { challenge, signature, publicKey } = signedChallenge;
  const now = Date.now();
  if (now > challenge.expiresAt + clockSkewMs) {
    return failure("CHALLENGE_EXPIRED", "Challenge has expired");
  }
  if (challenge.issuedAt > now + clockSkewMs) {
    return failure("CHALLENGE_NOT_YET_VALID", "Challenge issuedAt is in the future");
  }
  if (challenge.domain !== expectedDomain.trim().toLowerCase()) {
    return failure("INVALID_DOMAIN", "Domain mismatch");
  }
  if (nonceCache.has(challenge.nonce)) {
    return failure("NONCE_REPLAYED", "Nonce has already been used");
  }
  let pubkeyBytes;
  try {
    const pk = new PublicKey(publicKey);
    pubkeyBytes = pk.toBytes();
  } catch {
    return failure("INVALID_PUBLIC_KEY", "Invalid Solana public key");
  }
  const payload = canonicalize(challenge);
  let sigBytes;
  try {
    sigBytes = base64ToBytes(signature);
  } catch {
    return failure("ENCODING_ERROR", "Signature is not valid base64");
  }
  const valid = nacl2.sign.detached.verify(payload, sigBytes, pubkeyBytes);
  if (!valid) {
    return failure("INVALID_SIGNATURE", "Signature verification failed");
  }
  nonceCache.set(challenge.nonce);
  return { valid: true, publicKey };
}
function challengeSigningBytes(challenge) {
  return canonicalize(challenge);
}
function encodeSignature(signatureBytes) {
  return bytesToBase64(signatureBytes);
}
var InMemoryNonceCache = class {
  cache = /* @__PURE__ */ new Map();
  ttlMs;
  constructor(ttlMs = DEFAULT_CHALLENGE_TTL_MS * 2) {
    this.ttlMs = ttlMs;
  }
  has(nonce) {
    return this.cache.has(nonce);
  }
  set(nonce) {
    this.evict();
    this.cache.set(nonce, Date.now());
  }
  evict() {
    const cutoff = Date.now() - this.ttlMs;
    for (const [nonce, ts] of this.cache) {
      if (ts < cutoff) this.cache.delete(nonce);
    }
  }
};
var Claw401AuthError = class extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = "Claw401AuthError";
  }
};
function failure(code, reason) {
  return { valid: false, publicKey: null, reason, errorCode: code };
}

// src/session.ts
async function createSession(input) {
  const { publicKey, domain, nonce, options = {} } = input;
  const { scopes = ["read"], ttlMs = DEFAULT_SESSION_TTL_MS } = options;
  const createdAt = Date.now();
  const expiresAt = createdAt + ttlMs;
  const sessionId = await deriveSessionId(nonce, publicKey, domain, createdAt);
  return {
    sessionId,
    publicKey,
    scopes,
    domain,
    createdAt,
    expiresAt,
    nonce
  };
}
function verifySession(options) {
  const { session, expectedDomain, requiredScopes = [], clockSkewMs = 3e4 } = options;
  if (Date.now() > session.expiresAt + clockSkewMs) {
    return { valid: false, session: null, reason: "Session has expired" };
  }
  if (session.domain !== expectedDomain.trim().toLowerCase()) {
    return { valid: false, session: null, reason: "Session domain mismatch" };
  }
  for (const required of requiredScopes) {
    if (!session.scopes.includes(required)) {
      return {
        valid: false,
        session: null,
        reason: `Missing required scope: ${required}`
      };
    }
  }
  return { valid: true, session };
}
function serializeSession(session) {
  return JSON.stringify(session);
}
function deserializeSession(raw) {
  return JSON.parse(raw);
}
async function signProof(options) {
  const { type, issuerPublicKey, subject, claims, issuerSecretKey, ttlMs } = options;
  if (issuerSecretKey.length !== 64) {
    throw new Error("issuerSecretKey must be 64 bytes (Ed25519 secret + public)");
  }
  const now = Date.now();
  const payload = {
    type,
    issuer: issuerPublicKey,
    subject,
    claims,
    issuedAt: now,
    ...ttlMs !== void 0 ? { expiresAt: now + ttlMs } : {},
    nonce: generateNonce(),
    version: PROTOCOL_VERSION
  };
  const payloadBytes = canonicalize(payload);
  const sigBytes = nacl2.sign.detached(payloadBytes, issuerSecretKey);
  return { ...payload, signature: bytesToBase64(sigBytes) };
}
function verifyProof(options) {
  const { proof, clockSkewMs = 3e4 } = options;
  if (proof.expiresAt !== void 0 && Date.now() > proof.expiresAt + clockSkewMs) {
    return { valid: false, proof: null, reason: "Proof has expired" };
  }
  let pubkeyBytes;
  try {
    pubkeyBytes = new PublicKey(proof.issuer).toBytes();
  } catch {
    return { valid: false, proof: null, reason: "Invalid issuer public key" };
  }
  const { signature, ...payloadFields } = proof;
  const payloadBytes = canonicalize(payloadFields);
  let sigBytes;
  try {
    sigBytes = base64ToBytes(signature);
  } catch {
    return { valid: false, proof: null, reason: "Invalid signature encoding" };
  }
  const valid = nacl2.sign.detached.verify(payloadBytes, sigBytes, pubkeyBytes);
  if (!valid) {
    return { valid: false, proof: null, reason: "Signature verification failed" };
  }
  return { valid: true, proof };
}
async function createAgentAttestation(options) {
  const { agentKey, operatorKey, operatorSecretKey, agentId, capabilities, ttlMs } = options;
  if (operatorSecretKey.length !== 64) {
    throw new Error("operatorSecretKey must be 64 bytes (Ed25519 secret + public)");
  }
  const now = Date.now();
  const nonce = generateNonce();
  const attestationId = await deriveAttestationId(agentKey, operatorKey, now, nonce);
  const payload = {
    attestationId,
    agentKey,
    operatorKey,
    capabilities,
    agentId,
    issuedAt: now,
    ...ttlMs !== void 0 ? { expiresAt: now + ttlMs } : {},
    nonce,
    version: PROTOCOL_VERSION
  };
  const payloadBytes = canonicalize(payload);
  const sigBytes = nacl2.sign.detached(payloadBytes, operatorSecretKey);
  return { ...payload, signature: bytesToBase64(sigBytes) };
}
function verifyAgentAttestation(options) {
  const { attestation, expectedOperatorKey, clockSkewMs = 3e4 } = options;
  if (attestation.expiresAt !== void 0 && Date.now() > attestation.expiresAt + clockSkewMs) {
    return { valid: false, attestation: null, reason: "Attestation has expired" };
  }
  if (expectedOperatorKey && attestation.operatorKey !== expectedOperatorKey) {
    return { valid: false, attestation: null, reason: "Operator key mismatch" };
  }
  let operatorPubkeyBytes;
  try {
    operatorPubkeyBytes = new PublicKey(attestation.operatorKey).toBytes();
  } catch {
    return { valid: false, attestation: null, reason: "Invalid operator public key" };
  }
  const { signature, ...payloadFields } = attestation;
  const payloadBytes = canonicalize(payloadFields);
  let sigBytes;
  try {
    sigBytes = base64ToBytes(signature);
  } catch {
    return { valid: false, attestation: null, reason: "Invalid signature encoding" };
  }
  const valid = nacl2.sign.detached.verify(payloadBytes, sigBytes, operatorPubkeyBytes);
  if (!valid) {
    return { valid: false, attestation: null, reason: "Signature verification failed" };
  }
  return { valid: true, attestation };
}
function serializeAttestation(attestation) {
  return Buffer.from(JSON.stringify(attestation)).toString("base64");
}
function deserializeAttestation(encoded) {
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
}

export { DEFAULT_CHALLENGE_TTL_MS, DEFAULT_SESSION_TTL_MS, InMemoryNonceCache, PROTOCOL_VERSION, base64ToBytes, bytesToBase64, bytesToHex, canonicalize, challengeSigningBytes, createAgentAttestation, createSession, deriveAttestationId, deriveSessionId, deserializeAttestation, deserializeSession, encodeSignature, generateChallenge, generateNonce, hexToBytes, serializeAttestation, serializeSession, sha256Hex, signProof, stringToBytes, verifyAgentAttestation, verifyProof, verifySession, verifySignature };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map
/**
 * Challenge generation and signature verification.
 *
 * Implements the X401 challenge-response flow:
 *   1. Server calls generateChallenge() → sends to client
 *   2. Client signs the canonical challenge payload
 *   3. Server calls verifySignature() with the signed result
 *
 * Security invariants:
 *   - Challenges are domain-bound: a signature for domain A is invalid for domain B
 *   - Challenges expire after DEFAULT_CHALLENGE_TTL_MS
 *   - Replay protection is enforced via an external nonce cache (caller-supplied)
 *   - Private keys never touch this module
 */

import nacl from "tweetnacl";
import { PublicKey } from "@solana/web3.js";
import {
  Challenge,
  SignedChallenge,
  Claw401ErrorCode,
} from "./types.js";
import {
  PROTOCOL_VERSION,
  DEFAULT_CHALLENGE_TTL_MS,
  generateNonce,
  base64ToBytes,
  bytesToBase64,
  canonicalize,
} from "./utils.js";

/** Options for challenge generation. */
export interface GenerateChallengeOptions {
  /** Domain that must be present in the signed payload. Required. */
  domain: string;
  /** TTL in milliseconds. Defaults to 5 minutes. */
  ttlMs?: number;
}

/**
 * Generates a time-bound, domain-scoped authentication challenge.
 *
 * The returned challenge must be sent to the client. The client signs
 * canonicalize(challenge) with their Ed25519 wallet key.
 */
export function generateChallenge(options: GenerateChallengeOptions): Challenge {
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
    version: PROTOCOL_VERSION,
  };
}

/** Options for verifySignature. */
export interface VerifySignatureOptions {
  signedChallenge: SignedChallenge;
  /** Expected domain. Must match exactly (after lowercase trim). */
  expectedDomain: string;
  /**
   * Nonce replay cache. The caller must persist this between requests.
   * verify() will call markUsed() after a successful verification.
   */
  nonceCache: NonceCache;
  /** Acceptable clock skew in ms. Defaults to 30 seconds. */
  clockSkewMs?: number;
}

export interface NonceCache {
  /** Returns true if this nonce has already been used. */
  has(nonce: string): boolean;
  /** Marks a nonce as used. */
  set(nonce: string): void;
}

/** Result of a signature verification. */
export interface VerifySignatureResult {
  valid: boolean;
  publicKey: string | null;
  reason?: string;
  errorCode?: Claw401ErrorCode;
}

/**
 * Verifies a signed challenge.
 *
 * Checks, in order:
 *   1. Challenge has not expired
 *   2. Domain matches expected domain
 *   3. Nonce has not been replayed
 *   4. Signature is a valid Ed25519 signature over the canonical challenge payload
 *   5. Signing key matches the stated public key
 *
 * On success, the nonce is marked as used in the provided cache.
 */
export function verifySignature(options: VerifySignatureOptions): VerifySignatureResult {
  const { signedChallenge, expectedDomain, nonceCache, clockSkewMs = 30_000 } = options;
  const { challenge, signature, publicKey } = signedChallenge;

  // 1. Expiry check with clock skew tolerance
  const now = Date.now();
  if (now > challenge.expiresAt + clockSkewMs) {
    return failure("CHALLENGE_EXPIRED", "Challenge has expired");
  }
  if (challenge.issuedAt > now + clockSkewMs) {
    return failure("CHALLENGE_NOT_YET_VALID", "Challenge issuedAt is in the future");
  }

  // 2. Domain binding
  if (challenge.domain !== expectedDomain.trim().toLowerCase()) {
    return failure("INVALID_DOMAIN", "Domain mismatch");
  }

  // 3. Replay protection
  if (nonceCache.has(challenge.nonce)) {
    return failure("NONCE_REPLAYED", "Nonce has already been used");
  }

  // 4. Validate public key format
  let pubkeyBytes: Uint8Array;
  try {
    const pk = new PublicKey(publicKey);
    pubkeyBytes = pk.toBytes();
  } catch {
    return failure("INVALID_PUBLIC_KEY", "Invalid Solana public key");
  }

  // 5. Reconstruct canonical signed payload and verify signature
  const payload = canonicalize(challenge as unknown as Record<string, unknown>);
  let sigBytes: Uint8Array;
  try {
    sigBytes = base64ToBytes(signature);
  } catch {
    return failure("ENCODING_ERROR", "Signature is not valid base64");
  }

  const valid = nacl.sign.detached.verify(payload, sigBytes, pubkeyBytes);
  if (!valid) {
    return failure("INVALID_SIGNATURE", "Signature verification failed");
  }

  // Mark nonce as consumed — must be called after all checks pass
  nonceCache.set(challenge.nonce);

  return { valid: true, publicKey };
}

/**
 * Produces the canonical bytes that a client should sign for a given challenge.
 * Expose this so client-side tooling can produce the exact same payload.
 */
export function challengeSigningBytes(challenge: Challenge): Uint8Array {
  return canonicalize(challenge as unknown as Record<string, unknown>);
}

/**
 * Helper: base64-encode a raw signature for inclusion in SignedChallenge.
 */
export function encodeSignature(signatureBytes: Uint8Array): string {
  return bytesToBase64(signatureBytes);
}

// ---------------------------------------------------------------------------
// In-memory nonce cache (for development / single-process servers)
// ---------------------------------------------------------------------------

/**
 * Simple in-memory LRU-style nonce cache with TTL eviction.
 *
 * For production use, replace with a distributed cache (Redis, etc.)
 * that persists across process restarts and horizontal replicas.
 *
 * Evicts entries older than `ttlMs` on every `set()` call.
 */
export class InMemoryNonceCache implements NonceCache {
  private readonly cache = new Map<string, number>();
  private readonly ttlMs: number;

  constructor(ttlMs = DEFAULT_CHALLENGE_TTL_MS * 2) {
    this.ttlMs = ttlMs;
  }

  has(nonce: string): boolean {
    return this.cache.has(nonce);
  }

  set(nonce: string): void {
    this.evict();
    this.cache.set(nonce, Date.now());
  }

  private evict(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [nonce, ts] of this.cache) {
      if (ts < cutoff) this.cache.delete(nonce);
    }
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

class Claw401AuthError extends Error {
  constructor(
    public readonly code: Claw401ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "Claw401AuthError";
  }
}

function failure(code: Claw401ErrorCode, reason: string): VerifySignatureResult {
  return { valid: false, publicKey: null, reason, errorCode: code };
}

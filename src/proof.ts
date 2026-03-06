/**
 * Signed capability and identity proofs.
 *
 * A Proof is a signed statement from an issuer about a subject.
 * Proofs are self-contained: they carry the issuer's public key and a signature
 * over the canonical payload, so any verifier can validate them independently.
 *
 * Use cases:
 *   - Capability delegation: issuer grants subject permission to perform actions
 *   - Identity attestation: issuer asserts facts about a subject
 *   - Cross-service trust: service A issues proof, service B verifies without calling A
 */

import nacl from "tweetnacl";
import { PublicKey } from "@solana/web3.js";
import { Proof, ProofPayload } from "./types.js";
import {
  PROTOCOL_VERSION,
  generateNonce,
  base64ToBytes,
  bytesToBase64,
  canonicalize,
} from "./utils.js";

export interface SignProofOptions {
  type: Proof["type"];
  /** Issuer's base58 public key. */
  issuerPublicKey: string;
  /** Subject identifier (public key or opaque ID). */
  subject: string;
  /** Arbitrary claims to include in the proof. */
  claims: Record<string, unknown>;
  /** Issuer's Ed25519 secret key (64 bytes: secret + public). */
  issuerSecretKey: Uint8Array;
  /** Optional TTL in ms. If omitted, proof never expires. */
  ttlMs?: number;
}

/**
 * Signs a capability or identity proof.
 *
 * The payload (everything except `signature`) is canonicalized and signed
 * with the issuer's Ed25519 secret key.
 *
 * SECURITY: The secret key is used ephemerally in this function and is not stored.
 * Callers should ensure the key material is zeroed after use.
 */
export async function signProof(options: SignProofOptions): Promise<Proof> {
  const { type, issuerPublicKey, subject, claims, issuerSecretKey, ttlMs } = options;

  // Validate key length — Ed25519 secret key is 64 bytes (seed + public)
  if (issuerSecretKey.length !== 64) {
    throw new Error("issuerSecretKey must be 64 bytes (Ed25519 secret + public)");
  }

  const now = Date.now();
  const payload: ProofPayload = {
    type,
    issuer: issuerPublicKey,
    subject,
    claims,
    issuedAt: now,
    ...(ttlMs !== undefined ? { expiresAt: now + ttlMs } : {}),
    nonce: generateNonce(),
    version: PROTOCOL_VERSION,
  };

  const payloadBytes = canonicalize(payload as unknown as Record<string, unknown>);
  const sigBytes = nacl.sign.detached(payloadBytes, issuerSecretKey);

  return { ...payload, signature: bytesToBase64(sigBytes) };
}

export interface VerifyProofOptions {
  proof: Proof;
  /** Clock skew tolerance in ms. Defaults to 30 seconds. */
  clockSkewMs?: number;
}

export interface VerifyProofResult {
  valid: boolean;
  proof: Proof | null;
  reason?: string;
}

/**
 * Verifies a signed proof.
 *
 * Checks:
 *   1. Proof has not expired (if expiresAt is set)
 *   2. Signature is valid Ed25519 over the canonical payload
 *   3. Signing key matches issuer field
 */
export function verifyProof(options: VerifyProofOptions): VerifyProofResult {
  const { proof, clockSkewMs = 30_000 } = options;

  // 1. Expiry
  if (proof.expiresAt !== undefined && Date.now() > proof.expiresAt + clockSkewMs) {
    return { valid: false, proof: null, reason: "Proof has expired" };
  }

  // 2. Validate issuer public key
  let pubkeyBytes: Uint8Array;
  try {
    pubkeyBytes = new PublicKey(proof.issuer).toBytes();
  } catch {
    return { valid: false, proof: null, reason: "Invalid issuer public key" };
  }

  // 3. Reconstruct payload (everything except signature)
  const { signature, ...payloadFields } = proof;
  const payloadBytes = canonicalize(payloadFields as unknown as Record<string, unknown>);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64ToBytes(signature);
  } catch {
    return { valid: false, proof: null, reason: "Invalid signature encoding" };
  }

  const valid = nacl.sign.detached.verify(payloadBytes, sigBytes, pubkeyBytes);
  if (!valid) {
    return { valid: false, proof: null, reason: "Signature verification failed" };
  }

  return { valid: true, proof };
}

/**
 * Agent attestation module.
 *
 * An AgentAttestation is an operator-signed document that:
 *   - Binds an agent's public key to a declared set of capabilities
 *   - Allows downstream services to verify the agent is authorized
 *   - Can be attached to MCP tool calls as a verifiable identity proof
 *
 * Flow:
 *   1. Operator calls createAgentAttestation() with the agent's key and capabilities
 *   2. Agent includes the attestation in outbound requests (e.g., MCP context header)
 *   3. Recipient calls verifyAgentAttestation() to validate the attestation
 *
 * The operator's signature covers: agentKey, operatorKey, capabilities, agentId,
 * issuedAt, expiresAt, nonce, version — all canonicalized.
 */

import nacl from "tweetnacl";
import { PublicKey } from "@solana/web3.js";
import {
  AgentAttestation,
  AgentAttestationPayload,
  AgentCapabilities,
  AgentVerificationResult,
} from "./types.js";
import {
  PROTOCOL_VERSION,
  generateNonce,
  base64ToBytes,
  bytesToBase64,
  canonicalize,
  deriveAttestationId,
} from "./utils.js";

export interface CreateAgentAttestationOptions {
  /** Agent's public key (base58). */
  agentKey: string;
  /** Operator's public key (base58). */
  operatorKey: string;
  /** Operator's Ed25519 secret key (64 bytes). */
  operatorSecretKey: Uint8Array;
  /** Human-readable agent identifier (e.g., "claw401-agent-001"). */
  agentId: string;
  /** Capabilities this attestation grants. */
  capabilities: AgentCapabilities;
  /** Optional TTL in ms. If omitted, attestation does not expire. */
  ttlMs?: number;
}

/**
 * Creates and signs an agent attestation.
 *
 * Called by the operator (the party that owns/deploys the agent).
 * The operator signs over the full payload with their Ed25519 key.
 */
export async function createAgentAttestation(
  options: CreateAgentAttestationOptions,
): Promise<AgentAttestation> {
  const { agentKey, operatorKey, operatorSecretKey, agentId, capabilities, ttlMs } = options;

  if (operatorSecretKey.length !== 64) {
    throw new Error("operatorSecretKey must be 64 bytes (Ed25519 secret + public)");
  }

  const now = Date.now();
  const nonce = generateNonce();
  const attestationId = await deriveAttestationId(agentKey, operatorKey, now, nonce);

  const payload: AgentAttestationPayload = {
    attestationId,
    agentKey,
    operatorKey,
    capabilities,
    agentId,
    issuedAt: now,
    ...(ttlMs !== undefined ? { expiresAt: now + ttlMs } : {}),
    nonce,
    version: PROTOCOL_VERSION,
  };

  const payloadBytes = canonicalize(payload as unknown as Record<string, unknown>);
  const sigBytes = nacl.sign.detached(payloadBytes, operatorSecretKey);

  return { ...payload, signature: bytesToBase64(sigBytes) };
}

export interface VerifyAgentAttestationOptions {
  attestation: AgentAttestation;
  /**
   * Expected operator key. If provided, the attestation's operatorKey
   * must match. Use this to pin the attestation to a known operator.
   */
  expectedOperatorKey?: string;
  /** Clock skew tolerance in ms. Defaults to 30 seconds. */
  clockSkewMs?: number;
}

/**
 * Verifies an agent attestation.
 *
 * Checks:
 *   1. Attestation has not expired (if expiresAt is set)
 *   2. Operator key matches expectedOperatorKey (if provided)
 *   3. Signature is valid Ed25519 over the canonical payload
 */
export function verifyAgentAttestation(
  options: VerifyAgentAttestationOptions,
): AgentVerificationResult {
  const { attestation, expectedOperatorKey, clockSkewMs = 30_000 } = options;

  // 1. Expiry check
  if (attestation.expiresAt !== undefined && Date.now() > attestation.expiresAt + clockSkewMs) {
    return { valid: false, attestation: null, reason: "Attestation has expired" };
  }

  // 2. Operator key pinning
  if (expectedOperatorKey && attestation.operatorKey !== expectedOperatorKey) {
    return { valid: false, attestation: null, reason: "Operator key mismatch" };
  }

  // 3. Validate operator public key format
  let operatorPubkeyBytes: Uint8Array;
  try {
    operatorPubkeyBytes = new PublicKey(attestation.operatorKey).toBytes();
  } catch {
    return { valid: false, attestation: null, reason: "Invalid operator public key" };
  }

  // 4. Reconstruct payload and verify signature
  const { signature, ...payloadFields } = attestation;
  const payloadBytes = canonicalize(payloadFields as unknown as Record<string, unknown>);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64ToBytes(signature);
  } catch {
    return { valid: false, attestation: null, reason: "Invalid signature encoding" };
  }

  const valid = nacl.sign.detached.verify(payloadBytes, sigBytes, operatorPubkeyBytes);
  if (!valid) {
    return { valid: false, attestation: null, reason: "Signature verification failed" };
  }

  return { valid: true, attestation };
}

/**
 * Extracts and serializes an attestation for injection into an MCP tool call context.
 * The returned string can be placed in a request header (e.g., X-Agent-Attestation).
 */
export function serializeAttestation(attestation: AgentAttestation): string {
  return Buffer.from(JSON.stringify(attestation)).toString("base64");
}

/**
 * Deserializes an attestation from an MCP context header value.
 * Does not validate — call verifyAgentAttestation() after deserialization.
 */
export function deserializeAttestation(encoded: string): AgentAttestation {
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as AgentAttestation;
}

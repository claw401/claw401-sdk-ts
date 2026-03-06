/**
 * Session issuance and verification.
 *
 * A session is issued after successful challenge verification.
 * Sessions are:
 *   - Domain-scoped
 *   - Wallet-bound (publicKey)
 *   - Scope-limited
 *   - Tied to the originating nonce (prevents session forgery via nonce substitution)
 *   - Identified by a deterministic session ID
 */

import {
  Session,
  CreateSessionOptions,
  SessionVerificationResult,
  SessionScope,
} from "./types.js";
import {
  DEFAULT_SESSION_TTL_MS,
  deriveSessionId,
} from "./utils.js";

/** Input required to create a session (output from successful verifySignature). */
export interface CreateSessionInput {
  publicKey: string;
  domain: string;
  /** The nonce from the originating challenge. */
  nonce: string;
  options?: CreateSessionOptions;
}

/**
 * Creates an authenticated session after a successful signature verification.
 *
 * The session ID is deterministic: sha256(nonce + publicKey + domain + createdAt).
 * This means sessions can be reconstructed from their inputs — useful for debugging
 * and distributed session stores that don't persist the full struct.
 */
export async function createSession(input: CreateSessionInput): Promise<Session> {
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
    nonce,
  };
}

/** Options for session verification. */
export interface VerifySessionOptions {
  session: Session;
  /** Domain the session must be bound to. */
  expectedDomain: string;
  /** Required scopes. If provided, all listed scopes must be present. */
  requiredScopes?: SessionScope[];
  /** Clock skew tolerance in ms. Defaults to 30 seconds. */
  clockSkewMs?: number;
}

/**
 * Verifies a session is valid for the given domain and scope requirements.
 */
export function verifySession(options: VerifySessionOptions): SessionVerificationResult {
  const { session, expectedDomain, requiredScopes = [], clockSkewMs = 30_000 } = options;

  // 1. Expiry
  if (Date.now() > session.expiresAt + clockSkewMs) {
    return { valid: false, session: null, reason: "Session has expired" };
  }

  // 2. Domain binding
  if (session.domain !== expectedDomain.trim().toLowerCase()) {
    return { valid: false, session: null, reason: "Session domain mismatch" };
  }

  // 3. Scope check
  for (const required of requiredScopes) {
    if (!session.scopes.includes(required)) {
      return {
        valid: false,
        session: null,
        reason: `Missing required scope: ${required}`,
      };
    }
  }

  return { valid: true, session };
}

/**
 * Serializes a session for storage or transmission.
 * Returns a JSON string — callers are responsible for encryption at rest.
 */
export function serializeSession(session: Session): string {
  return JSON.stringify(session);
}

/**
 * Deserializes a session from its JSON representation.
 * Does not validate — call verifySession() after deserialization.
 */
export function deserializeSession(raw: string): Session {
  return JSON.parse(raw) as Session;
}

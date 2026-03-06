/**
 * Core type definitions for the Claw401 X401 authentication protocol.
 */

/** Supported cryptographic curve identifiers. */
export type CurveType = "ed25519";

/** A base58-encoded Solana wallet public key. */
export type PublicKey = string;

/** Hex-encoded byte string. */
export type HexString = string;

/** Base64-encoded byte string. */
export type Base64String = string;

/** ISO 8601 timestamp string. */
export type ISOTimestamp = string;

// ---------------------------------------------------------------------------
// Challenge
// ---------------------------------------------------------------------------

/** An authentication challenge issued by the server. */
export interface Challenge {
  /** Unique nonce for this challenge (32-byte hex). */
  nonce: HexString;
  /** Domain this challenge is bound to (e.g. "app.example.com"). */
  domain: string;
  /** Challenge issuance time (Unix ms). */
  issuedAt: number;
  /** Challenge expiry time (Unix ms). */
  expiresAt: number;
  /** Protocol version. */
  version: string;
}

/** The signed message format that the client must sign. */
export interface ChallengePayload {
  nonce: HexString;
  domain: string;
  issuedAt: number;
  expiresAt: number;
  version: string;
}

/** A challenge bundled with its signature submitted for verification. */
export interface SignedChallenge {
  /** The original challenge. */
  challenge: Challenge;
  /** Base58 or base64 encoded signature bytes. */
  signature: string;
  /** Signer's public key. */
  publicKey: PublicKey;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/** Scope of permissions granted in a session. */
export type SessionScope = "read" | "write" | "admin" | "agent" | string;

/** An authenticated session issued after successful challenge verification. */
export interface Session {
  /** Deterministic session identifier. */
  sessionId: string;
  /** Authenticated wallet address. */
  publicKey: PublicKey;
  /** Scopes granted to this session. */
  scopes: SessionScope[];
  /** Domain this session is bound to. */
  domain: string;
  /** Session creation time (Unix ms). */
  createdAt: number;
  /** Session expiry time (Unix ms). */
  expiresAt: number;
  /** The nonce from the originating challenge (replay protection). */
  nonce: HexString;
}

/** Options for creating a session. */
export interface CreateSessionOptions {
  scopes?: SessionScope[];
  /** TTL in milliseconds. Defaults to 24 hours. */
  ttlMs?: number;
}

/** Result of a session verification. */
export interface SessionVerificationResult {
  valid: boolean;
  session: Session | null;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/** A signed capability or identity proof. */
export interface Proof {
  /** Proof type identifier. */
  type: "capability" | "identity" | "delegation";
  /** Issuer's public key. */
  issuer: PublicKey;
  /** Subject (target) public key or identifier. */
  subject: string;
  /** Claims carried in this proof (arbitrary key/value). */
  claims: Record<string, unknown>;
  /** Issuance time (Unix ms). */
  issuedAt: number;
  /** Optional expiry (Unix ms). */
  expiresAt?: number;
  /** Nonce to prevent replay. */
  nonce: HexString;
  /** Proof signature (base64). */
  signature: Base64String;
  /** Protocol version. */
  version: string;
}

/** Unsigned proof payload (used as signing input). */
export type ProofPayload = Omit<Proof, "signature">;

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/** Declared capabilities for an autonomous agent. */
export interface AgentCapabilities {
  /** Human-readable capability names. */
  actions: string[];
  /** Resources the agent can access. */
  resources?: string[];
  /** Optional MCP tool names. */
  mcpTools?: string[];
}

/** An attestation binding a key to an agent identity. */
export interface AgentAttestation {
  /** Attestation identifier. */
  attestationId: string;
  /** Agent's public key. */
  agentKey: PublicKey;
  /** Upstream operator's public key. */
  operatorKey: PublicKey;
  /** Declared agent capabilities. */
  capabilities: AgentCapabilities;
  /** Human-readable agent identifier. */
  agentId: string;
  /** Issuance time (Unix ms). */
  issuedAt: number;
  /** Optional expiry (Unix ms). */
  expiresAt?: number;
  /** Nonce for replay protection. */
  nonce: HexString;
  /** Attestation signature from operator key (base64). */
  signature: Base64String;
  /** Protocol version. */
  version: string;
}

/** Payload signed to create an agent attestation. */
export type AgentAttestationPayload = Omit<AgentAttestation, "signature">;

/** Result of verifying an agent attestation. */
export interface AgentVerificationResult {
  valid: boolean;
  attestation: AgentAttestation | null;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type Claw401ErrorCode =
  | "CHALLENGE_EXPIRED"
  | "CHALLENGE_NOT_YET_VALID"
  | "INVALID_SIGNATURE"
  | "INVALID_DOMAIN"
  | "NONCE_REPLAYED"
  | "SESSION_EXPIRED"
  | "SESSION_INVALID"
  | "PROOF_EXPIRED"
  | "PROOF_INVALID"
  | "ATTESTATION_INVALID"
  | "ATTESTATION_EXPIRED"
  | "INVALID_PUBLIC_KEY"
  | "ENCODING_ERROR"
  | "UNKNOWN";

export interface Claw401Error {
  code: Claw401ErrorCode;
  message: string;
}

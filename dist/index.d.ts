/**
 * Core type definitions for the Claw401 X401 authentication protocol.
 */
/** Supported cryptographic curve identifiers. */
type CurveType = "ed25519";
/** A base58-encoded Solana wallet public key. */
type PublicKey = string;
/** Hex-encoded byte string. */
type HexString = string;
/** Base64-encoded byte string. */
type Base64String = string;
/** ISO 8601 timestamp string. */
type ISOTimestamp = string;
/** An authentication challenge issued by the server. */
interface Challenge {
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
interface ChallengePayload {
    nonce: HexString;
    domain: string;
    issuedAt: number;
    expiresAt: number;
    version: string;
}
/** A challenge bundled with its signature submitted for verification. */
interface SignedChallenge {
    /** The original challenge. */
    challenge: Challenge;
    /** Base58 or base64 encoded signature bytes. */
    signature: string;
    /** Signer's public key. */
    publicKey: PublicKey;
}
/** Scope of permissions granted in a session. */
type SessionScope = "read" | "write" | "admin" | "agent" | string;
/** An authenticated session issued after successful challenge verification. */
interface Session {
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
interface CreateSessionOptions {
    scopes?: SessionScope[];
    /** TTL in milliseconds. Defaults to 24 hours. */
    ttlMs?: number;
}
/** Result of a session verification. */
interface SessionVerificationResult {
    valid: boolean;
    session: Session | null;
    reason?: string;
}
/** A signed capability or identity proof. */
interface Proof {
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
type ProofPayload = Omit<Proof, "signature">;
/** Declared capabilities for an autonomous agent. */
interface AgentCapabilities {
    /** Human-readable capability names. */
    actions: string[];
    /** Resources the agent can access. */
    resources?: string[];
    /** Optional MCP tool names. */
    mcpTools?: string[];
}
/** An attestation binding a key to an agent identity. */
interface AgentAttestation {
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
type AgentAttestationPayload = Omit<AgentAttestation, "signature">;
/** Result of verifying an agent attestation. */
interface AgentVerificationResult {
    valid: boolean;
    attestation: AgentAttestation | null;
    reason?: string;
}
type Claw401ErrorCode = "CHALLENGE_EXPIRED" | "CHALLENGE_NOT_YET_VALID" | "INVALID_SIGNATURE" | "INVALID_DOMAIN" | "NONCE_REPLAYED" | "SESSION_EXPIRED" | "SESSION_INVALID" | "PROOF_EXPIRED" | "PROOF_INVALID" | "ATTESTATION_INVALID" | "ATTESTATION_EXPIRED" | "INVALID_PUBLIC_KEY" | "ENCODING_ERROR" | "UNKNOWN";
interface Claw401Error {
    code: Claw401ErrorCode;
    message: string;
}

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

/** Options for challenge generation. */
interface GenerateChallengeOptions {
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
declare function generateChallenge(options: GenerateChallengeOptions): Challenge;
/** Options for verifySignature. */
interface VerifySignatureOptions {
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
interface NonceCache {
    /** Returns true if this nonce has already been used. */
    has(nonce: string): boolean;
    /** Marks a nonce as used. */
    set(nonce: string): void;
}
/** Result of a signature verification. */
interface VerifySignatureResult {
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
declare function verifySignature(options: VerifySignatureOptions): VerifySignatureResult;
/**
 * Produces the canonical bytes that a client should sign for a given challenge.
 * Expose this so client-side tooling can produce the exact same payload.
 */
declare function challengeSigningBytes(challenge: Challenge): Uint8Array;
/**
 * Helper: base64-encode a raw signature for inclusion in SignedChallenge.
 */
declare function encodeSignature(signatureBytes: Uint8Array): string;
/**
 * Simple in-memory LRU-style nonce cache with TTL eviction.
 *
 * For production use, replace with a distributed cache (Redis, etc.)
 * that persists across process restarts and horizontal replicas.
 *
 * Evicts entries older than `ttlMs` on every `set()` call.
 */
declare class InMemoryNonceCache implements NonceCache {
    private readonly cache;
    private readonly ttlMs;
    constructor(ttlMs?: number);
    has(nonce: string): boolean;
    set(nonce: string): void;
    private evict;
}

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

/** Input required to create a session (output from successful verifySignature). */
interface CreateSessionInput {
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
declare function createSession(input: CreateSessionInput): Promise<Session>;
/** Options for session verification. */
interface VerifySessionOptions {
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
declare function verifySession(options: VerifySessionOptions): SessionVerificationResult;
/**
 * Serializes a session for storage or transmission.
 * Returns a JSON string — callers are responsible for encryption at rest.
 */
declare function serializeSession(session: Session): string;
/**
 * Deserializes a session from its JSON representation.
 * Does not validate — call verifySession() after deserialization.
 */
declare function deserializeSession(raw: string): Session;

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

interface SignProofOptions {
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
declare function signProof(options: SignProofOptions): Promise<Proof>;
interface VerifyProofOptions {
    proof: Proof;
    /** Clock skew tolerance in ms. Defaults to 30 seconds. */
    clockSkewMs?: number;
}
interface VerifyProofResult {
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
declare function verifyProof(options: VerifyProofOptions): VerifyProofResult;

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

interface CreateAgentAttestationOptions {
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
declare function createAgentAttestation(options: CreateAgentAttestationOptions): Promise<AgentAttestation>;
interface VerifyAgentAttestationOptions {
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
declare function verifyAgentAttestation(options: VerifyAgentAttestationOptions): AgentVerificationResult;
/**
 * Extracts and serializes an attestation for injection into an MCP tool call context.
 * The returned string can be placed in a request header (e.g., X-Agent-Attestation).
 */
declare function serializeAttestation(attestation: AgentAttestation): string;
/**
 * Deserializes an attestation from an MCP context header value.
 * Does not validate — call verifyAgentAttestation() after deserialization.
 */
declare function deserializeAttestation(encoded: string): AgentAttestation;

/**
 * Low-level encoding, hashing, and nonce utilities.
 * These are the deterministic building blocks referenced throughout the protocol.
 */

/** Protocol version string injected into all signed payloads. */
declare const PROTOCOL_VERSION = "x401/1.0";
/** Default challenge TTL: 5 minutes. */
declare const DEFAULT_CHALLENGE_TTL_MS: number;
/** Default session TTL: 24 hours. */
declare const DEFAULT_SESSION_TTL_MS: number;
/** Encodes a Uint8Array to a lowercase hex string. */
declare function bytesToHex(bytes: Uint8Array): HexString;
/** Decodes a hex string to a Uint8Array. */
declare function hexToBytes(hex: HexString): Uint8Array;
/** Encodes a Uint8Array to a base64 string. */
declare function bytesToBase64(bytes: Uint8Array): Base64String;
/** Decodes a base64 string to a Uint8Array. */
declare function base64ToBytes(b64: Base64String): Uint8Array;
/** Encodes a string to UTF-8 bytes. */
declare function stringToBytes(str: string): Uint8Array;
/**
 * Generates a cryptographically random 32-byte nonce as a hex string.
 * Uses the platform's CSPRNG (crypto.getRandomValues in browser, crypto module in Node).
 */
declare function generateNonce(): HexString;
/**
 * SHA-256 hash of arbitrary bytes.
 * Returns hex-encoded digest.
 * Uses Web Crypto API (Node 18+ and all modern browsers).
 */
declare function sha256Hex(data: Uint8Array): Promise<HexString>;
/**
 * Deterministic session ID derived from: nonce + publicKey + domain + createdAt.
 * This is not a secret — it is a canonical identifier.
 */
declare function deriveSessionId(nonce: HexString, publicKey: string, domain: string, createdAt: number): Promise<string>;
/**
 * Deterministic attestation ID derived from: agentKey + operatorKey + issuedAt + nonce.
 */
declare function deriveAttestationId(agentKey: string, operatorKey: string, issuedAt: number, nonce: HexString): Promise<string>;
/**
 * Produces a canonical UTF-8 byte representation of a signing payload.
 * All fields are sorted by key to ensure deterministic ordering.
 *
 * This is the canonical serialization: JSON.stringify with sorted keys.
 * Never use this output for anything other than signing — it is not a display format.
 */
declare function canonicalize(obj: Record<string, unknown>): Uint8Array;

export { type AgentAttestation, type AgentAttestationPayload, type AgentCapabilities, type AgentVerificationResult, type Base64String, type Challenge, type ChallengePayload, type Claw401Error, type Claw401ErrorCode, type CreateAgentAttestationOptions, type CreateSessionInput, type CreateSessionOptions, type CurveType, DEFAULT_CHALLENGE_TTL_MS, DEFAULT_SESSION_TTL_MS, type GenerateChallengeOptions, type HexString, type ISOTimestamp, InMemoryNonceCache, type NonceCache, PROTOCOL_VERSION, type Proof, type ProofPayload, type PublicKey, type Session, type SessionScope, type SessionVerificationResult, type SignProofOptions, type SignedChallenge, type VerifyAgentAttestationOptions, type VerifyProofOptions, type VerifyProofResult, type VerifySessionOptions, type VerifySignatureOptions, type VerifySignatureResult, base64ToBytes, bytesToBase64, bytesToHex, canonicalize, challengeSigningBytes, createAgentAttestation, createSession, deriveAttestationId, deriveSessionId, deserializeAttestation, deserializeSession, encodeSignature, generateChallenge, generateNonce, hexToBytes, serializeAttestation, serializeSession, sha256Hex, signProof, stringToBytes, verifyAgentAttestation, verifyProof, verifySession, verifySignature };

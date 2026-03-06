/**
 * @claw401/sdk
 *
 * TypeScript SDK for the Claw401 X401 wallet authentication protocol.
 *
 * Exports are organized by domain:
 *   - auth:    Challenge generation, signature verification
 *   - session: Session issuance and verification
 *   - proof:   Signed capability and identity proofs
 *   - agent:   Agent attestation (create + verify)
 *   - utils:   Encoding, nonce, hashing utilities
 *   - types:   All TypeScript interfaces and type aliases
 */

export * from "./auth.js";
export * from "./session.js";
export * from "./proof.js";
export * from "./agent.js";
export * from "./utils.js";
export * from "./types.js";

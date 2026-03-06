# @claw401/sdk

TypeScript SDK for the Claw401 X401 wallet authentication protocol.

## Install

```bash
npm install @claw401/sdk
# or
pnpm add @claw401/sdk
```

## Overview

Claw401 is a deterministic wallet authentication protocol for Solana. This SDK implements:

- Challenge-response authentication (X401 standard)
- Domain-scoped session issuance
- Signed capability proofs
- Agent attestation for autonomous systems

## Usage

### Server-side: Generate a challenge

```typescript
import { generateChallenge, verifySignature, InMemoryNonceCache } from "@claw401/sdk";

const nonceCache = new InMemoryNonceCache();

// Generate a challenge to send to the client
const challenge = generateChallenge({ domain: "app.example.com" });
// Send challenge to client...
```

### Client-side: Sign the challenge

```typescript
import { challengeSigningBytes, encodeSignature } from "@claw401/sdk";
import { sign } from "@solana/web3.js";

// wallet.signMessage signs raw bytes with the wallet's Ed25519 key
const payload = challengeSigningBytes(challenge);
const signature = await wallet.signMessage(payload);

const signedChallenge = {
  challenge,
  signature: encodeSignature(signature),
  publicKey: wallet.publicKey.toBase58(),
};
```

### Server-side: Verify and create a session

```typescript
import { verifySignature, createSession, verifySession } from "@claw401/sdk";

const result = verifySignature({
  signedChallenge,
  expectedDomain: "app.example.com",
  nonceCache,
});

if (!result.valid) {
  throw new Error(result.reason);
}

const session = await createSession({
  publicKey: result.publicKey!,
  domain: "app.example.com",
  nonce: signedChallenge.challenge.nonce,
  options: { scopes: ["read", "write"] },
});
```

### Agent attestation

```typescript
import { createAgentAttestation, verifyAgentAttestation } from "@claw401/sdk";

// Operator creates attestation for an agent
const attestation = await createAgentAttestation({
  agentKey: agentPublicKey,
  operatorKey: operatorPublicKey,
  operatorSecretKey: operatorKeypair.secretKey,
  agentId: "my-agent-001",
  capabilities: {
    actions: ["read:orders", "submit:transaction"],
    mcpTools: ["get_balance", "transfer"],
  },
  ttlMs: 24 * 60 * 60 * 1000, // 24 hours
});

// Downstream service verifies the attestation
const result = verifyAgentAttestation({
  attestation,
  expectedOperatorKey: knownOperatorPublicKey,
});
```

## API Reference

### auth

- `generateChallenge(options)` — Generate a domain-scoped challenge
- `verifySignature(options)` — Verify a signed challenge
- `challengeSigningBytes(challenge)` — Get canonical bytes for client signing
- `encodeSignature(bytes)` — Base64-encode a signature
- `InMemoryNonceCache` — In-memory nonce replay cache (dev/testing only)

### session

- `createSession(input)` — Create a session after successful verification
- `verifySession(options)` — Verify a session's validity and scope
- `serializeSession(session)` — Serialize session to JSON
- `deserializeSession(raw)` — Deserialize session from JSON

### proof

- `signProof(options)` — Sign a capability or identity proof
- `verifyProof(options)` — Verify a signed proof

### agent

- `createAgentAttestation(options)` — Create an operator-signed agent attestation
- `verifyAgentAttestation(options)` — Verify an agent attestation
- `serializeAttestation(attestation)` — Serialize for MCP context header
- `deserializeAttestation(encoded)` — Deserialize from MCP context header

## Security Notes

- Private keys are never stored or transmitted by this SDK
- All signatures use Ed25519 via TweetNaCl
- Nonce replay protection requires an external cache in distributed deployments
- Challenges are domain-bound — cross-domain replay attacks are rejected
- All signing payloads are canonicalized (sorted JSON keys) for determinism

## License

Apache-2.0

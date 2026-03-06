import { describe, it, expect, beforeEach } from "vitest";
import nacl from "tweetnacl";
import {
  generateChallenge,
  verifySignature,
  challengeSigningBytes,
  encodeSignature,
  InMemoryNonceCache,
} from "../auth.js";

function makeKeypair() {
  return nacl.sign.keyPair();
}

/** Encode public key as base58 (minimal implementation for tests). */
function pubkeyToBase58(bytes: Uint8Array): string {
  // Use @solana/web3.js PublicKey for encoding
  const { PublicKey } = require("@solana/web3.js");
  return new PublicKey(bytes).toBase58();
}

describe("generateChallenge", () => {
  it("returns a challenge with correct structure", () => {
    const challenge = generateChallenge({ domain: "example.com" });
    expect(challenge.nonce).toHaveLength(64); // 32 bytes hex
    expect(challenge.domain).toBe("example.com");
    expect(challenge.version).toBe("x401/1.0");
    expect(challenge.expiresAt).toBeGreaterThan(challenge.issuedAt);
  });

  it("normalizes domain to lowercase", () => {
    const challenge = generateChallenge({ domain: "Example.COM" });
    expect(challenge.domain).toBe("example.com");
  });

  it("throws on empty domain", () => {
    expect(() => generateChallenge({ domain: "" })).toThrow();
  });

  it("respects custom TTL", () => {
    const ttlMs = 60_000;
    const challenge = generateChallenge({ domain: "test.com", ttlMs });
    expect(challenge.expiresAt - challenge.issuedAt).toBe(ttlMs);
  });
});

describe("verifySignature", () => {
  let keypair: ReturnType<typeof nacl.sign.keyPair>;
  let cache: InMemoryNonceCache;

  beforeEach(() => {
    keypair = makeKeypair();
    cache = new InMemoryNonceCache();
  });

  function signChallenge(challenge: ReturnType<typeof generateChallenge>) {
    const payload = challengeSigningBytes(challenge);
    const sigBytes = nacl.sign.detached(payload, keypair.secretKey);
    return {
      challenge,
      signature: encodeSignature(sigBytes),
      publicKey: pubkeyToBase58(keypair.publicKey),
    };
  }

  it("accepts a valid signature", () => {
    const challenge = generateChallenge({ domain: "app.test" });
    const signed = signChallenge(challenge);
    const result = verifySignature({
      signedChallenge: signed,
      expectedDomain: "app.test",
      nonceCache: cache,
    });
    expect(result.valid).toBe(true);
    expect(result.publicKey).toBe(signed.publicKey);
  });

  it("rejects an expired challenge", () => {
    const challenge = generateChallenge({ domain: "app.test", ttlMs: -1000 });
    const signed = signChallenge(challenge);
    const result = verifySignature({
      signedChallenge: signed,
      expectedDomain: "app.test",
      nonceCache: cache,
      clockSkewMs: 0,
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("CHALLENGE_EXPIRED");
  });

  it("rejects a domain mismatch", () => {
    const challenge = generateChallenge({ domain: "correct.com" });
    const signed = signChallenge(challenge);
    const result = verifySignature({
      signedChallenge: signed,
      expectedDomain: "wrong.com",
      nonceCache: cache,
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("INVALID_DOMAIN");
  });

  it("rejects a replayed nonce", () => {
    const challenge = generateChallenge({ domain: "app.test" });
    const signed = signChallenge(challenge);

    // First use: valid
    const first = verifySignature({
      signedChallenge: signed,
      expectedDomain: "app.test",
      nonceCache: cache,
    });
    expect(first.valid).toBe(true);

    // Second use: replay
    const second = verifySignature({
      signedChallenge: signed,
      expectedDomain: "app.test",
      nonceCache: cache,
    });
    expect(second.valid).toBe(false);
    expect(second.errorCode).toBe("NONCE_REPLAYED");
  });

  it("rejects an invalid signature", () => {
    const challenge = generateChallenge({ domain: "app.test" });
    const otherKeypair = nacl.sign.keyPair();
    const payload = challengeSigningBytes(challenge);
    // Sign with a different key
    const wrongSigBytes = nacl.sign.detached(payload, otherKeypair.secretKey);
    const signed = {
      challenge,
      signature: encodeSignature(wrongSigBytes),
      publicKey: pubkeyToBase58(keypair.publicKey), // pubkey doesn't match signer
    };
    const result = verifySignature({
      signedChallenge: signed,
      expectedDomain: "app.test",
      nonceCache: cache,
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("INVALID_SIGNATURE");
  });
});

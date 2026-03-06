import { describe, it, expect } from "vitest";
import nacl from "tweetnacl";
import { createAgentAttestation, verifyAgentAttestation } from "../agent.js";

function pubkeyToBase58(bytes: Uint8Array): string {
  const { PublicKey } = require("@solana/web3.js");
  return new PublicKey(bytes).toBase58();
}

describe("Agent attestation", () => {
  it("creates and verifies a valid attestation", async () => {
    const operatorKp = nacl.sign.keyPair();
    const agentKp = nacl.sign.keyPair();

    const attestation = await createAgentAttestation({
      agentKey: pubkeyToBase58(agentKp.publicKey),
      operatorKey: pubkeyToBase58(operatorKp.publicKey),
      operatorSecretKey: operatorKp.secretKey,
      agentId: "test-agent-001",
      capabilities: { actions: ["read:data", "submit:transaction"] },
    });

    const result = verifyAgentAttestation({ attestation });
    expect(result.valid).toBe(true);
    expect(result.attestation?.agentId).toBe("test-agent-001");
  });

  it("rejects an expired attestation", async () => {
    const operatorKp = nacl.sign.keyPair();
    const agentKp = nacl.sign.keyPair();

    const attestation = await createAgentAttestation({
      agentKey: pubkeyToBase58(agentKp.publicKey),
      operatorKey: pubkeyToBase58(operatorKp.publicKey),
      operatorSecretKey: operatorKp.secretKey,
      agentId: "test-agent-002",
      capabilities: { actions: ["read:data"] },
      ttlMs: -1000,
    });

    const result = verifyAgentAttestation({ attestation, clockSkewMs: 0 });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("expired");
  });

  it("rejects wrong operator key", async () => {
    const operatorKp = nacl.sign.keyPair();
    const agentKp = nacl.sign.keyPair();
    const wrongKp = nacl.sign.keyPair();

    const attestation = await createAgentAttestation({
      agentKey: pubkeyToBase58(agentKp.publicKey),
      operatorKey: pubkeyToBase58(operatorKp.publicKey),
      operatorSecretKey: operatorKp.secretKey,
      agentId: "test-agent-003",
      capabilities: { actions: ["read:data"] },
    });

    const result = verifyAgentAttestation({
      attestation,
      expectedOperatorKey: pubkeyToBase58(wrongKp.publicKey),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("mismatch");
  });
});

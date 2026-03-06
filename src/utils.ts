/**
 * Low-level encoding, hashing, and nonce utilities.
 * These are the deterministic building blocks referenced throughout the protocol.
 */

import { HexString, Base64String } from "./types.js";

/** Protocol version string injected into all signed payloads. */
export const PROTOCOL_VERSION = "x401/1.0";

/** Default challenge TTL: 5 minutes. */
export const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;

/** Default session TTL: 24 hours. */
export const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/** Encodes a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): HexString {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Decodes a hex string to a Uint8Array. */
export function hexToBytes(hex: HexString): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16);
    if (isNaN(byte)) throw new Error(`Invalid hex byte at position ${i}`);
    bytes[i / 2] = byte;
  }
  return bytes;
}

/** Encodes a Uint8Array to a base64 string. */
export function bytesToBase64(bytes: Uint8Array): Base64String {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  return btoa(String.fromCharCode(...bytes));
}

/** Decodes a base64 string to a Uint8Array. */
export function base64ToBytes(b64: Base64String): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Encodes a string to UTF-8 bytes. */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically random 32-byte nonce as a hex string.
 * Uses the platform's CSPRNG (crypto.getRandomValues in browser, crypto module in Node).
 */
export function generateNonce(): HexString {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Node.js fallback
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require("crypto") as typeof import("crypto");
    const buf = nodeCrypto.randomBytes(32);
    bytes.set(buf);
  }
  return bytesToHex(bytes);
}

// ---------------------------------------------------------------------------
// Hashing (SHA-256)
// ---------------------------------------------------------------------------

/**
 * SHA-256 hash of arbitrary bytes.
 * Returns hex-encoded digest.
 * Uses Web Crypto API (Node 18+ and all modern browsers).
 */
export async function sha256Hex(data: Uint8Array): Promise<HexString> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Deterministic session ID derived from: nonce + publicKey + domain + createdAt.
 * This is not a secret — it is a canonical identifier.
 */
export async function deriveSessionId(
  nonce: HexString,
  publicKey: string,
  domain: string,
  createdAt: number,
): Promise<string> {
  const raw = `${nonce}:${publicKey}:${domain}:${createdAt}`;
  return sha256Hex(stringToBytes(raw));
}

/**
 * Deterministic attestation ID derived from: agentKey + operatorKey + issuedAt + nonce.
 */
export async function deriveAttestationId(
  agentKey: string,
  operatorKey: string,
  issuedAt: number,
  nonce: HexString,
): Promise<string> {
  const raw = `${agentKey}:${operatorKey}:${issuedAt}:${nonce}`;
  return sha256Hex(stringToBytes(raw));
}

// ---------------------------------------------------------------------------
// Signing payload canonicalization
// ---------------------------------------------------------------------------

/**
 * Produces a canonical UTF-8 byte representation of a signing payload.
 * All fields are sorted by key to ensure deterministic ordering.
 *
 * This is the canonical serialization: JSON.stringify with sorted keys.
 * Never use this output for anything other than signing — it is not a display format.
 */
export function canonicalize(obj: Record<string, unknown>): Uint8Array {
  const sorted = sortObjectKeys(obj);
  return stringToBytes(JSON.stringify(sorted));
}

function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

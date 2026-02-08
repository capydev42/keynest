# Cryptographic Architecture

This document describes the cryptographic design that the current implementation
uses. The goal is to protect secrets at rest using well-reviewed primitives while
keeping the file format simple and auditable.

---

## Design Principles

- Use only well-reviewed cryptographic algorithms
- Avoid custom cryptography
- Encrypt everything at rest
- Fail safely on authentication errors
- Keep the file format simple and versioned

---

## High-Level Overview

1. The user provides a master password
2. A cryptographic key is derived using a password-based key derivation function
3. All secrets are serialized into a single data structure
4. The serialized data is encrypted and authenticated
5. The encrypted blob is stored on disk

---

## Key Derivation (implementation)

- **Algorithm used:** Argon2 via `argon2::Argon2::default()` (the crate's default
  configuration — typically Argon2id with default parameters). The code calls
  `hash_password_into(password.as_bytes(), salt, &mut key)` to fill a 32-byte key.
- **Purpose:** derive a 256-bit (32 byte) symmetric key from the user password.

Inputs:
- Master password (UTF-8)
- Random salt (16 bytes)

Output:
- 256-bit symmetric encryption key (32 bytes)

Note: the implementation currently uses the library default Argon2 parameters.
For production use you should make parameters explicit and tuned for your
deployment (memory size, iterations, parallelism). See "Future work" below.

---

## Encryption (implementation)

- **Algorithm used:** XChaCha20-Poly1305 (via `chacha20poly1305::XChaCha20Poly1305`).
  This AEAD provides confidentiality and integrity and uses a 24-byte nonce
  (XNonce) which reduces risk of accidental nonce reuse compared to 12-byte
  nonces.

Properties provided by the AEAD:
- Confidentiality: ciphertext hides plaintext without the derived key.
- Integrity / authentication: tampering or wrong keys causes decryption to fail.

The implementation generates a fresh 24-byte random nonce for each encryption
operation using `getrandom::fill`.

Note: no additional associated data (AAD) is used in the current implementation.

---

## On-disk format (actual implementation)

The current file layout written by the library is exactly:

MAGIC (4) | VERSION (1) | SALT (16) | NONCE (24) | CIPHERTEXT

- `MAGIC` = ASCII `KNST` (4 bytes)
- `VERSION` = single byte (current implementation uses `1`)
- `SALT` = 16 bytes (SALT_LEN)
- `NONCE` = 24 bytes (NONCE_LEN for XChaCha20-Poly1305)
- `CIPHERTEXT` = remaining bytes (authenticated ciphertext)

The code checks the 4-byte magic and version and then extracts salt/nonces at
the following offsets when opening a file (example):
- salt: bytes 5..21 (16 bytes)
- nonce: bytes 21..45 (24 bytes)

The ciphertext is the bytes after offset 45 and is decrypted with the derived
key and nonce.

---

## Serialization

- Secrets are serialized with `serde_json` (JSON) and the full serialized blob
  is encrypted as a single unit. The implementation writes only the encrypted
  blob to disk; no plaintext is persisted.

Note: JSON is convenient and auditable but not the most compact. Consider a
binary format for size-sensitive scenarios.

---

## Memory handling (current and recommendations)

- Current implementation uses fixed-size stack/heap buffers for key/salt/nonce
  and does not yet explicitly zeroize secrets after use.
- Recommendation: add the `zeroize` crate (or similar) to zero secret material
  (derived keys, plaintext buffers) as soon as they are no longer needed. For
  higher assurance consider OS-backed secure memory guards.

---

## Error handling in code

- Decryption errors are translated into a generic error (`anyhow!("Invalid
  password or corrupted data")`) so callers do not receive partial plaintext.
- Other failures use contextual error messages (e.g. "key derivation failed",
  "encryption failed", "OS random generator unavailable"). Avoid exposing
  secrets in error text.

Ensure callers handle errors gracefully and do not print secret material to
logs or STDOUT in production code.

---

## Threat Model Summary

Protected against:
- Offline attacks on the encrypted store
- Accidental plaintext exposure
- File tampering

Not protected against:
- Compromised runtime environments
- Weak master passwords
- Malicious binaries

---

## Future work / considerations

1. Make Argon2 parameters explicit and provide a clear migration path for
   changing them (store parameter set/version alongside salt).
2. Introduce zeroization of secrets (`zeroize` crate) after use.
3. Consider using a constant-time memcmp for file format checks if concerned
   about timing side-channels.
4. Add file-format versioning and backward-compatibility handling.
5. Consider HSM/OS-level integrations for secret storage in higher-security
   deployments.

## Summary

The implementation uses:

- Argon2 (crate default) to derive a 32-byte key from a password + 16-byte salt
- XChaCha20-Poly1305 (24-byte nonce) for authenticated encryption
- JSON (serde_json) for serialization

This design favors simplicity and modern primitives; before production use
review Argon2 parameters, add zeroization, and perform a security audit.

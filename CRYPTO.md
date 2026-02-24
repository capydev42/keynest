# Cryptographic Architecture

This document describes the cryptographic design used by Keynest to protect secrets at rest using well-reviewed primitives.

---

## Design Principles

- Use only well-reviewed cryptographic algorithms
- Avoid custom cryptography
- Encrypt everything at rest
- Fail safely on authentication errors
- Keep the file format simple and versioned
- Use secure memory handling (zeroization)

---

## High-Level Overview

1. The user provides a master password
2. A cryptographic key is derived using Argon2id
3. All secrets are serialized into a JSON structure
4. The serialized data is encrypted with ChaCha20-Poly1305
5. The encrypted blob is stored on disk with metadata header

---

## Key Derivation

- **Algorithm:** Argon2id (via `argon2` crate)
- **Version:** Argon2 v0x13 (recommended version)
- **Output:** 256-bit (32 byte) symmetric key

### Default Parameters

| Parameter | Default Value | Recommendation Source |
|-----------|---------------|----------------------|
| Memory Cost | 64 MiB (65536 KiB) | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) (minimum 46-64 MiB) |
| Time Cost | 3 iterations | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) (minimum 1) |
| Parallelism | 1 thread | Security & compatibility |

The default values are based on [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) recommendations and provide a good balance between security and performance:

- **Memory (64 MiB):** Protects against GPU/ASIC brute-force attacks. OWASP recommends at least 46-64 MiB for sensitive applications.
- **Time (3):** A reasonable compromise between security and usability. Higher values increase security but slow down key derivation.
- **Parallelism (1):** Simplest compatibility across different systems. Can be increased by advanced users.

For higher security (at the cost of performance):
```bash
keynest init --argon-mem 131072 --argon-time 5 --argon-parallelism 4
```

Parameters are stored in the file header for future verification.

---

## Encryption

- **Algorithm:** XChaCha20-Poly1305 (AEAD)
- **Nonce:** 24 bytes (XNonce)
- **Key:** 32 bytes (derived from password)

Properties:
- **Confidentiality:** ciphertext hides plaintext without the derived key
- **Integrity:** tampering or wrong keys causes decryption to fail
- **Fresh nonce:** a new random nonce is generated for each encryption

---

## On-disk Format

```
MAGIC (4) | VERSION (1) | MEM_COST (4) | TIME_COST (4) | PARALLELISM (4) | SALT (16) | NONCE (24) | CIPHERTEXT
```

| Field | Size | Description |
|-------|------|-------------|
| MAGIC | 4 bytes | ASCII `KNST` |
| VERSION | 1 byte | File format version (currently 1) |
| MEM_COST | 4 bytes | Argon2 memory cost (KiB) |
| TIME_COST | 4 bytes | Argon2 time cost (iterations) |
| PARALLELISM | 4 bytes | Argon2 parallelism |
| SALT | 16 bytes | Random salt for key derivation |
| NONCE | 24 bytes | Random nonce for encryption |
| CIPHERTEXT | variable | Authenticated encrypted data |

**Total header size:** 53 bytes

---

## Serialization

- Secrets are serialized with `serde_json` (JSON)
- The full serialized blob is encrypted as a single unit
- Only the encrypted blob is written to disk (no plaintext persisted)

---

## Memory Handling

- The `zeroize` crate is used for secure memory cleanup
- Derived keys are zeroized after use
- The `Drop` trait is implemented for `Keynest` to ensure cleanup

```rust
impl Drop for Keynest {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
```

Note: The salt is stored in the file format (KeystoreFile) which is persisted to disk, not kept in memory-only.

---

## Error Handling

- Decryption errors return: `"Invalid password or corrupted data"`
- Other failures use contextual messages: `"key derivation failed"`, `"encryption failed"`
- No secrets are exposed in error messages

---

## Threat Model

### Protected Against
- Offline attacks on the encrypted store
- Accidental plaintext exposure
- File tampering (AEAD authentication)

### Not Protected Against
- Compromised runtime environments
- Weak master passwords
- Malicious binaries
- Memory scraping attacks

---

## Future Considerations

1. Versioned file format for backward compatibility
2. Constant-time comparisons for timing attack mitigation
3. HSM/OS-level integrations for higher security

---

## Summary

| Component | Implementation |
|-----------|----------------|
| KDF | Argon2id (configurable) |
| Encryption | XChaCha20-Poly1305 |
| Nonce | 24 bytes (random per encryption) |
| Salt | 16 bytes (random per keystore) |
| Serialization | JSON (serde_json) |
| Memory | zeroize crate for secure cleanup |
| File Version | V1 |

This design prioritizes simplicity and modern, well-audited cryptographic primitives.

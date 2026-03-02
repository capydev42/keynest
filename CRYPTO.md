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
5. The encrypted blob is stored on disk using a versioned TLV format

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

The keystore uses a versioned TLV (Type-Length-Value) format for extensibility.

### V2 Format (current)

```
MAGIC (4) | VERSION (1) | TLV Entries...
```

#### File Header

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | MAGIC | `"KNST"` (0x4B4E5354) |
| 4 | 1 | VERSION | Format version (2) |
| 5+ | N | TLV Entries | Type-Length-Value encoded fields |

#### TLV Entry Structure

Each field encoded as:
```
TYPE (1) | LENGTH (2) | VALUE (N)
```

- **TYPE:** 1 byte identifier (little-endian)
- **LENGTH:** 2 bytes (u16, little-endian) - maximum 65535 bytes
- **VALUE:** N bytes of data

#### TLV Type Identifiers

| Type ID | Field | Value Format | Size |
|---------|-------|--------------|------|
| 1 | KDF | mem_cost(4) + time_cost(4) + parallelism(4) | 12 bytes |
| 2 | Salt | Random salt bytes | 16 bytes |
| 3 | Nonce | XChaCha20 nonce | 24 bytes |
| 4 | Ciphertext | Encrypted JSON data | Variable |

#### Example V2 File Layout

```
Offset 0:   4B 4E 53 54          [MAGIC: "KNST"]
Offset 4:   02                   [VERSION: 2]
Offset 5:   01                   [TYPE: KDF]
Offset 6:   0C 00               [LENGTH: 12]
Offset 8:   00 01 00 00 03 00 00 00 01 00 00 00  [KDF params]
Offset 20:  02                   [TYPE: Salt]
Offset 21:  10 00               [LENGTH: 16]
Offset 23:   ... 16 bytes ...  [Salt]
Offset 39:  03                   [TYPE: Nonce]
Offset 40:  18 00               [LENGTH: 24]
Offset 42:   ... 24 bytes ...  [Nonce]
Offset 66:  04                   [TYPE: Ciphertext]
Offset 67:  XX XX               [LENGTH: N]
Offset 69:   ... N bytes ...   [Ciphertext]
```

#### TLV Design Rationale

- **Extensible:** New field types can be added without breaking parsers (unknown types are ignored)
- **Self-describing:** Length prefix prevents parsing errors
- **Alignment:** Compact encoding with no padding overhead
- **Forward compatible:** Unknown TLV types are silently ignored during parsing

Older versions (v1) use a fixed binary format for backward compatibility.

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
| File Version | V2 (TLV format) |

This design prioritizes simplicity and modern, well-audited cryptographic primitives.

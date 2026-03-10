# Changelog

All notable changes to keynest will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Header struct for authenticated metadata (AAD)
- AAD (Authenticated Additional Data) for AEAD encryption
- Unit test for AAD authentication
- Duplicate TLV field detection (KDF, Algorithm, Salt, Nonce, Ciphertext)
- AEAD_TAG_LEN constant and ciphertext length validation (min 16 bytes)
- Memory exhaustion protection (MAX_CIPHERTEXT: 16 MiB, MAX_TLV_SIZE: 1 MiB)

### Changed
- Refactored file format: introduced Header struct for metadata

### Security
- AAD protects header metadata from tampering
- Validates ciphertext has minimum length for AEAD tag
- Rejects duplicate fields in TLV parsing
- Added size limits to prevent memory exhaustion attacks

### Documentation
- Added AAD section to CRYPTO.md

---

## [0.3.0] - 2026-03-07

### Added
- TLV (Type-Length-Value) v2 file format with extensibility support
- Algorithm field (XChaCha20-Poly1305) to v2 TLV format for future algorithm flexibility
- Algorithm dispatch system for runtime algorithm selection
- Unit tests for format parsing (invalid magic, unsupported version, missing/invalid algorithm)
- File permission hardening (0o600 for keystore, 0o700 for directories)
- Symlink attack protection

### Changed
- Refactored crypto module: split into `algorithm.rs` (dispatch) and `chacha20poly1305.rs` (implementation)
- Removed unused v1 serialization code (v2 is the current format)
- Improved code quality (cleaned up unused imports, fixed warnings)

### Security
- File permissions set to 0600 (owner read/write only)
- Directory permissions set to 0700 (owner only)
- Auto-repair of overly permissive existing files
- Symlink validation to prevent attacks

### Documentation
- Updated CRYPTO.md with detailed TLV format specification
- Added file header structure, TLV entry layout, and byte-level example
- Added documentation for Algorithm enum and password input functions
- Added Algorithm Dispatch section explaining the extensible design
- Added File Permissions section to CRYPTO.md

---

## [0.2.0] - 2026-02-25

### Added
- Versioned file format abstraction for future compatibility
- Atomic crash-safe storage writes (temp file + rename)
- Windows-specific atomic file replacement using `ReplaceFileW` API
- `info` command to display keystore metadata

### Changed
- Internal format handling refactored into dedicated module
- Replaced unmaintained `atty` crate with `std::io::IsTerminal`
- Default storage now uses platform-specific directories

### Fixed
- Security: improved error handling and secret zeroization
- Various code quality improvements

---

## [0.1.0] - 2026-02-18

### Added
- Initialize encrypted local keystore
- Store, retrieve, update, and remove secrets
- List all keys or keys with values/timestamps
- Custom Argon2 KDF parameters (memory, time, parallelism)
- Cross-platform support (Linux, macOS, Windows)
- Custom storage location via `--store` flag
- Password input via environment variable, stdin, or interactive prompt
- Rekey functionality to change password and/or KDF parameters
- GitHub Actions CI workflow
- Automated release workflow with multi-platform builds
- Security audit and dependency checks
- MIT OR Apache-2.0 dual licensing
- Comprehensive documentation (README, CRYPTO.md, SECURITY.md)

### Security
- Argon2id key derivation
- XChaCha20-Poly1305 authenticated encryption
- Secure memory handling with `zeroize` crate

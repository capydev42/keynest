# Changelog

All notable changes to keynest will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- (nothing yet)

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

# Keynest

[![crates.io](https://img.shields.io/crates/v/keynest.svg)](https://crates.io/crates/keynest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/capydev42/keynest/actions/workflows/ci.yml/badge.svg)](https://github.com/capydev42/keynest/actions/workflows/ci.yml)

Simple, offline, cross-platform secrets manager written in Rust.

Store your secrets securely in an encrypted local file — no cloud, no server, no daemon.

---

## Why Keynest?

Keynest fills the gap between insecure `.env` files and heavyweight secrets managers.

- **Strong security** without infrastructure (Argon2id + ChaCha20Poly1305)
- **Offline-first** secrets management
- **Portability** across machines and environments
- **Simple CLI** that works well with scripts and automation

---

## Installation

### From crates.io

```bash
cargo install keynest
```

### From source

```bash
cargo install --git https://github.com/capydev42/keynest.git
```

Or build locally:

```bash
cargo build --release
./target/release/keynest
```

---

## Quick Start

```bash
# Initialize a new keystore
keynest init

# Store a secret
keynest set github_token "ghp_xxxx"

# Retrieve a secret
keynest get github_token

# List all keys
keynest list

# Update a secret
keynest update github_token "ghp_yyyy"

# Remove a secret
keynest remove github_token

# Show keystore info (KDF params, creation date)
keynest info

# Change password (and optionally KDF parameters)
keynest rekey
keynest rekey --argon-mem 131072  # upgrade memory cost
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize a new keystore |
| `set <key> <value>` | Store a secret |
| `get <key>` | Retrieve a secret |
| `update <key> <value>` | Update existing secret |
| `list [--all]` | List keys (--all shows values & timestamps) |
| `remove <key>` | Remove a secret |
| `info` | Show keystore information (KDF params, creation date) |
| `rekey` | Change password and/or KDF parameters |

---

## Features

### Security
- **Encryption:** ChaCha20-Poly1305 (AEAD)
- **Key Derivation:** Argon2id with configurable parameters
- **Secure Memory:** Keys and passwords are zeroized after use

### CLI Options
- `--store <path>` - Specify custom keystore location

### KDF Options (for init/rekey)
- `--argon-mem <kb>` - Memory cost in KiB (default: 65536)
- `--argon-time <n>` - Time cost / iterations (default: 3)
- `--argon-parallelism <n>` - Parallelism (default: 1)

### Password Input
Keynest accepts passwords via:
1. Environment variable: `KEYNEST_PASSWORD="secret" keynest get key`
2. Stdin: `echo "secret" | keynest get key`
3. Interactive prompt (default)

---

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
keynest = "0.1"
```

### Simple example (default storage location)

```rust
use keynest::Keynest;
use anyhow::Result;
use zeroize::Zeroizing;

fn main() -> Result<()> {
    let password = Zeroizing::new(String::from("my-password"));
    
    // Create new keystore
    let mut kn = Keynest::init(password.clone())?;
    
    // Store secrets
    kn.set("api_token", "secret123")?;
    kn.save()?;
    
    // Later: reopen
    let kn = Keynest::open(password)?;
    assert_eq!(kn.get("api_token"), Some("secret123"));
    
    Ok(())
}
```

### Advanced example (custom storage location)

```rust
use keynest::{Keynest, KdfParams, Storage};
use anyhow::Result;
use zeroize::Zeroizing;

fn main() -> Result<()> {
    let storage = Storage::new("/path/to/keystore.db");
    let password = Zeroizing::new(String::from("my-password"));
    
    // Create new keystore with custom KDF parameters
    let kdf = KdfParams::default();
    let mut kn = Keynest::init_with_storage_and_kdf(password, storage, kdf)?;
    
    // Store secrets
    kn.set("api_token", "secret123")?;
    kn.save()?;
    
    // Later: reopen
    let kn = Keynest::open_with_storage(Zeroizing::new(String::from("my-password")), storage)?;
    assert_eq!(kn.get("api_token"), Some("secret123"));
    
    Ok(())
}
```

---

## Storage Location

Default keystore locations by OS:
- **Linux:** `~/.local/share/keynest/.keynest.db`
- **macOS:** `~/Library/Application Support/keynest/.keynest.db`
- **Windows:** `%APPDATA%\keynest\.keynest.db`

Use `--store <path>` to override.

---

## Development

```bash
# Build
cargo build

# Test
cargo test

# Format
cargo fmt

# Lint
cargo clippy -- -D warnings
```

---

## License

Licensed under either of:
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

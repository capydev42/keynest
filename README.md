# Keynest

[![crates.io](https://img.shields.io/crates/v/keynest.svg)](https://crates.io/crates/keynest)
[![docs.rs](https://img.shields.io/docsrs/keynest)](https://docs.rs/keynest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/capydev42/keynest/actions/workflows/ci.yml/badge.svg)](https://github.com/capydev42/keynest/actions/workflows/ci.yml)

Stop committing secrets by accident.

A simple, offline secrets manager that replaces `.env` files.

Run any command with encrypted secrets — no cloud, no setup.

---

## Why Keynest?

| Problem | Solution |
|---------|----------|
| `.env` files leak secrets | Encrypted local storage |
| Vault is overkill | Single binary, no setup |
| 1Password CLI requires account | Local, no account needed |
| Secrets in code/prompts | Runtime injection |

---

## Run Commands with Secrets

Inject secrets into any process as environment variables:

```bash
keynest exec -- docker compose up
```

→ your app receives secrets via environment variables

Works with:
- Docker
- Node.js
- Python
- shell scripts
- CI pipelines
- AI agents

No `.env` files needed.

---

## Philosophy

- No cloud
- No accounts
- No background services
- Just a simple encrypted file

Your secrets stay on your machine.

---

## Try it in 30 seconds

```bash
keynest init
keynest set api_key test123
keynest exec -- printenv API_KEY
```

Output: `test123`

---

## AI & Agent Usage

Use Keynest as a secure local secret store for AI agents.

```bash
keynest exec -- python agent.py
```

Access secrets via environment variables (e.g. `API_KEY`):

```python
import os
api_key = os.environ["API_KEY"]
```

Keeps secrets out of:
- source code
- logs
- prompts
- LLM context

Works well with:
- LangChain
- AutoGPT
- custom agents

---

## Installation

### Pre-built binaries

Download the latest release from GitHub: [keynest/releases/latest](https://github.com/capydev42/keynest/releases/latest)

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

# Store a secret (three ways)
keynest set github_token "ghp_xxxx"           # as argument
keynest set github_token --file secret.txt    # from file
keynest set github_token --prompt             # interactive prompt

# Retrieve a secret
keynest get github_token
keynest get github_token --clip              # copy to clipboard (auto-clears after 15s)
keynest get github_token --clip --timeout 30 # copy with custom timeout

# List all keys
keynest list

# Update a secret
keynest update github_token "ghp_yyyy"

# Remove a secret
keynest remove github_token

# Run command with secrets as environment variables
keynest exec -- docker compose up
keynest exec --only API_KEY -- \
  curl -H "Authorization: Bearer $API_KEY" https://api.example.com
keynest exec --prefix MY_ -- env
keynest exec --print

# Show keystore info (KDF params, creation date)
keynest info

# Change password (and optionally KDF parameters)
keynest rekey
keynest rekey --argon-mem 131072  # upgrade memory cost

# Import/Export secrets
keynest import .env
keynest import secrets.json
keynest import --overwrite .env
keynest export --format env
keynest export secrets.json
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize a new keystore |
| `set <key> [<value>]` | Store a secret (value, --file, or --prompt) |
| `get <key>` | Retrieve a secret (exits 1 if not found) |
| `get <key> --clip` | Copy secret to clipboard (auto-clears after 15s) |
| `update <key> <value>` | Update existing secret |
| `list [--all]` | List keys (--all shows values & timestamps) |
| `remove <key>` | Remove a secret |
| `exec -- <cmd>` | Run command with secrets as environment variables |
| `info` | Show keystore information (KDF params, creation date) |
| `rekey` | Change password and/or KDF parameters |
| `import <file>` | Import secrets from file (env or json) |
| `export [file]` | Export secrets to file or stdout |

All commands support `--json` for structured output (get, list, info).

---

## Security

- **Key Derivation:** Argon2id with configurable parameters
- **Secure Memory:** Keys and passwords are zeroized after use
- **Encryption:** XChaCha20-Poly1305 AEAD

### Security Notes

- Uses well-established cryptographic primitives (Argon2id, XChaCha20-Poly1305)
- No network access
- No telemetry
- Zero-config — works out of the box

---

## CLI Options
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

### Add as Dependency

```bash
cargo add keynest
```

```rust
use keynest::{Keynest, Storage, KdfParams};
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

## Star History

If you find Keynest useful, consider giving it a star ⭐

---

## License

Licensed under either of:
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

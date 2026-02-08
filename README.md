# Keynest 🐦🔐

Keynest is a simple, offline, cross-platform secrets manager written in Rust.

Store your secrets securely in an encrypted local file — no cloud, no server, no daemon.

---

## Why Keynest?

Keynest fills the gap between insecure `.env` files and heavyweight secrets managers.

Modern development workflows need secrets everywhere — locally, in scripts, in CI — but existing solutions are often either **too insecure** or **too complex** for small projects and individual developers.

Keynest is designed for developers who want:

- **Strong security** without infrastructure
- **Offline-first** secrets management
- **Portability** across machines and environments
- **A simple CLI** that works well with scripts and automation

Unlike cloud-based password managers or server-backed vaults, Keynest stores secrets **locally in an encrypted file**, requires **no account, no daemon, and no network access**, and behaves the same on every platform.

In short:  
**Keynest is for developers who want secure secrets without the operational burden.**

---

## How to use

This repository provides two ways to interact with Keynest:

- Library API (embed Keynest in other Rust applications)
- Command-line executable (standalone CLI to manage secrets)

> Note: This project is an MVP. Do not use it as-is for production secrets management — see the security TODOs below.

### Build & test (quick commands)

- Build (debug): `cargo build`
- Build (release): `cargo build --release`
- Run CLI: `cargo run -- <command>` (runs the executable in the workspace)
- Run all tests: `cargo test`
- Run a single unit test by name:

  ```bash
  # run a specific test function
  cargo test init_and_open_work

  # show test output (disable capture)
  cargo test init_and_open_work -- --nocapture
  ```

- Format and lint:
  - `cargo fmt`
  - `cargo clippy -- -D warnings`

---

### Library usage (embed Keynest)

Add this crate as a dependency (for local development):

```toml
# In your project's Cargo.toml
[dependencies]
keynest = { path = "../keynest" }
```

Example usage (basic flow):

```rust
use keynest::Keynest;
use anyhow::Result;

fn demo() -> Result<()> {
    // Create a new keystore (prompts or accepts password in your code)
    let mut kn = Keynest::init("my-password")?;

    // Store secrets
    kn.set("api_token", "supersecret")?;
    kn.set("db_password", "hunter2")?;

    // Persist changes
    kn.save()?;

    // Re-open later
    let kn2 = Keynest::open("my-password")?;
    assert_eq!(kn2.get("api_token"), Some(&"supersecret".to_string()));

    Ok(())
}
```

Notes:
- Use `Keynest::init` to create a new keystore, and `Keynest::open` to load an existing one.
- Call `save()` after making changes to persist them.
- Prefer using the API from a secure runtime (avoid hard-coding passwords).

---

### CLI usage (executable)

Build and run:
```bash
# Run the CLI with cargo
cargo run -- <subcommand> [args]
```

The CLI will prompt for a password (it reads the password securely from the terminal). Example interactive session:

```bash
# initialize store (you'll be prompted for a password)
cargo run -- init
# Output:
# > Enter password: ****
# Keystore initialized

# store a secret
cargo run -- set mykey "secret-value"
# Enter password: ****
# Stored secret 'mykey'

# get a secret
cargo run -- get mykey
# Enter password: ****
# secret-value

# list keys
cargo run -- list
# Enter password: ****
# Name:
# mykey

# remove a key
cargo run -- remove mykey
# Enter password: ****
# Key : 'mykey' removed sucessfully
```

Subcommands:
- `init` — initialize the keystore
- `set <key> <value>` — store a secret
- `get <key>` — retrieve a secret
- `update <key> <new_value>` — update existing secret
- `list [--all]` — list keys; with `--all` show names, values and timestamps
- `remove <key>` — remove a secret

Password input

- Keynest accepts the password in three ways (in order of precedence):
  1. Environment variable: `KEYNEST_PASSWORD` — e.g. `KEYNEST_PASSWORD="supersecret" keynest get github_token`
  2. Piped via stdin (useful in scripts): `echo "supersecret" | keynest get github_token` or
     `printf "%s" "$KEYNEST_PASSWORD" | keynest get github_token`
  3. Interactive TTY prompt (fallback): when neither of the above are provided the CLI will prompt
     you to type a password securely.

Examples:

```bash
# Use environment variable
KEYNEST_PASSWORD="supersecret" cargo run -- get github_token

# Pipe password on stdin
echo "supersecret" | cargo run -- get github_token

# Interactive prompt (no env var or stdin)
cargo run -- get github_token
# Password: ****
```

Notes:
- Supplying the password via environment variable or stdin is convenient for automation, but treat
  those approaches carefully: avoid leaving secrets in shell history or process tables and prefer
  ephemeral CI secrets or secure secret stores when available.

---

### Security & TODOs (MVP caveats)

- This is an MVP. Before production use:
  1. Review Argon2/crypto parameters and KDF configuration.
  2. Remove or replace any `panic!`/`unwrap()` in library code with proper `Result` handling.
  3. Add stronger error handling and avoid leaking secret material in logs.
  4. Add CI: `cargo fmt`, `cargo clippy`, tests.
  5. Add integration/end-to-end tests and an audit of cryptographic primitives.

- TODO: enhance documentation, enhance the MVP state, enhance error handling.

---

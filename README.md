# Keynest 🐦🔐

Keynest is a simple, offline, cross-platform secrets manager written in Rust.

Store your secrets securely in an encrypted local file — no cloud, no server, no daemon.

## Features

- Encrypted local secrets store
- Simple CLI interface
- Cross-platform single binary
- No external dependencies

## Example

keynest init
keynest set DB_PASSWORD
keynest get DB_PASSWORD
keynest list
keynest remove DB_PASSWORD

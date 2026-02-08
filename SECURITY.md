# Security Policy

Keynest is a local, offline secrets manager.  
Security is a core design goal, and responsible disclosure is encouraged.

---

## Supported Versions

Only the latest released version of Keynest receives security updates.

| Version | Supported |
|--------|-----------|
| latest | ✅ |
| older | ❌ |

---

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public GitHub issue**.

Instead, report it privately:

- Open a **GitHub Security Advisory**, or
- Contact the maintainer directly (if contact information is provided)

Please include:
- A clear description of the issue
- Steps to reproduce
- Potential impact
- Any suggested fixes (if available)

---

## Security Goals

Keynest aims to:

- Protect secrets at rest using strong, modern cryptography
- Minimize attack surface by avoiding unnecessary features
- Remain fully auditable as open source software
- Avoid network access entirely

---

## Non-Goals

Keynest does **not** aim to protect against:

- A fully compromised operating system
- Attackers with access to process memory
- Keyloggers or malicious binaries
- Weak or reused master passwords

---

## Cryptography

Keynest relies exclusively on well-established cryptographic primitives and libraries.

Custom cryptography is explicitly avoided.

Details can be found in the Crypto Architecture documentation.


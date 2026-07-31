<p align="center">
  <img src="assets/logo/ellkan-icon-mark-fondo-oscuro.png" alt="Ellkan" width="160">
</p>

<h1 align="center">Ellkan</h1>
<p align="center">Zero-knowledge, self-hosted password manager.</p>
<p align="center"><a href="README.md">Español</a> · <b>English</b> (this file)</p>

**Ellkan** — from Mapudungun *elkan*, "to hide, to conceal."

## What Ellkan is

A self-hosted password manager with a zero-knowledge architecture: the server never sees your private keys or your secrets in plaintext. Backend in Rust (Axum), encryption with modern primitives (X25519, Ed25519, XChaCha20-Poly1305, Argon2id), web frontend and browser extension share the same cryptographic core compiled to WebAssembly.

## Tech stack

### Backend

| Component | Technology |
| --- | --- |
| Language | Rust (2024 edition) |
| Web framework | Axum (on Tokio) |
| Database | PostgreSQL 18+ |
| Data access | `sqlx`, compile-time verified queries |
| Authentication | Ed25519 nonce-signature — no passwords stored server-side |
| Architecture | Modular monolith (Controller → Service → Repository) |
| Deployment | Docker / Docker Compose |

### Frontend and extension

| Component | Technology |
| --- | --- |
| Web frontend | SvelteKit + TypeScript |
| Browser extension | Manifest V3 (Chrome, Firefox, Safari) |
| Cryptographic core | Compiled to WebAssembly, shared across backend, web, and extension |
| Package manager | pnpm |
| E2E testing | Playwright |

### Cryptography

| Primitive | Use |
| --- | --- |
| X25519 | Key agreement (end-to-end encryption) |
| Ed25519 | Digital signatures (authentication) |
| XChaCha20-Poly1305 | Authenticated encryption (AEAD) of secrets and metadata |
| Argon2id | Master key derivation from the passphrase |
| HKDF-SHA256 | Domain-separated subkey derivation per context |
| zeroize / secrecy | Secure wiping and redaction of secrets in memory |
| subtle | Constant-time comparisons (timing-attack mitigation) |

## FAQ

**Can the server see my passwords?**
No. Everything is encrypted and decrypted on your own device, never on the server — it's like handing someone a locked safe to hold onto: they can store it, but they never get a key to open it or see what's inside.

**What happens if someone steals the server's database?**
They don't get your passwords — they only get locked safes. Without your master password (which is never stored anywhere, not even on the server), there's no way to open them.

**How do you protect my keys in the computer's memory (RAM) while they're being used?**
The key is never left sitting around in memory waiting for someone to grab it. Every time it's needed, it's rebuilt on the spot from your password, used for an instant, and immediately wiped — like writing something on a piece of paper, using it once, and tearing it up right away, instead of leaving it lying on the desk. Your master password is kept only while your session is open and never touches the disk: close the browser or app, and it's gone. The one thing this can't prevent: if your computer already has malware spying on it, that malware could see the key at the exact instant you're using it — no password manager can protect you from that, because at that point the attacker is already inside your machine, not inside the system.

## Status

Actively in development, early stage.

## License

**AGPL-3.0** — see [LICENSE](LICENSE) (official English text, the only legally binding one) and [LICENSE.es.txt](LICENSE.es.txt) (unofficial Spanish translation, for reference only).

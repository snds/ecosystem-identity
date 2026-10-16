# ecosystem-identity

The shared identity and persona crate for the Mailbird, Synapse, and Lockdown ecosystem.

A person remembers **one master password** and keeps **one recovery kit**. Everything else in here is machinery behind that: a root key, one key per persona (the wall between work, personal, and business), one key per app per persona, and a crown-jewel key for the secrets that must never autofill. Any ecosystem app can create the identity alone. A later app finds it and reuses it. Lockdown adopts it without moving or re-encrypting anything.

**Spec:** [`snds/lockdown` `docs/plan/01-identity.md`](https://github.com/snds/lockdown/blob/main/docs/plan/01-identity.md) (v1.4). Decisions D10–D33 in [`docs/plan/decisions.md`](https://github.com/snds/lockdown/blob/main/docs/plan/decisions.md).

## What is in the crate

| Module | Job |
|---|---|
| `records` | Profile, Persona, Device, KeyEnvelope, Consent, Manifest as canonical CBOR, Ed25519-signed, unknown fields preserved |
| `keys` | Typed secret keys; XChaCha20-Poly1305 wraps bound to `{profile, persona, key, purpose, app}` |
| `kdf` | Argon2id with signed, per-surface floors that may only rise; HKDF-SHA-512 for the Account Unlock Key |
| `kem` | Hybrid X25519 + ML-KEM-768 (X-Wing) for device and persona receiving keys |
| `store` | The on-disk layout with a signed, hash-chained manifest; rollback and tamper detection |
| `attach` | `create`, `attach`, `open_or_create`, `recover_with_kit`, `recover_with_account`, personas, app keys, `adopt` |
| `kit` | Recovery kit: Secret Key + recovery code, Crockford base32 |
| `handshake` | Same-device enrolment between two ecosystem apps: transport and verifier traits, commit-then-reveal, six-digit code, Unix-socket transport |
| `auth`, `keystore` | OPAQUE and platform-keystore traits; file keystore for desktop and CI; hardware backends declared |
| `schema/` | JSON Schema for every record; a test fails when stale |

## Use it

```toml
[dependencies]
ecosystem-identity = { git = "https://github.com/snds/ecosystem-identity", rev = "<commit>" }
```

Pin a commit (or the `v0.1.0` tag once it is on the remote). The format major (`FORMAT = "ecosystem-identity/1"`) is the compatibility promise; readers refuse a higher major with a clear message.

## Develop

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
UPDATE_SCHEMAS=1 cargo test --test schema   # regenerate schema/ after a record change
```

Tests run with the `insecure-test-kdf` feature through the crate's self dev-dependency. Never enable it in an app.

## Provenance

Built first inside [`snds/Mailbird`](https://github.com/snds/Mailbird) (`crates/identity`, PRs #44 and #46, ADR-0049 and ADR-0050) per Lockdown decision D12, and extracted here on 2026-10-16. The two ADRs are carried in `docs/decisions/`.

## Licence

Apache-2.0. No employer code or data; see NOTICE.

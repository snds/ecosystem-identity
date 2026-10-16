# Decision 0002 (was Mailbird ADR-0050) · Identity crate: the local handshake, and parameters that only rise

- **Carried from:** snds/Mailbird `docs/decisions/` on 2026-10-16, at extraction.
- **Status:** Proposed
- **Date:** 2026-10-16
- **Builds on:** [decision 0001](0001-identity-crate.md) (the shared identity crate: records, envelopes, create and attach)
- **Decided elsewhere:** Lockdown decisions D18–D27 (`snds/lockdown` `docs/plan/decisions.md`) and the identity spec v1.3 (`docs/plan/01-identity.md`). D26 accepted "parameters only ever rise" as a follow-up. D27 gave this session spec §10 step 4 (the handshake behind a test double) and the D26 follow-up, inside `crates/identity` only.

## Decision

`crates/identity` gains the local handshake of spec §6 step 3 behind a transport trait, and enforces 04-security §4's rule that Argon2id parameters never go down across loads. Two small API changes asked for by Mailbird's step-3 work (the app label on app keys, and retiring an envelope) ride along. Nothing outside `crates/identity/` and this file changes.

### What this adds

- **`handshake`** — the second app on a device gets the identity from the running one, with no kit and no typing.
  - `PeerTransport` (connect / accept) and `PeerChannel` (one framed message per send or receive, 4-byte length prefix, 64 KiB cap). Two transports: `ChannelTransport` in memory, and `UnixSocketTransport` (`#[cfg(unix)]`) at `<identity-root>/handshake.sock`, mode `0600` inside the `0700` root, peer credentials from `SO_PEERCRED` (Linux) or `getpeereid` (other Unix).
  - `PeerVerifier` answers "is the other end an ecosystem app I trust?" and runs on **both** sides before anything moves (03-architecture §7). `ProcessIdentityVerifier` is built for Linux: same user, executable read through `/proc/<pid>/exe`, compared by path and, when the installed manifest gives one, by SHA-256 of the running image. `CodeSignatureVerifier` (Apple audit token → `SecCode`; Windows pipe client → Authenticode / MSIX family) is declared with what it must do and refuses every peer with a clear `Error::PeerUntrusted` until built. `AllowAll` and `Scripted` are for tests.
  - `ConfirmNewDevice` is the person's say on the running app; it receives the proposed `Device`, the verified app, and the six-digit `Sas`. `AutoConfirm` and `Decline` are for tests.
  - `Responder` (running app) and `Requester` (new app). The requester opens the envelope with its device receiving key, checks the root key derives the profile's signing key, writes its own `device` wrap, and attaches the ordinary way.
  - Guarantees: one request per connection; a timeout on every step; a request nonce accepted once (the responder remembers the last 4096); a "no" writes nothing; the new device's record is signed by the ISK and the manifest advances before the grant is sent; the requester refuses a store behind the head the grant reports.
- **D26 enforced.** `Head` carries `kdf: Option<Argon2Params>`, the parameters in force when that head was accepted. `attach` and `refresh` refuse a profile below them with `Error::KdfLowered`, naming both sets; equal or higher passes; a head from an older build (no `kdf`) checks the floor only. `kdf::calibrate_at_least(previous, target)` never returns below `previous`; `calibrate` is that from the floor.
- **App label on app keys (asked for by step 3).** `KeyEnvelope.app` and `Aad.app`; `wrap_app_key(persona, app, key)`, `unwrap_app_key(persona, app, key_id)`, `app_keys(persona, app)`; the crown-jewel pair takes the label too. A re-labelled envelope is refused by name before decryption, and a rewritten `aad` fails the tag.
- **Retire an envelope (asked for by step 3).** `retire_envelope(key_id, wrapped_by)` removes the file; the manifest gains a `Tombstone` (path, last hash, the `seq` that removed it, when); the head advances. A copy of the file put back is an unlisted file and refused.
- **Schemas** for `key-envelope`, `manifest` and `aad` are regenerated; `head` and `handshake-message` are new files, so an app in another language can check its reading of the wire.

### The protocol, in one picture

```text
running app (responder)                        new app (requester)
  Hello { profile, device, kem_pub, commit } ──▶
                                            ◀── Request { device, nonce, pop }
  Reveal { nonce } ─────────────────────────▶   both show the 6-digit code
  Granted { envelope, head } | Refused ─────▶
```

The responder commits to its nonce (SHA-256) before it sees the requester's and reveals it afterwards, so neither side can steer the code once it knows the other's input: a process sitting between two honest apps cannot make the two displays agree. `pop` is the device key's signature over the profile, the commitment, the nonce and the proposed `Device`, so the requester holds the key it names. The code is six digits of SHA-256 over both nonces and both receiving keys.

## Deviations from spec v1.3, proposed as Lockdown decisions

Each is additive under the spec's own §9 rule, or a point the spec left open. D28 and D29 were asked for by the step-3 session; the rest are this session's.

- **D28 (proposed): `KeyEnvelope.app` and `Aad.app`.** An `app-data` or `crown-jewel` envelope carries the app it belongs to, inside the associated data as well, so it cannot be re-labelled. The field is empty for the other purposes and then left out of the encoding, so every envelope written before this field opens unchanged. The spec's `aad` becomes `{profile_id, persona_id, key_id, purpose, app, v}` with `app` optional.
- **D29 (proposed): retiring an envelope leaves a tombstone in the manifest.** `Manifest.tombstones` lists every file a write removed (path, last hash, removing `seq`, time). The chain explains the deletion; the head advances; a restored copy is unlisted and refused. The loader already refused unlisted files; the tombstone is the record of why one is missing.
- **D30 (proposed): peer wraps use `x-wing-xchacha20poly1305` and carry `enc`.** The spec reserved `hpke-x25519-mlkem768` for peer envelopes (D23). What this crate writes is X-Wing encapsulation → HKDF-SHA-512 (bound to the encapsulation and the recipient key) → XChaCha20-Poly1305 with the same associated data as every other envelope. That is not RFC 9180 HPKE, so it gets its own name, and `hpke-x25519-mlkem768` stays reserved for the real suite. `x25519-xchacha20poly1305` is the same construction for a build without ML-KEM. `KeyEnvelope.enc` (the encapsulation) is new and absent on symmetric wraps. No new `purpose`: the handshake's envelope is the IRK, `purpose: irk`, `wrapped_by: peer.<new device id>` (the `peer` kind the spec already defined).
- **D31 (proposed): handshake wire protocol v1** as drawn above: responder speaks first, commit-then-reveal for the code, proof of possession by the device key, one request per connection, the peer envelope is handed over and not stored (the new device writes its own `device` wrap), and the grant carries the head so the requester refuses a store behind it. Version `HANDSHAKE_V = 1` in every message.
- **D32 (proposed): `Head` carries the last accepted Argon2id parameters**, which closes D26's accepted gap. Where the head is persisted per platform stays the shell's decision (ADR-0049). Raising the parameters of an existing profile is not offered yet: the kit and account wraps were stretched with the old set, so a raise needs the recovery code in hand to re-wrap them; `calibrate_at_least` is the piece a later "re-stretch on next kit use" builds on.
- **D33 (proposed): on Linux the handshake socket lives in the identity root** (`<root>/handshake.sock`, `0600`, root `0700`) and the peer is verified by process identity (same uid, `/proc/<pid>/exe` path and hash against the installed binaries). 03-architecture §7 leaves open whether to require a pairing code on every Linux connect; this handshake always shows the six-digit code and always asks the person on the running app, which is that code.

## Out of scope here

QR device enrolment between two devices (spec §8 row 2: the same `Hello`/`Request` shape over a QR plus a short code, later), key transparency for device keys (Lockdown's server), hardware keystores and the Apple/Windows/Android verifiers (declared, not built), real HPKE, persona revocation and re-keying, raising a profile's parameters in place, and the step-3 note-lock re-wrap itself (the other session, `crates/core`).

## Verification

- `cargo fmt -p ecosystem-identity -- --check`, `cargo clippy -p ecosystem-identity --all-targets -- -D warnings`, `cargo test -p ecosystem-identity` and `cargo test -p pim-core` pass; counts are in the pull request.
- New tests: in-memory handshake end to end (create on A → handshake → attach on B without the kit; both open the same persona key and app key; B's signed `Device` is in the store with `enrolled_by: device A`; the manifest advanced by one on A and one more on B; the code matched on both sides), untrusted peer refused on either side with nothing written, person declines with nothing written, replayed request refused by the same responder, Unix-socket handshake end to end with process-identity verification on both sides (socket mode `0600`, removed on drop, timeout when nobody connects), the D26 cases (equal ok, raise ok, lower refused on attach and on refresh, older head without parameters passes, calibration never lowers), the re-labelled app envelope, and retire → attach → restored copy refused.

## Consequences

- An app that keeps the `Head` across runs now also keeps the parameters it accepted; the shell that persists the head persists both, since it is one value.
- Mailbird's step-3 consumer wraps its note-lock key with `wrap_app_key(persona, "mailbird", &key)` and lists it with `app_keys`; another app cannot open or re-label it.
- The Unix transport is the reference for the three platform channels still to come (XPC, bound service, named pipe): each is one `PeerTransport` plus one `PeerVerifier`; the protocol and the store side do not change.

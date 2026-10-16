# Decision 0001 (was Mailbird ADR-0049) · The shared identity crate (`ecosystem-identity`)

- **Carried from:** snds/Mailbird `docs/decisions/` on 2026-10-16, at extraction.
- **Status:** Proposed
- **Date:** 2026-10-16
- **Builds on:** ADR-0043 in snds/Mailbird (locked notes) (locked notes, Phase 33: the key this crate will take over)
- **Decided elsewhere:** Lockdown decisions D10–D16 (`snds/lockdown` `docs/plan/decisions.md`) and the identity format spec (`docs/plan/01-identity.md`, v1.2). D10: any app can create the identity, and the first installed owns it until Lockdown adopts it. D11: the recovery kit belongs to the identity, not the app. D12: **Mailbird is the test-bed**: the crate is built in this repository first, then extracted. D13: personas are records, never flags. D15: the neutral identifier (`group.design.snds.identity`, `snds/identity`). D16: one Android signing key.

## Decision

Mailbird gains a second Rust crate, `crates/identity`, package `ecosystem-identity`. It owns the person's identity on disk (profile, personas, devices, key envelopes, consents) in the layout every ecosystem app reads, and it knows nothing about mail or notes. It lives here only because this is the first app that can prove it (D12); it moves out whole when Lockdown starts consuming it.

### What this PR adds (spec §10 steps 1 and 2)

- **Records** (`records`): `Profile`, `Persona`, `Device`, `KeyEnvelope`, `Consent`, and the store's `Manifest`, as canonical CBOR (sorted map keys, no floats), each with a `v` field and an Ed25519 signature by the Identity Signing Key. Unknown fields are captured in an `extra` map and written back untouched, so a newer app's additions survive an older app's rewrite. JSON Schema for each is exported to `crates/identity/schema/` and a test fails when it drifts.
- **Keys** (`keys`): `Irk`, `PersonaKey`, `AppDataKey`, `CrownJewelKey`, `DeviceUnlockKey`, `AccountUnlockKey`, `KitKey` as typed newtypes over `secrecy::SecretBox`. Symmetric wraps are XChaCha20-Poly1305 with associated data = canonical CBOR of `{profile_id, persona_id, key_id, purpose, v}`. An envelope moved to another persona or purpose is refused by name before any decryption; a rewritten `aad` then fails the tag.
- **KDF** (`kdf`): Argon2id with a floor per platform (desktop 64 MiB / 3 / 4), parameters signed into the profile and refused below the floor on every load; HKDF-SHA-512 for the Account Unlock Key exactly as 04-security §3 writes it.
- **Receiving keys** (`kem`): `Persona.kem_pub` and `Device.kem_pub` with `KemAlg`. The hybrid X25519 + ML-KEM-768 is implemented through RustCrypto's `x-wing` over `ml-kem`, which builds on stable Rust 1.97; plain X25519 stays as a fallback.
- **Store** (`store`): `FORMAT = "ecosystem-identity/1"`, `profile.cbor`, `personas/`, `devices/`, `envelopes/`, `consents/`, and a signed, hash-chained `manifest.cbor`. Loading verifies the manifest, every record's signature, every file's hash, and that nothing is on disk the manifest does not list. Platform roots follow D15.
- **Attach** (`attach`): `Identity::create`, `Identity::attach` (§6 steps 2 and 4: probe, verify, open the device-wrapped IRK with the device unlock), `open_or_create` (adds step 5), `recover_with_kit`, `recover_with_account`, persona creation, `wrap_app_key` / `unwrap_app_key`, the crown-jewel pair, `adopt(manager)` and `unlink` (§7: `Profile.manager` only), consents, and `refresh`.
- **Recovery kit** (`kit`): Secret Key (128 bits, `A1-…`) and recovery code (160 bits), Crockford base32, forgiving of case and look-alike letters.
- **Traits for what does not exist yet:** `AccountAuth` (OPAQUE later; `LocalStubAuth` now, documented as not OPAQUE) and `DeviceKeystore` (`FileKeystore` now, for Linux, macOS, and CI; `SecureEnclaveKeystore`, `StrongBoxKeystore`, `TpmKeystore` declared with what each must do and a clear error from `open`).
- **Conformance suite** (`crates/identity/tests/`): record round trips, the moved envelope, the tampered and rolled-back manifest, the refused Argon2id floor, create → attach without the kit, recover from the kit on an empty root, adopt changing only `manager`, unknown fields surviving a rewrite, and the refused format major. CI runs it beside `pim-core`.

### What the follow-up PR does (spec §10 step 3)

Re-wrap the Phase 33 note-lock key as Mailbird's App Data Key for the persona that owns the notes, on the user's next unlock: `Identity::wrap_app_key(persona, &NotesKey)` once, keep the returned key id in the store's settings, and from then on open the notes with `unwrap_app_key`. The passphrase path in `notes_lock.rs` stays as the standalone lock (D5); the wrap is what puts the notes within reach of the recovery kit (D11). Nothing in `crates/core` changes in this PR.

### Why here, not its own repository

D12: the crate needs a real consumer to prove the format before Lockdown exists, and this repository has one (`crates/core`, the sync relay, the note lock). The package name is a working name, the crate imports nothing from `pim-core`, and the move is a `git mv` plus a path change in the two `Cargo.toml` lines that mention it.

## Deviations from spec v1.2, proposed as Lockdown decisions

Each is a clarification the spec left open or a small addition under its own §9 rule that new fields are additive. None changes a decided point.

- **D18 (proposed): `Profile` carries `isk_pub` and `kdf`.** The spec lists neither, yet every reader needs the signing key to verify the chain and 04-security §4 says the Argon2id parameters live in the profile, signed. Both are additive.
- **D19 (proposed): the ISK and each persona's receiving key are derived, not stored.** `ISK = HKDF-SHA-512(IRK, "ecosystem-identity/isk/v1")`; persona receiving-key seed `= HKDF-SHA-512(PK, "ecosystem-identity/persona-kem/v1" ‖ persona_id)`. Holding the IRK is holding the ISK, which is what §7 assumes when the manager signs the profile. The spec says the private half is "wrapped by that Persona Key"; derivation gives the same reach with no extra envelope and no new `purpose` value. Rotation needs a counter field later.
- **D20 (proposed): a Persona Key's `key_id` is its `persona_id`.** The spec gives the persona no key-id field. Re-keying a persona will need one; add it additively then.
- **D21 (proposed): envelope file names are `<key_id>.<kind>.<id>.cbor`.** The spec writes `<key_id>.<wrapped_by>.cbor`; `wrapped_by` is a pair, and the IRK has one wrap per device, so the id has to be in the name.
- **D22 (proposed): the `account` and `kit` wraps use the profile id as their `KeyRef.id`.** The spec names the kinds and not the ids.
- **D23 (proposed): the hybrid KEM is X-Wing.** The spec says "hybrid X25519 + ML-KEM-768 through HPKE". This slice needs only key generation and the published public key; X-Wing (`draft-connolly-cfrg-xwing-kem`) is the standardised combiner of exactly those two and is what `hpke-x25519-mlkem768` envelopes will carry when peer wraps arrive. The `KemAlg` id is `x25519-mlkem768`; the envelope `alg` string stays as the spec writes it.
- **D24 (proposed): every record is signed by the ISK.** The spec allows a device-key signature on envelopes "before the ISK exists". In this crate the ISK exists from the first byte (it derives from the IRK), so the case never arises and the verifier accepts the ISK only.
- **D25 (proposed): `Device.kem_pub` and `EnrolledBy::Creator` are added.** The spec gives each device a hybrid pair for enrolment but no field for it; `enrolled_by` (device or kit) has no value for the device that made the identity.
- **Rollback memory is the caller's.** The manifest is hash-chained, and `attach` takes the head this device last accepted and refuses an older store; the crate does not itself persist that head. 04-security §7 says "every device remembers the newest head it accepted"; where that memory lives on each platform is a shell decision.
- **Parameters "only rise" is not yet enforced** across loads, only the floor is. It needs the same per-device memory as the head.
- **Argon2id is calibrated at create** with a 1 s target starting from the floor and adding passes; the floor's memory is not raised. A finer calibration is a later change with no format impact.

## Out of scope here

The handshake between running apps (§6 step 3; §10 step 4), device enrolment over QR (§8 row 2), peer envelopes (`hpke-x25519-mlkem768`, `purpose: share`), persona revocation and re-keying, key transparency, a real OPAQUE client, hardware keystores, Android and iOS root resolution, and concurrent writers to one root (the store writes atomically per file; two apps writing at once is a later lock).

## Verification

- `cargo fmt -p ecosystem-identity -- --check`, `cargo clippy -p ecosystem-identity --all-targets -- -D warnings`, `cargo test -p ecosystem-identity` (6 unit, 11 conformance, 2 schema), and `cargo test -p pim-core` pass.
- The tests run at a lowered Argon2id floor through the `insecure-test-kdf` feature, enabled only by the crate's own self dev-dependency, the way `notes_lock.rs` lowers its PBKDF2 count under `cfg(test)`.

## Consequences

- Every new app-level key in Mailbird is wrapped through `wrap_app_key` from now on, or that data stays out of the recovery kit's reach (D11).
- A format change is a change to the records and the schema files together, with the conformance suite as the gate; the manifest and `v` fields are what make an older reader stop rather than guess.
- The crate's working name and location are temporary by design (D12). Nothing in Mailbird may depend on the path beyond the two workspace lines.

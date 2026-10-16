//! `ecosystem-identity`: the one identity every ecosystem app embeds.
//!
//! It owns the person's profile, personas, devices, keys, and recovery kit,
//! on disk in a layout every app can read (spec `01-identity.md` v1.3).
//! Any app can create it alone; later apps find it and attach; a manager
//! adopts it without moving or re-encrypting anything.
//!
//! - [`records`] — the signed CBOR records and the envelope's associated data
//! - [`keys`] — the typed keys and the symmetric wrap
//! - [`kdf`] — Argon2id with a signed floor; HKDF for the Account Unlock Key
//! - [`kem`] — receiving keys (hybrid X25519 + ML-KEM-768, or X25519)
//! - [`store`] — the on-disk layout, the manifest, and the checks on load
//! - [`attach`] — [`Identity`]: create, attach, recover, wrap and unwrap
//! - [`handshake`] — the local handshake: a second app on the same device
//!   gets the identity from the running one (§6 step 3)
//! - [`kit`] — the recovery kit's text and the key it rebuilds
//! - [`keystore`] — the device's own keys, behind [`DeviceKeystore`]
//! - [`auth`] — account login, behind [`AccountAuth`] (OPAQUE later; a local stub now)
//! - [`schema`] — JSON Schema for every record
//!
//! This crate knows nothing about mail, notes, or any one app. It lives in
//! this repository while the first app proves it (D12) and moves out whole.

pub mod attach;
pub mod auth;
pub mod cbor;
pub mod error;
pub mod handshake;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod keystore;
pub mod kit;
pub mod records;
pub mod schema;
pub mod store;

pub use attach::{AccountCredentials, Attach, Backup, Identity, signing_key};
pub use auth::{AccountAuth, ExportKey, LocalStubAuth};
/// The Ed25519 implementation records are signed with, so callers can name its types.
pub use ed25519_dalek;
pub use error::{Error, Result};
pub use handshake::{
    ConfirmNewDevice, Enrolled, HandshakeOptions, PeerChannel, PeerIdentity, PeerTransport,
    PeerVerifier, Requester, Responder, Sas, TrustedPeer,
};
pub use kdf::Argon2Params;
pub use kem::{KemAlg, KemPublicKey};
pub use keys::{AppDataKey, CrownJewelKey, Irk, PersonaKey, SymmetricKey};
pub use keystore::{DeviceKeystore, FileKeystore};
pub use kit::RecoveryKit;
pub use records::{
    Consent, Device, Id, KeyEnvelope, KeyRef, KeyRefKind, Manifest, Persona, PersonaKind, Platform,
    Profile, Purpose, Record, RecoveryState, Timestamp,
};
pub use store::{FORMAT, FORMAT_MAJOR, Head, Store, default_root};

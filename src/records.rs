//! The records (spec §2 and §4): `Profile`, `Persona`, `Device`,
//! `KeyEnvelope`, `Consent`, and the store's `Manifest`.
//!
//! Every record is canonical CBOR, carries its format version in `v`, and is
//! signed by the Identity Signing Key (ISK). Fields a reader does not know
//! land in `extra` and are written back untouched (spec §9).

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::cbor::{Extra, from_slice, to_canonical};
use crate::kdf::Argon2Params;
use crate::kem::KemPublicKey;
use crate::{Error, Result};

/// The record format version this crate writes and the highest it reads.
pub const RECORD_V: u16 = 1;

/// A 128-bit identifier. It is written as the usual hyphenated UUID text in
/// every encoding, so CBOR, JSON, and file names all show the same string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct Id(uuid::Uuid);

impl Id {
    /// A fresh random id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// The 16 raw bytes, for salts and associated data.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Parses the hyphenated text form.
    pub fn parse(text: &str) -> Result<Self> {
        uuid::Uuid::parse_str(text)
            .map(Self)
            .map_err(|_| Error::Invalid(format!("'{text}' isn't an id")))
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.0.hyphenated())
    }
}

impl Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(&self.0.hyphenated())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        uuid::Uuid::parse_str(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Seconds since the Unix epoch, UTC.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The current time.
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self(i64::try_from(secs).unwrap_or(i64::MAX))
    }
}

/// Whether the person has a recovery kit, and whether it has been tried.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryState {
    /// No kit has been made. The only thing a manager may newly ask for (§7).
    #[default]
    None,
    /// A kit exists.
    Created,
    /// The kit was used once in a drill and it opened the identity.
    Drilled,
}

/// One per person. Who manages the identity and how far recovery has got.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Profile {
    /// Record format version.
    pub v: u16,
    /// The person's identifier. Never changes.
    pub profile_id: Id,
    /// When the identity was created.
    pub created_at: Timestamp,
    /// Recovery kit state.
    pub recovery: RecoveryState,
    /// The app that manages this identity (for example `lockdown`), or none.
    /// While none, any app may write the profile (§2, §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// The store format major this profile was written under.
    pub format_v: u16,
    /// Public half of the Identity Signing Key, which signs every record.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub isk_pub: [u8; 32],
    /// Password-stretching parameters for the recovery kit and the account
    /// slot. Signed here so a relay cannot lower them (04-security §4).
    pub kdf: Argon2Params,
    /// Fields this crate does not know. Kept as read.
    #[serde(flatten)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub extra: Extra,
    /// Ed25519 signature by the ISK over the record with `sig` empty.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub sig: Vec<u8>,
}

/// What a persona is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PersonaKind {
    /// Home life. Every identity starts with one of these.
    Personal,
    /// Employment.
    Work,
    /// A business the person runs.
    Business,
    /// Anything else; `label` says what.
    Custom,
}

/// One per wall (D13). An app holding one persona's key cannot read another's data.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Persona {
    /// Record format version.
    pub v: u16,
    /// The persona's identifier.
    pub persona_id: Id,
    /// What the person calls it.
    pub label: String,
    /// What it is for.
    pub kind: PersonaKind,
    /// The app that created it.
    pub created_by_app: String,
    /// The identity key that wraps this persona's key (the IRK's key id).
    pub identity_key_ref: KeyRef,
    /// Public half of the persona's receiving key for shares. The private
    /// half is derived from the Persona Key, so only a holder of that key
    /// can open a share sent to this persona.
    pub kem_pub: KemPublicKey,
    /// A display colour, as the app likes to write it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Fields this crate does not know. Kept as read.
    #[serde(flatten)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub extra: Extra,
    /// Ed25519 signature by the ISK over the record with `sig` empty.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub sig: Vec<u8>,
}

/// The operating system family a device runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// macOS.
    Macos,
    /// iOS and iPadOS.
    Ios,
    /// Android.
    Android,
    /// Windows.
    Windows,
    /// Linux and the BSDs.
    Linux,
    /// A browser.
    Web,
    /// Something else.
    Other,
}

impl Platform {
    /// The platform this binary was built for.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "ios") {
            Self::Ios
        } else if cfg!(target_os = "android") {
            Self::Android
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )) {
            Self::Linux
        } else if cfg!(target_family = "wasm") {
            Self::Web
        } else {
            Self::Other
        }
    }
}

/// How a device came to be enrolled.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnrolledBy {
    /// The first device: it created the identity.
    Creator,
    /// Another, already enrolled device vouched for it (§8 row 2).
    Device {
        /// That device's id.
        id: Id,
    },
    /// The recovery kit rebuilt the root key on it (§8 row 3).
    Kit,
}

/// One per enrolled device.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Device {
    /// Record format version.
    pub v: u16,
    /// The device's identifier, chosen by its keystore.
    pub device_id: Id,
    /// What the person calls it.
    pub name: String,
    /// Its operating system.
    pub platform: Platform,
    /// Platform keystore attestation, when the platform offers one.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Vec<u8>>")]
    pub attestation: Option<Vec<u8>>,
    /// The device's Ed25519 public key.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub device_pub: [u8; 32],
    /// The device's receiving key, used only to enrol it (§3).
    pub kem_pub: KemPublicKey,
    /// When it was enrolled.
    pub enrolled_at: Timestamp,
    /// How it was enrolled.
    pub enrolled_by: EnrolledBy,
    /// When it was revoked, if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
    /// Fields this crate does not know. Kept as read.
    #[serde(flatten)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub extra: Extra,
    /// Ed25519 signature by the ISK over the record with `sig` empty.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub sig: Vec<u8>,
}

/// Which kind of key can open an envelope.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRefKind {
    /// The Account Unlock Key (password + Secret Key through OPAQUE). `id` is the profile.
    Account,
    /// A device's keystore key. `id` is the device.
    Device,
    /// A Persona Key. `id` is the persona.
    Persona,
    /// The Identity Root Key. `id` is its key id.
    Irk,
    /// The key the recovery code rebuilds. `id` is the profile.
    Kit,
    /// Another person's or device's receiving key. `id` is theirs.
    Peer,
}

impl KeyRefKind {
    /// The word used in file names and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Device => "device",
            Self::Persona => "persona",
            Self::Irk => "irk",
            Self::Kit => "kit",
            Self::Peer => "peer",
        }
    }
}

/// Who can open an envelope: a kind and the id of that kind's holder.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, JsonSchema,
)]
pub struct KeyRef {
    /// Which kind of key.
    pub kind: KeyRefKind,
    /// Which one.
    pub id: Id,
}

impl KeyRef {
    /// A reference of this kind to this id.
    pub fn new(kind: KeyRefKind, id: Id) -> Self {
        Self { kind, id }
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.kind.as_str(), self.id)
    }
}

/// The cipher that sealed an envelope.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum WrapAlg {
    /// Symmetric wrap with a 192-bit random nonce.
    #[serde(rename = "xchacha20poly1305")]
    XChaCha20Poly1305,
    /// Public-key wrap to a peer through HPKE (RFC 9180) with hybrid
    /// X25519 + ML-KEM-768. Reserved: this crate does not yet write it.
    #[serde(rename = "hpke-x25519-mlkem768")]
    HpkeX25519MlKem768,
    /// Public-key wrap to a device's receiving key: X-Wing (hybrid
    /// X25519 + ML-KEM-768) encapsulates a shared secret, HKDF-SHA-512 turns
    /// it into a key, and that key seals the payload with XChaCha20-Poly1305.
    /// The encapsulation is in `enc`. This is what the local handshake
    /// writes (spec §6 step 3). It is not RFC 9180 HPKE, so it has its own
    /// name.
    #[serde(rename = "x-wing-xchacha20poly1305")]
    XWingXChaCha20Poly1305,
    /// The same construction over plain X25519, for a build without ML-KEM.
    /// Not post-quantum.
    #[serde(rename = "x25519-xchacha20poly1305")]
    X25519XChaCha20Poly1305,
}

impl WrapAlg {
    /// The peer-wrap cipher that goes with a receiving key's scheme.
    pub fn for_kem(alg: crate::kem::KemAlg) -> Self {
        match alg {
            crate::kem::KemAlg::X25519 => Self::X25519XChaCha20Poly1305,
            crate::kem::KemAlg::X25519MlKem768 => Self::XWingXChaCha20Poly1305,
        }
    }

    /// The receiving-key scheme a peer-wrap cipher uses, or none for a
    /// symmetric or reserved cipher.
    pub fn kem(self) -> Option<crate::kem::KemAlg> {
        match self {
            Self::X25519XChaCha20Poly1305 => Some(crate::kem::KemAlg::X25519),
            Self::XWingXChaCha20Poly1305 => Some(crate::kem::KemAlg::X25519MlKem768),
            Self::XChaCha20Poly1305 | Self::HpkeX25519MlKem768 => None,
        }
    }
}

/// What the wrapped key is for. Part of the associated data, so an envelope
/// cannot be passed off as another purpose.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// The Identity Root Key.
    Irk,
    /// A Persona Key.
    Persona,
    /// An App Data Key.
    AppData,
    /// A Crown-Jewel Key.
    CrownJewel,
    /// A key shared with a peer.
    Share,
}

/// What an envelope's associated data says: where the envelope belongs.
/// Canonical CBOR of this is the AEAD's associated data (§4).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Aad {
    /// The profile the key belongs to.
    pub profile_id: Id,
    /// The persona the key belongs to, or none for identity-wide keys.
    pub persona_id: Option<Id>,
    /// The key being wrapped.
    pub key_id: Id,
    /// What the key is for.
    pub purpose: Purpose,
    /// The app an `app-data` or `crown-jewel` key belongs to (D28). Empty
    /// for the other purposes, and then left out of the encoding, so
    /// envelopes written before this field opens unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    /// The envelope format version.
    pub v: u16,
}

impl Aad {
    /// The bytes handed to the AEAD.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_canonical(self)
    }
}

impl fmt::Display for Aad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.persona_id {
            Some(p) => write!(
                f,
                "{:?} key {} of persona {} in profile {}",
                self.purpose, self.key_id, p, self.profile_id
            )?,
            None => write!(
                f,
                "{:?} key {} of profile {}",
                self.purpose, self.key_id, self.profile_id
            )?,
        }
        if !self.app.is_empty() {
            write!(f, " for app {}", self.app)?;
        }
        Ok(())
    }
}

/// One wrapped key (§4).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct KeyEnvelope {
    /// Record format version.
    pub v: u16,
    /// The key being wrapped.
    pub key_id: Id,
    /// Who can open it.
    pub wrapped_by: KeyRef,
    /// The cipher.
    pub alg: WrapAlg,
    /// Canonical CBOR of [`Aad`]. Readers recompute it from where they found
    /// the envelope and refuse one that disagrees.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub aad: Vec<u8>,
    /// The AEAD nonce (24 random bytes).
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub nonce: Vec<u8>,
    /// The sealed key and its tag.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub ciphertext: Vec<u8>,
    /// For a public-key wrap: the KEM encapsulation the recipient's
    /// receiving key opens to get the sealing key. Absent on symmetric wraps.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Vec<u8>>")]
    pub enc: Option<Vec<u8>>,
    /// What the key is for.
    pub purpose: Purpose,
    /// The app an `app-data` or `crown-jewel` key belongs to; empty for the
    /// other purposes (D28). Also sealed into the associated data, so an
    /// envelope cannot be re-labelled to another app.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    /// When it was wrapped.
    pub created_at: Timestamp,
    /// Fields this crate does not know. Kept as read.
    #[serde(flatten)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub extra: Extra,
    /// Ed25519 signature by the ISK over the record with `sig` empty.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub sig: Vec<u8>,
}

impl KeyEnvelope {
    /// The file name this envelope is stored under: `<key_id>.<kind>.<id>.cbor`.
    pub fn file_name(&self) -> String {
        format!("{}.{}.cbor", self.key_id, self.wrapped_by)
    }
}

/// One tolerated-tier grant: the person saw a disclosure and said yes.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Consent {
    /// Record format version.
    pub v: u16,
    /// The bridge or plugin the grant is for.
    pub bridge: String,
    /// The version of the disclosure text that was shown.
    pub disclosure_version: u32,
    /// When the person agreed.
    pub granted_at: Timestamp,
    /// On which device.
    pub device_id: Id,
    /// Fields this crate does not know. Kept as read.
    #[serde(flatten)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub extra: Extra,
    /// Ed25519 signature by the ISK over the record with `sig` empty.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub sig: Vec<u8>,
}

impl Consent {
    /// The file name this consent is stored under: `<bridge>.<version>.cbor`.
    pub fn file_name(&self) -> String {
        format!("{}.{}.cbor", self.bridge, self.disclosure_version)
    }
}

/// One line of the manifest: a file, its hash, and its record version.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ManifestEntry {
    /// Path relative to the identity root, with `/` separators.
    pub path: String,
    /// SHA-256 of the file's bytes.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub hash: Vec<u8>,
    /// The record's `v`.
    pub version: u16,
}

/// A file the store once held and has since removed (D29). The chain keeps
/// saying what was there, so a removal is a recorded step, not a gap, and
/// a copy of the file put back is an unlisted file and refused.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Tombstone {
    /// The path the file had, relative to the identity root.
    pub path: String,
    /// SHA-256 of the file's last bytes.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub hash: Vec<u8>,
    /// The manifest `seq` that removed it.
    pub seq: u64,
    /// When it was removed.
    pub retired_at: Timestamp,
}

/// The signed, hash-chained list of every file in the store (§5). A reader
/// that remembers the newest manifest it accepted can tell a rollback.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Manifest {
    /// Record format version.
    pub v: u16,
    /// Rises by one on every write.
    pub seq: u64,
    /// SHA-256 of the previous manifest's bytes; empty for the first.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub prev: Vec<u8>,
    /// Every file, sorted by path.
    pub entries: Vec<ManifestEntry>,
    /// Every file that was removed, oldest first (D29). Empty until the
    /// first removal, and then left out of the encoding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<Tombstone>,
    /// When it was written.
    pub written_at: Timestamp,
    /// The device that wrote it.
    pub written_by: Id,
    /// Fields this crate does not know. Kept as read.
    #[serde(flatten)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub extra: Extra,
    /// Ed25519 signature by the ISK over the record with `sig` empty.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub sig: Vec<u8>,
}

/// What every record can do: encode, decode, sign, verify.
pub trait Record: Serialize + DeserializeOwned + Clone {
    /// The record's name, for messages and schema files.
    const NAME: &'static str;
    /// The record's `v`.
    fn version(&self) -> u16;
    /// The signature as stored.
    fn sig(&self) -> &[u8];
    /// Replaces the signature.
    fn set_sig(&mut self, sig: Vec<u8>);

    /// The record as canonical CBOR, signature included.
    fn to_bytes(&self) -> Result<Vec<u8>> {
        to_canonical(self)
    }

    /// Decodes a record and refuses a version this crate does not know.
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let record: Self = from_slice(bytes)?;
        let v = record.version();
        if v == 0 || v > RECORD_V {
            return Err(Error::RecordTooNew {
                record: Self::NAME,
                found: v,
                supported: RECORD_V,
            });
        }
        Ok(record)
    }

    /// The bytes a signature covers: the record with `sig` empty.
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.set_sig(Vec::new());
        to_canonical(&unsigned)
    }

    /// Signs the record in place.
    fn sign(&mut self, key: &SigningKey) -> Result<()> {
        let bytes = self.signed_bytes()?;
        self.set_sig(key.sign(&bytes).to_bytes().to_vec());
        Ok(())
    }

    /// Checks the signature against the given public key.
    fn verify(&self, key: &VerifyingKey) -> Result<()> {
        let bad = || Error::BadSignature(Self::NAME.to_string());
        let sig = Signature::from_slice(self.sig()).map_err(|_| bad())?;
        key.verify(&self.signed_bytes()?, &sig).map_err(|_| bad())
    }
}

macro_rules! record {
    ($t:ty, $name:literal) => {
        impl Record for $t {
            const NAME: &'static str = $name;
            fn version(&self) -> u16 {
                self.v
            }
            fn sig(&self) -> &[u8] {
                &self.sig
            }
            fn set_sig(&mut self, sig: Vec<u8>) {
                self.sig = sig;
            }
        }
    };
}

record!(Profile, "profile");
record!(Persona, "persona");
record!(Device, "device");
record!(KeyEnvelope, "key-envelope");
record!(Consent, "consent");
record!(Manifest, "manifest");

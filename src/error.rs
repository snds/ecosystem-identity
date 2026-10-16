//! One error type for the whole crate. Every message is written for the
//! person who will read it in an app, not for a log file.

/// What can go wrong when reading, writing, or opening an identity.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file could not be read or written.
    #[error("couldn't read or write the identity store: {0}")]
    Io(#[from] std::io::Error),
    /// A record's bytes did not decode as the record they claim to be.
    #[error("a record in the identity store didn't decode ({0})")]
    Decode(String),
    /// A record could not be turned into bytes (should not happen with the
    /// crate's own types; reported rather than hidden).
    #[error("a record couldn't be encoded ({0})")]
    Encode(String),
    /// The store was written by a newer format than this crate reads.
    #[error(
        "this identity store uses format {found}, newer than this app understands (format {supported}); update the app that created it"
    )]
    FormatTooNew {
        /// The major version found in `FORMAT`.
        found: u16,
        /// The major version this crate reads.
        supported: u16,
    },
    /// The `FORMAT` file is not one this crate recognises at all.
    #[error("'{0}' isn't an ecosystem identity store")]
    FormatUnknown(String),
    /// A record's `v` is a major this crate does not know.
    #[error(
        "record {record} is version {found}, newer than this app understands (version {supported})"
    )]
    RecordTooNew {
        /// Which record.
        record: &'static str,
        /// Its version.
        found: u16,
        /// The version this crate reads.
        supported: u16,
    },
    /// A signature did not check out.
    #[error(
        "the signature on {0} didn't check out; the identity store may have been tampered with"
    )]
    BadSignature(String),
    /// A file does not match what the signed manifest says about it.
    #[error("the identity store doesn't match its manifest ({0}); it may have been tampered with")]
    Tampered(String),
    /// The store is older than the newest manifest this device accepted.
    #[error(
        "the identity store was rolled back: it is at manifest {found}, but this device last accepted manifest {remembered}"
    )]
    RolledBack {
        /// The manifest sequence on disk.
        found: u64,
        /// The sequence this device remembered.
        remembered: u64,
    },
    /// An envelope's associated data names a different place than the one it
    /// was asked to open for. It was not opened.
    #[error("this key envelope belongs to {0}; it was not opened")]
    EnvelopeMoved(String),
    /// The key did not open the envelope (wrong key, or a changed ciphertext).
    #[error("the key didn't open this envelope")]
    WrongKey,
    /// Password-stretching parameters below the signed floor were refused.
    #[error("the password-stretching settings ({0}) are weaker than the floor and were refused")]
    KdfBelowFloor(String),
    /// Password-stretching parameters lower than the ones this device last
    /// accepted were refused. They only ever rise (04-security §4, D26).
    #[error(
        "the password-stretching settings ({found}) are weaker than the ones this device last accepted ({remembered}); they only ever rise, so the store was refused"
    )]
    KdfLowered {
        /// What the profile says now.
        found: crate::kdf::Argon2Params,
        /// What this device accepted last.
        remembered: crate::kdf::Argon2Params,
    },
    /// The app on the other end of a local channel could not be shown to be
    /// an ecosystem app. Nothing was shared with it.
    #[error(
        "the app on the other end of the local channel couldn't be verified as an ecosystem app ({0}); nothing was shared"
    )]
    PeerUntrusted(String),
    /// The person was shown the new device and said no. Nothing was written.
    #[error("the person declined to enrol the new device; nothing was written")]
    Declined,
    /// An enrolment request was seen before. It was refused.
    #[error("this enrolment request was already used; it was refused")]
    Replayed,
    /// The local handshake did not finish: the other app sent something
    /// unexpected, refused, or the channel closed.
    #[error("the local handshake didn't finish: {0}")]
    Handshake(String),
    /// The other side of a local channel did not answer in time.
    #[error("the other app didn't answer in time")]
    Timeout,
    /// No identity exists at the root that was probed.
    #[error("no identity exists at {0}")]
    NoIdentity(String),
    /// A profile exists but this device holds no wrap of its root key.
    #[error(
        "this device isn't enrolled in the identity; enrol it from another device or use the recovery kit"
    )]
    DeviceNotEnrolled,
    /// The platform keystore could not be used.
    #[error("the device keystore isn't available: {0}")]
    Keystore(String),
    /// The recovery kit text did not parse.
    #[error("the recovery kit didn't read correctly: {0}")]
    BadKit(String),
    /// The recovery kit does not open this identity.
    #[error("the recovery kit doesn't open this identity")]
    KitRejected,
    /// A persona, device, key, or envelope that was asked for is not there.
    #[error("{0} wasn't found")]
    NotFound(String),
    /// Anything else the caller did wrong.
    #[error("{0}")]
    Invalid(String),
    /// The operating system gave no random bytes.
    #[error("the device couldn't make a random number")]
    Random,
    /// The platform or backend is not supported by this build.
    #[error("not supported here: {0}")]
    Unsupported(String),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

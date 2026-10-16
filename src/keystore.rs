//! The device's own keys, behind the [`DeviceKeystore`] trait.
//!
//! A device holds three things the identity never stores: a symmetric unlock
//! key that wraps the IRK for local use (released only after the platform's
//! own unlock), an Ed25519 key that identifies the device, and a receiving
//! key for enrolment. On a phone or a Mac with a Secure Enclave these live in
//! hardware. [`FileKeystore`] is the file-backed implementation for Linux,
//! CI, and any desktop until the hardware backends land; the hardware
//! backends are declared below with what each must do.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::kem::{self, DEFAULT_KEM, KemAlg, KemPublicKey, KemSecretKey};
use crate::keys::{DeviceUnlockKey, SymmetricKey, random_32};
use crate::records::{Id, Platform, Timestamp};
use crate::{Error, Result};

/// What the identity needs from a device.
pub trait DeviceKeystore {
    /// The device's stable id. It names the `Device` record and the
    /// `device` wraps of the IRK.
    fn device_id(&self) -> Id;
    /// The operating system the device runs.
    fn platform(&self) -> Platform;
    /// The public half of the device's Ed25519 key (`Device.device_pub`).
    fn device_pub(&self) -> [u8; 32];
    /// Signs with the device's Ed25519 key. Used for enrolment handshakes,
    /// not for records: those are signed by the ISK.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]>;
    /// The public half of the device's receiving key (`Device.kem_pub`).
    fn kem_pub(&self) -> KemPublicKey;
    /// The private half of the receiving key, for opening an enrolment.
    fn kem_secret(&self) -> Result<KemSecretKey>;
    /// A platform attestation of the keys, when the platform offers one.
    fn attestation(&self) -> Option<Vec<u8>>;
    /// The unlock key, after the platform's own check (biometric or PIN).
    /// This is the one user-visible step of a local attach (spec §6 step 4).
    fn unlock(&self) -> Result<DeviceUnlockKey>;
}

/// Which keystore backend a build can offer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeystoreBackend {
    /// A file in the app's data directory ([`FileKeystore`]).
    File,
    /// Apple Secure Enclave ([`SecureEnclaveKeystore`]).
    SecureEnclave,
    /// Android StrongBox or TEE-backed Keystore ([`StrongBoxKeystore`]).
    StrongBox,
    /// A TPM 2.0, on Windows through Windows Hello ([`TpmKeystore`]).
    Tpm,
}

/// The backends this build can actually open, best first. Today that is the
/// file backend everywhere; the others return a clear error from `open`.
pub fn available_backends() -> Vec<KeystoreBackend> {
    vec![KeystoreBackend::File]
}

const DEVICE_KEY_V: u16 = 1;

/// What the file keystore writes: every secret the device holds.
#[derive(Serialize, Deserialize)]
struct DeviceKeyFile {
    v: u16,
    device_id: Id,
    #[serde(with = "serde_bytes")]
    unlock_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    signing_seed: [u8; 32],
    kem_alg: KemAlg,
    #[serde(with = "serde_bytes")]
    kem_seed: [u8; 32],
    created_at: Timestamp,
}

/// A keystore kept in one file, readable only by the user (mode 0600 where
/// the platform has modes). It is as safe as the user's home directory: good
/// enough for Linux, CI, and a first desktop build; not a substitute for
/// hardware on a phone. The file never leaves the device and is not part of
/// the identity store.
pub struct FileKeystore {
    path: PathBuf,
    keys: DeviceKeyFile,
    platform: Platform,
}

impl FileKeystore {
    /// Opens the keystore file, or creates it with fresh keys.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let keys = if path.exists() {
            let bytes = std::fs::read(path)?;
            let keys: DeviceKeyFile = crate::cbor::from_slice(&bytes)?;
            if keys.v != DEVICE_KEY_V {
                return Err(Error::Keystore(format!(
                    "the device key file is version {}, which this app doesn't read",
                    keys.v
                )));
            }
            keys
        } else {
            let keys = DeviceKeyFile {
                v: DEVICE_KEY_V,
                device_id: Id::new(),
                unlock_key: random_32()?,
                signing_seed: random_32()?,
                kem_alg: DEFAULT_KEM,
                kem_seed: random_32()?,
                created_at: Timestamp::now(),
            };
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            crate::store::write_private(path, &crate::cbor::to_canonical(&keys)?)?;
            keys
        };
        Ok(Self {
            path: path.to_path_buf(),
            keys,
            platform: Platform::current(),
        })
    }

    /// Where the file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.keys.signing_seed)
    }
}

impl std::fmt::Debug for FileKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FileKeystore({}, device {})",
            self.path.display(),
            self.keys.device_id
        )
    }
}

impl DeviceKeystore for FileKeystore {
    fn device_id(&self) -> Id {
        self.keys.device_id
    }

    fn platform(&self) -> Platform {
        self.platform
    }

    fn device_pub(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        Ok(self.signing_key().sign(message).to_bytes())
    }

    fn kem_pub(&self) -> KemPublicKey {
        // The seed was generated for this algorithm, so expanding it cannot fail.
        kem::kem(self.keys.kem_alg)
            .keypair(self.keys.kem_seed)
            .map(|(_, public)| public)
            .unwrap_or(KemPublicKey {
                alg: self.keys.kem_alg,
                bytes: Vec::new(),
            })
    }

    fn kem_secret(&self) -> Result<KemSecretKey> {
        Ok(KemSecretKey::from_seed(
            self.keys.kem_alg,
            self.keys.kem_seed,
        ))
    }

    fn attestation(&self) -> Option<Vec<u8>> {
        None
    }

    fn unlock(&self) -> Result<DeviceUnlockKey> {
        Ok(DeviceUnlockKey::from_bytes(self.keys.unlock_key))
    }
}

/// Apple Secure Enclave backend. Not built yet.
///
/// What it must do: keep a P-256 key in the enclave with an access control
/// of `biometryCurrentSet` or device passcode, so `unlock` triggers Face ID
/// or Touch ID; hold the 256-bit unlock key wrapped to that P-256 key with
/// ECIES (`SecKeyCreateEncryptedData`), since the enclave does no symmetric
/// work itself; keep the Ed25519 and receiving-key seeds in the keychain
/// under the shared App Group with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
/// return the DeviceCheck / App Attest assertion as `attestation`.
#[derive(Debug)]
pub struct SecureEnclaveKeystore(());

impl SecureEnclaveKeystore {
    /// Always an error in this build, with the reason.
    pub fn open() -> Result<Self> {
        Err(Error::Keystore(
            "the Secure Enclave backend isn't built yet; use FileKeystore until it is".into(),
        ))
    }
}

/// Android StrongBox / TEE backend. Not built yet.
///
/// What it must do: generate an AES-256-GCM key in the Android Keystore with
/// `setIsStrongBoxBacked(true)` when the device has it, and
/// `setUserAuthenticationRequired(true)` so `unlock` goes through
/// BiometricPrompt; wrap the 256-bit unlock key with it; keep the Ed25519
/// and receiving-key seeds encrypted under the same key; return the key
/// attestation certificate chain as `attestation`.
#[derive(Debug)]
pub struct StrongBoxKeystore(());

impl StrongBoxKeystore {
    /// Always an error in this build, with the reason.
    pub fn open() -> Result<Self> {
        Err(Error::Keystore(
            "the StrongBox backend isn't built yet; use FileKeystore until it is".into(),
        ))
    }
}

/// TPM 2.0 backend (Windows Hello on Windows, `tpm2-tss` on Linux). Not built yet.
///
/// What it must do: seal the 256-bit unlock key to the TPM with a policy
/// that needs the user's Windows Hello gesture (or a PIN on Linux), so
/// `unlock` prompts; keep the Ed25519 and receiving-key seeds sealed the
/// same way; return the TPM quote as `attestation`.
#[derive(Debug)]
pub struct TpmKeystore(());

impl TpmKeystore {
    /// Always an error in this build, with the reason.
    pub fn open() -> Result<Self> {
        Err(Error::Keystore(
            "the TPM backend isn't built yet; use FileKeystore until it is".into(),
        ))
    }
}

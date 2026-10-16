//! Account login, behind the [`AccountAuth`] trait.
//!
//! The real thing is OPAQUE (RFC 9807) against the ecosystem server, which
//! does not exist yet (04-security §3). What the identity needs from it is
//! one value: the 64-byte `export_key` the client ends up with, which mixes
//! with the Secret Key into the Account Unlock Key. [`LocalStubAuth`] is a
//! stand-in that produces an `export_key` of the right shape with no
//! server, so the account slot can be built and tested now.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::kdf::{Argon2Params, floor, hkdf_sha512, stretch};
use crate::keys::random_32;
use crate::records::Id;
use crate::{Error, Result};

/// The 64-byte key a successful login hands the client.
pub struct ExportKey(SecretBox<[u8; 64]>);

impl ExportKey {
    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// The raw bytes. Derive from them, then let them drop.
    pub fn expose(&self) -> &[u8; 64] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExportKey(…)")
    }
}

/// What the identity needs from account login.
pub trait AccountAuth {
    /// Registers the password for a profile and returns its `export_key`.
    fn register(&mut self, profile_id: &Id, password: &str) -> Result<ExportKey>;
    /// Logs in with the password and returns the same `export_key`.
    fn login(&mut self, profile_id: &Id, password: &str) -> Result<ExportKey>;
}

/// A local stand-in for OPAQUE. **Not OPAQUE.** It stretches the password
/// with Argon2id under a random server-side key that plays the OPRF key's
/// part, so the shape and the key sizes match what the real protocol gives
/// and nothing downstream has to change when it arrives.
///
/// What it does not give: a wrong password is not refused here (OPAQUE's
/// server would refuse it); it produces a different `export_key`, and the
/// account envelope then fails to open. Keep the server key: without it the
/// account slot cannot be opened again.
pub struct LocalStubAuth {
    server_key: SecretBox<[u8; 32]>,
    params: Argon2Params,
    registered: BTreeSet<Id>,
}

impl LocalStubAuth {
    /// A stub with a fresh server key.
    pub fn generate() -> Result<Self> {
        Ok(Self::new(random_32()?))
    }

    /// A stub over a kept server key.
    pub fn new(server_key: [u8; 32]) -> Self {
        Self {
            server_key: SecretBox::new(Box::new(server_key)),
            params: floor(),
            registered: BTreeSet::new(),
        }
    }

    /// The server key, to keep for next time.
    pub fn server_key(&self) -> &[u8; 32] {
        self.server_key.expose_secret()
    }

    fn export_key(&self, profile_id: &Id, password: &str) -> Result<ExportKey> {
        // Stands in for the OPRF round: the password blinded by a server key
        // the client never sees, so no salt is exposed.
        let mut info = b"ecosystem-identity/stub-auth/oprf/v1".to_vec();
        info.extend_from_slice(profile_id.as_bytes());
        let mut oprf = Zeroizing::new([0u8; 64]);
        hkdf_sha512(
            password.as_bytes(),
            Some(self.server_key.expose_secret()),
            &info,
            oprf.as_mut(),
        )?;
        // OPAQUE's stretching step, Argon2id over the OPRF output (04-security §3 step 2).
        let stretched = stretch(oprf.as_ref(), profile_id.as_bytes(), &self.params)?;
        let mut out = [0u8; 64];
        hkdf_sha512(
            stretched.as_ref(),
            None,
            b"ecosystem-identity/stub-auth/export-key/v1",
            &mut out,
        )?;
        Ok(ExportKey::from_bytes(out))
    }
}

impl fmt::Debug for LocalStubAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalStubAuth({} registered)", self.registered.len())
    }
}

impl AccountAuth for LocalStubAuth {
    fn register(&mut self, profile_id: &Id, password: &str) -> Result<ExportKey> {
        if password.chars().count() < 8 {
            return Err(Error::Invalid(
                "use a password of at least 8 characters".into(),
            ));
        }
        self.registered.insert(*profile_id);
        self.export_key(profile_id, password)
    }

    fn login(&mut self, profile_id: &Id, password: &str) -> Result<ExportKey> {
        if !self.registered.contains(profile_id) {
            return Err(Error::NotFound(format!(
                "an account for profile {profile_id}"
            )));
        }
        self.export_key(profile_id, password)
    }
}

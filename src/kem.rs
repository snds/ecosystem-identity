//! Receiving keys for shares and enrolment (spec §3): the public half lives
//! in `Persona.kem_pub` and `Device.kem_pub`; the private half is derived
//! from a 32-byte seed.
//!
//! The default is the hybrid X25519 + ML-KEM-768 combination, as X-Wing
//! (RustCrypto's `x-wing` over `ml-kem`), which builds on stable Rust. Plain
//! X25519 stays available for a build that cannot carry ML-KEM. Neither is
//! HPKE yet: that layer arrives with peer envelopes (§4 `hpke-x25519-mlkem768`).

use std::fmt;

use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use x_wing::{Decapsulate, Decapsulator, Encapsulate, KeyExport};

use crate::kdf::hkdf_sha512;
use crate::keys::{random_32, random_bytes};
use crate::{Error, Result};

/// Which key-encapsulation scheme a receiving key uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum KemAlg {
    /// X25519 alone. Not post-quantum.
    #[serde(rename = "x25519")]
    X25519,
    /// Hybrid X25519 + ML-KEM-768 (X-Wing). The default.
    #[serde(rename = "x25519-mlkem768")]
    X25519MlKem768,
}

/// The scheme new personas and devices get.
pub const DEFAULT_KEM: KemAlg = KemAlg::X25519MlKem768;

/// A receiving key's public half.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct KemPublicKey {
    /// The scheme.
    pub alg: KemAlg,
    /// The encoded public key (32 bytes for X25519, 1216 for the hybrid).
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub bytes: Vec<u8>,
}

/// A receiving key's private half: the seed it was expanded from.
pub struct KemSecretKey {
    alg: KemAlg,
    seed: SecretBox<[u8; 32]>,
}

impl KemSecretKey {
    /// Rebuilds the private half from its seed.
    pub fn from_seed(alg: KemAlg, seed: [u8; 32]) -> Self {
        Self {
            alg,
            seed: SecretBox::new(Box::new(seed)),
        }
    }

    /// The scheme.
    pub fn alg(&self) -> KemAlg {
        self.alg
    }

    /// The seed, for re-deriving the public half. Use it at once.
    pub(crate) fn seed(&self) -> &[u8; 32] {
        self.seed.expose_secret()
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecretKey({:?}, …)", self.alg)
    }
}

/// The 256-bit secret both sides end up with.
pub struct SharedSecret(SecretBox<[u8; 32]>);

impl SharedSecret {
    /// The raw bytes. Feed them to a KDF; never use them as a key directly.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(…)")
    }
}

/// What a key-encapsulation scheme does.
pub trait Kem {
    /// The scheme's id.
    fn alg(&self) -> KemAlg;
    /// The key pair a seed expands to.
    fn keypair(&self, seed: [u8; 32]) -> Result<(KemSecretKey, KemPublicKey)>;
    /// Makes a fresh shared secret for the holder of `public` and the
    /// ciphertext that carries it.
    fn encapsulate(&self, public: &KemPublicKey) -> Result<(Vec<u8>, SharedSecret)>;
    /// Recovers the shared secret from a ciphertext.
    fn decapsulate(&self, secret: &KemSecretKey, ciphertext: &[u8]) -> Result<SharedSecret>;
}

/// The scheme for an id.
pub fn kem(alg: KemAlg) -> &'static dyn Kem {
    match alg {
        KemAlg::X25519 => &X25519Kem,
        KemAlg::X25519MlKem768 => &HybridKem,
    }
}

/// A fresh key pair for `alg`.
pub fn generate(alg: KemAlg) -> Result<(KemSecretKey, KemPublicKey)> {
    kem(alg).keypair(random_32()?)
}

fn check(alg: KemAlg, found: KemAlg) -> Result<()> {
    if alg == found {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "expected a {alg:?} key, got {found:?}"
        )))
    }
}

/// X25519 as a KEM: the ciphertext is an ephemeral public key, the shared
/// secret is HKDF over the Diffie-Hellman result, bound to both public keys.
pub struct X25519Kem;

const X25519_INFO: &[u8] = b"ecosystem-identity/kem/x25519/v1";

fn x25519_shared(
    dh: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Result<SharedSecret> {
    let mut info = Vec::with_capacity(X25519_INFO.len() + 64);
    info.extend_from_slice(X25519_INFO);
    info.extend_from_slice(ephemeral_pub);
    info.extend_from_slice(recipient_pub);
    let mut out = [0u8; 32];
    hkdf_sha512(dh, None, &info, &mut out)?;
    Ok(SharedSecret(SecretBox::new(Box::new(out))))
}

impl Kem for X25519Kem {
    fn alg(&self) -> KemAlg {
        KemAlg::X25519
    }

    fn keypair(&self, seed: [u8; 32]) -> Result<(KemSecretKey, KemPublicKey)> {
        let secret = x25519_dalek::StaticSecret::from(seed);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok((
            KemSecretKey::from_seed(KemAlg::X25519, seed),
            KemPublicKey {
                alg: KemAlg::X25519,
                bytes: public.to_bytes().to_vec(),
            },
        ))
    }

    fn encapsulate(&self, public: &KemPublicKey) -> Result<(Vec<u8>, SharedSecret)> {
        check(KemAlg::X25519, public.alg)?;
        let their: [u8; 32] = public
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("an X25519 public key is 32 bytes".into()))?;
        let their = x25519_dalek::PublicKey::from(their);
        let mut seed = [0u8; 32];
        random_bytes(&mut seed)?;
        let ephemeral = x25519_dalek::StaticSecret::from(seed);
        let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
        let dh = ephemeral.diffie_hellman(&their);
        if !dh.was_contributory() {
            return Err(Error::Invalid(
                "the X25519 public key is a low-order point".into(),
            ));
        }
        let shared = x25519_shared(dh.as_bytes(), ephemeral_pub.as_bytes(), their.as_bytes())?;
        Ok((ephemeral_pub.to_bytes().to_vec(), shared))
    }

    fn decapsulate(&self, secret: &KemSecretKey, ciphertext: &[u8]) -> Result<SharedSecret> {
        check(KemAlg::X25519, secret.alg)?;
        let ephemeral: [u8; 32] = ciphertext
            .try_into()
            .map_err(|_| Error::Invalid("an X25519 ciphertext is 32 bytes".into()))?;
        let ephemeral = x25519_dalek::PublicKey::from(ephemeral);
        let ours = x25519_dalek::StaticSecret::from(*secret.seed.expose_secret());
        let our_pub = x25519_dalek::PublicKey::from(&ours);
        let dh = ours.diffie_hellman(&ephemeral);
        if !dh.was_contributory() {
            return Err(Error::Invalid(
                "the X25519 ciphertext is a low-order point".into(),
            ));
        }
        x25519_shared(dh.as_bytes(), ephemeral.as_bytes(), our_pub.as_bytes())
    }
}

/// Hybrid X25519 + ML-KEM-768 through X-Wing.
pub struct HybridKem;

impl Kem for HybridKem {
    fn alg(&self) -> KemAlg {
        KemAlg::X25519MlKem768
    }

    fn keypair(&self, seed: [u8; 32]) -> Result<(KemSecretKey, KemPublicKey)> {
        let dk = x_wing::DecapsulationKey::from(seed);
        let public = dk.encapsulation_key().to_bytes().to_vec();
        Ok((
            KemSecretKey::from_seed(KemAlg::X25519MlKem768, seed),
            KemPublicKey {
                alg: KemAlg::X25519MlKem768,
                bytes: public,
            },
        ))
    }

    fn encapsulate(&self, public: &KemPublicKey) -> Result<(Vec<u8>, SharedSecret)> {
        check(KemAlg::X25519MlKem768, public.alg)?;
        let ek = x_wing::EncapsulationKey::try_from(public.bytes.as_slice())
            .map_err(|_| Error::Invalid("the hybrid public key didn't parse".into()))?;
        let (ct, ss) = ek.encapsulate();
        Ok((
            ct.to_vec(),
            SharedSecret(SecretBox::new(Box::new(ss.into()))),
        ))
    }

    fn decapsulate(&self, secret: &KemSecretKey, ciphertext: &[u8]) -> Result<SharedSecret> {
        check(KemAlg::X25519MlKem768, secret.alg)?;
        let dk = x_wing::DecapsulationKey::from(*secret.seed.expose_secret());
        let ss = dk
            .decapsulate_slice(ciphertext)
            .map_err(|_| Error::Invalid("a hybrid ciphertext is 1120 bytes".into()))?;
        Ok(SharedSecret(SecretBox::new(Box::new(ss.into()))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_schemes_round_trip() {
        for alg in [KemAlg::X25519, KemAlg::X25519MlKem768] {
            let (sk, pk) = generate(alg).unwrap();
            let (ct, ss1) = kem(alg).encapsulate(&pk).unwrap();
            let ss2 = kem(alg).decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss1.expose(), ss2.expose(), "{alg:?}");
            let (other, _) = generate(alg).unwrap();
            assert!(
                kem(alg)
                    .decapsulate(&other, &ct)
                    .map(|s| s.expose() != ss1.expose())
                    .unwrap_or(true),
                "{alg:?}: another key gets another secret"
            );
        }
        assert_eq!(
            generate(KemAlg::X25519MlKem768).unwrap().1.bytes.len(),
            x_wing::ENCAPSULATION_KEY_SIZE
        );
    }
}

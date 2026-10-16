//! The key tree (spec §3) as typed keys, and the symmetric wrap that turns a
//! key into a [`KeyEnvelope`] (§4).
//!
//! Every key is a 256-bit value held in a [`SecretBox`], which zeroises the
//! memory when it is dropped and never prints its contents. The types differ
//! only in name, and that is the point: an `AppDataKey` cannot be handed to a
//! function that wants a `PersonaKey`.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::kem::{KemPublicKey, KemSecretKey};
use crate::records::{Aad, Id, KeyEnvelope, KeyRef, Purpose, RECORD_V, Timestamp, WrapAlg};
use crate::{Error, Result};

/// Fills `buf` from the operating system's random source.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// Thirty-two fresh random bytes.
pub fn random_32() -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    random_bytes(&mut out)?;
    Ok(out)
}

/// What every 256-bit symmetric key in the tree can do.
pub trait SymmetricKey: Sized {
    /// A key from raw bytes (for keys derived or unwrapped elsewhere).
    fn from_bytes(bytes: [u8; 32]) -> Self;
    /// The raw bytes. Use them at once; never copy them out.
    fn expose(&self) -> &[u8; 32];
    /// A fresh random key.
    fn generate() -> Result<Self> {
        Ok(Self::from_bytes(random_32()?))
    }
}

macro_rules! key32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(SecretBox<[u8; 32]>);

        impl SymmetricKey for $name {
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(SecretBox::new(Box::new(bytes)))
            }
            fn expose(&self) -> &[u8; 32] {
                self.0.expose_secret()
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self::from_bytes(*self.expose())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(…)"))
            }
        }
    };
}

key32!(
    /// The Identity Root Key. Random, 256-bit, never leaves a device unwrapped.
    /// Everything else hangs off it.
    Irk
);
key32!(
    /// A Persona Key: the wall between work, personal, and business (D13).
    PersonaKey
);
key32!(
    /// An App Data Key: what an app actually encrypts its data with, one per
    /// app per persona.
    AppDataKey
);
key32!(
    /// A Crown-Jewel Key: the high-blast-radius class, one per persona.
    CrownJewelKey
);
key32!(
    /// The key a device's keystore releases after the platform unlock. It
    /// wraps the IRK for local use so unlock never needs the kit.
    DeviceUnlockKey
);
key32!(
    /// The Account Unlock Key, derived from the password and the Secret Key
    /// (04-security §3). Opens the `account` wrap of the IRK.
    AccountUnlockKey
);
key32!(
    /// The key the recovery code alone rebuilds. Opens the `kit` wrap of the IRK.
    KitKey
);

/// Wraps `secret` under `with` and returns the envelope, not yet signed.
/// `aad` says where the envelope belongs; it is sealed into the tag, so the
/// envelope opens only where it was made for.
pub fn wrap<K: SymmetricKey>(
    secret: &[u8],
    with: &K,
    wrapped_by: KeyRef,
    aad: &Aad,
) -> Result<KeyEnvelope> {
    if aad.v != RECORD_V {
        return Err(Error::Invalid(
            "the associated data must carry the current record version".into(),
        ));
    }
    let aad_bytes = aad.to_bytes()?;
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(*with.expose()));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| Error::Invalid("couldn't seal the key".into()))?;
    Ok(KeyEnvelope {
        v: RECORD_V,
        key_id: aad.key_id,
        wrapped_by,
        alg: WrapAlg::XChaCha20Poly1305,
        aad: aad_bytes,
        nonce: nonce.to_vec(),
        ciphertext,
        enc: None,
        purpose: aad.purpose,
        app: aad.app.clone(),
        created_at: Timestamp::now(),
        extra: Default::default(),
        sig: Vec::new(),
    })
}

/// The label the peer wrap's sealing key is derived under.
const PEER_WRAP_INFO: &[u8] = b"ecosystem-identity/peer-wrap/v1";

/// The sealing key for a peer wrap: HKDF-SHA-512 over the KEM shared secret,
/// bound to the encapsulation and the recipient's public key, so a
/// ciphertext cannot be re-addressed.
fn peer_sealing_key(
    shared: &crate::kem::SharedSecret,
    enc: &[u8],
    recipient: &KemPublicKey,
) -> Result<PeerWrapKey> {
    let mut info = Vec::with_capacity(PEER_WRAP_INFO.len() + enc.len() + recipient.bytes.len());
    info.extend_from_slice(PEER_WRAP_INFO);
    info.extend_from_slice(enc);
    info.extend_from_slice(&recipient.bytes);
    Ok(PeerWrapKey::from_bytes(*crate::kdf::subkey(
        shared.expose(),
        &info,
    )?))
}

key32!(
    /// The one-time key a peer wrap seals with. Derived from the KEM shared
    /// secret; never stored.
    PeerWrapKey
);

/// Wraps `secret` to a receiving key, so only the holder of its private half
/// can open it (spec §3 "public-key wrapping between devices"). The
/// envelope's `alg` names the scheme and `enc` carries the encapsulation.
/// Not yet signed. Used by the local handshake to hand the IRK to a new
/// device.
pub fn wrap_to_peer(
    secret: &[u8],
    to: &KemPublicKey,
    wrapped_by: KeyRef,
    aad: &Aad,
) -> Result<KeyEnvelope> {
    let (enc, shared) = crate::kem::kem(to.alg).encapsulate(to)?;
    let key = peer_sealing_key(&shared, &enc, to)?;
    let mut envelope = wrap(secret, &key, wrapped_by, aad)?;
    envelope.alg = WrapAlg::for_kem(to.alg);
    envelope.enc = Some(enc);
    Ok(envelope)
}

/// Opens a peer wrap with the receiving key's private half. The same
/// place check as [`unwrap`] runs first; an envelope that names another
/// place is refused by name before any decryption.
pub fn unwrap_from_peer(
    envelope: &KeyEnvelope,
    with: &KemSecretKey,
    expected: &Aad,
) -> Result<Zeroizing<Vec<u8>>> {
    let Some(alg) = envelope.alg.kem() else {
        return Err(Error::Unsupported(
            "only envelopes wrapped to a receiving key open here".into(),
        ));
    };
    if alg != with.alg() {
        return Err(Error::WrongKey);
    }
    let enc = envelope.enc.as_deref().ok_or(Error::WrongKey)?;
    let kem = crate::kem::kem(alg);
    let shared = kem.decapsulate(with, enc)?;
    let (_, ours) = kem.keypair(*with.seed())?;
    let key = peer_sealing_key(&shared, enc, &ours)?;
    let mut symmetric = envelope.clone();
    symmetric.alg = WrapAlg::XChaCha20Poly1305;
    unwrap(&symmetric, &key, expected)
}

/// Opens a peer wrap holding a 256-bit key and types it.
pub fn unwrap_key_from_peer<K: SymmetricKey>(
    envelope: &KeyEnvelope,
    with: &KemSecretKey,
    expected: &Aad,
) -> Result<K> {
    let plain = unwrap_from_peer(envelope, with, expected)?;
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| Error::WrongKey)?;
    Ok(K::from_bytes(bytes))
}

/// Opens an envelope that was made for `expected`. An envelope whose
/// associated data names another place is refused before any decryption:
/// a hostile store cannot move a key to another persona or purpose.
pub fn unwrap<K: SymmetricKey>(
    envelope: &KeyEnvelope,
    with: &K,
    expected: &Aad,
) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.alg != WrapAlg::XChaCha20Poly1305 {
        return Err(Error::Unsupported(
            "only symmetric envelopes open here".into(),
        ));
    }
    let expected_bytes = expected.to_bytes()?;
    if envelope.aad != expected_bytes
        || envelope.key_id != expected.key_id
        || envelope.purpose != expected.purpose
        || envelope.app != expected.app
    {
        let found: Aad = crate::cbor::from_slice(&envelope.aad)
            .map_err(|_| Error::EnvelopeMoved("an unreadable place".into()))?;
        return Err(Error::EnvelopeMoved(found.to_string()));
    }
    let nonce = XNonce::try_from(envelope.nonce.as_slice()).map_err(|_| Error::WrongKey)?;
    let cipher = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(*with.expose()));
    let plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &envelope.ciphertext,
                aad: &expected_bytes,
            },
        )
        .map_err(|_| Error::WrongKey)?;
    Ok(Zeroizing::new(plain))
}

/// Opens an envelope holding a 256-bit key and types it.
pub fn unwrap_key<K: SymmetricKey, W: SymmetricKey>(
    envelope: &KeyEnvelope,
    with: &W,
    expected: &Aad,
) -> Result<K> {
    let plain = unwrap(envelope, with, expected)?;
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| Error::WrongKey)?;
    Ok(K::from_bytes(bytes))
}

/// The associated data for a key of `purpose` under `profile_id`, with no
/// app label (the IRK, a Persona Key, a share).
pub fn aad(profile_id: Id, persona_id: Option<Id>, key_id: Id, purpose: Purpose) -> Aad {
    Aad {
        profile_id,
        persona_id,
        key_id,
        purpose,
        app: String::new(),
        v: RECORD_V,
    }
}

/// The associated data for an app's key (`app-data` or `crown-jewel`)
/// under a persona: the same as [`aad`] plus the app label, so the
/// envelope opens only for that app (D28).
pub fn app_aad(profile_id: Id, persona_id: Id, key_id: Id, purpose: Purpose, app: &str) -> Aad {
    Aad {
        profile_id,
        persona_id: Some(persona_id),
        key_id,
        purpose,
        app: app.to_string(),
        v: RECORD_V,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::KeyRefKind;

    #[test]
    fn wrap_binds_to_place() {
        let irk = Irk::generate().unwrap();
        let dev = DeviceUnlockKey::generate().unwrap();
        let profile = Id::new();
        let key_id = Id::new();
        let place = aad(profile, None, key_id, Purpose::Irk);
        let env = wrap(
            irk.expose(),
            &dev,
            KeyRef::new(KeyRefKind::Device, Id::new()),
            &place,
        )
        .unwrap();
        let back: Irk = unwrap_key(&env, &dev, &place).unwrap();
        assert_eq!(back.expose(), irk.expose());

        let moved = aad(profile, Some(Id::new()), key_id, Purpose::Irk);
        assert!(matches!(
            unwrap_key::<Irk, _>(&env, &dev, &moved),
            Err(Error::EnvelopeMoved(_))
        ));
        let repurposed = aad(profile, None, key_id, Purpose::AppData);
        assert!(matches!(
            unwrap_key::<Irk, _>(&env, &dev, &repurposed),
            Err(Error::EnvelopeMoved(_))
        ));
        let other = DeviceUnlockKey::generate().unwrap();
        assert!(matches!(
            unwrap_key::<Irk, _>(&env, &other, &place),
            Err(Error::WrongKey)
        ));

        // A store that rewrites the stored aad to match still fails the tag.
        let mut forged = env.clone();
        forged.aad = moved.to_bytes().unwrap();
        assert!(matches!(
            unwrap_key::<Irk, _>(&forged, &dev, &moved),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn the_app_label_is_sealed_in() {
        let adk = AppDataKey::generate().unwrap();
        let pk = PersonaKey::generate().unwrap();
        let (profile, persona, key_id) = (Id::new(), Id::new(), Id::new());
        let mine = app_aad(profile, persona, key_id, Purpose::AppData, "mailbird");
        let env = wrap(
            adk.expose(),
            &pk,
            KeyRef::new(KeyRefKind::Persona, persona),
            &mine,
        )
        .unwrap();
        assert_eq!(env.app, "mailbird");
        assert_eq!(
            unwrap_key::<AppDataKey, _>(&env, &pk, &mine)
                .unwrap()
                .expose(),
            adk.expose()
        );
        // Asked for as another app: refused by name, before decryption.
        let theirs = app_aad(profile, persona, key_id, Purpose::AppData, "other");
        assert!(matches!(
            unwrap_key::<AppDataKey, _>(&env, &pk, &theirs),
            Err(Error::EnvelopeMoved(place)) if place.contains("for app mailbird")
        ));
        // Re-labelled on disk, aad rewritten to match: the tag fails.
        let mut relabelled = env.clone();
        relabelled.app = "other".into();
        relabelled.aad = theirs.to_bytes().unwrap();
        assert!(matches!(
            unwrap_key::<AppDataKey, _>(&relabelled, &pk, &theirs),
            Err(Error::WrongKey)
        ));
        // Label stripped: the unlabelled place is another place.
        let unlabelled = aad(profile, Some(persona), key_id, Purpose::AppData);
        assert!(matches!(
            unwrap_key::<AppDataKey, _>(&env, &pk, &unlabelled),
            Err(Error::EnvelopeMoved(_))
        ));
        // An unlabelled aad encodes exactly as it did before the field
        // existed: a map of five, not six.
        assert_eq!(unlabelled.to_bytes().unwrap()[0], 0xa5);
        assert_eq!(mine.to_bytes().unwrap()[0], 0xa6);
    }

    #[test]
    fn peer_wrap_opens_only_for_the_receiving_key_at_the_right_place() {
        use crate::kem::{KemAlg, generate};
        for alg in [KemAlg::X25519, KemAlg::X25519MlKem768] {
            let irk = Irk::generate().unwrap();
            let (sk, pk) = generate(alg).unwrap();
            let profile = Id::new();
            let key_id = Id::new();
            let place = aad(profile, None, key_id, Purpose::Irk);
            let env = wrap_to_peer(
                irk.expose(),
                &pk,
                KeyRef::new(KeyRefKind::Peer, Id::new()),
                &place,
            )
            .unwrap();
            assert_eq!(env.alg, WrapAlg::for_kem(alg));
            assert!(env.enc.is_some());
            let back: Irk = unwrap_key_from_peer(&env, &sk, &place).unwrap();
            assert_eq!(back.expose(), irk.expose(), "{alg:?}");

            let (other, _) = generate(alg).unwrap();
            assert!(matches!(
                unwrap_key_from_peer::<Irk>(&env, &other, &place),
                Err(Error::WrongKey)
            ));
            let moved = aad(profile, Some(Id::new()), key_id, Purpose::Irk);
            assert!(matches!(
                unwrap_key_from_peer::<Irk>(&env, &sk, &moved),
                Err(Error::EnvelopeMoved(_))
            ));
            // A symmetric key does not open a peer wrap, and the other way round.
            let dev = DeviceUnlockKey::generate().unwrap();
            assert!(matches!(
                unwrap_key::<Irk, _>(&env, &dev, &place),
                Err(Error::Unsupported(_))
            ));
            let sym = wrap(
                irk.expose(),
                &dev,
                KeyRef::new(KeyRefKind::Device, Id::new()),
                &place,
            )
            .unwrap();
            assert!(matches!(
                unwrap_key_from_peer::<Irk>(&sym, &sk, &place),
                Err(Error::Unsupported(_))
            ));
        }
    }
}

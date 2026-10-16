//! The recovery kit (spec §0, §8): a Secret Key and a recovery code on one
//! printed page. The recovery code alone rebuilds the key that opens the
//! `kit` wrap of the IRK; the Secret Key joins the password in the Account
//! Unlock Key (04-security §3).
//!
//! Both are written in Crockford base32 with dashes, which survives a
//! printer, a photo, and a tired person typing: no `I`, `L`, `O`, or `U`,
//! and the reader forgives case, spaces, and the look-alike letters.

use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::kdf::{Argon2Params, stretch};
use crate::keys::{KitKey, SymmetricKey, random_bytes};
use crate::records::Id;
use crate::{Error, Result};

/// The Secret Key: 128 random bits. Shown as `A1-` and 26 characters.
pub struct SecretKey(SecretBox<[u8; 16]>);

impl SecretKey {
    /// The raw bytes, for the Account Unlock Key.
    pub fn expose(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

/// The recovery code: 160 random bits. Shown as 8 groups of 4 characters.
pub struct RecoveryCode(SecretBox<[u8; 20]>);

/// The version prefix on a Secret Key, so a later format can be told apart.
pub const SECRET_KEY_PREFIX: &str = "A1";

const KIT_SALT_INFO: &[u8] = b"ecosystem-identity/kit/v1";

/// One person's recovery kit.
pub struct RecoveryKit {
    profile_id: Id,
    secret_key: SecretKey,
    recovery_code: RecoveryCode,
}

impl RecoveryKit {
    /// A fresh kit for a profile.
    pub fn generate(profile_id: Id) -> Result<Self> {
        let mut sk = [0u8; 16];
        random_bytes(&mut sk)?;
        let mut code = [0u8; 20];
        random_bytes(&mut code)?;
        Ok(Self {
            profile_id,
            secret_key: SecretKey(SecretBox::new(Box::new(sk))),
            recovery_code: RecoveryCode(SecretBox::new(Box::new(code))),
        })
    }

    /// A kit from what the person typed.
    pub fn from_text(profile_id: Id, secret_key: &str, recovery_code: &str) -> Result<Self> {
        let mut sk_text = normalize(secret_key);
        if sk_text.len() == 28 && sk_text.starts_with(SECRET_KEY_PREFIX) {
            sk_text.drain(..2);
        }
        let sk = decode(&sk_text, 16).map_err(|e| Error::BadKit(format!("Secret Key: {e}")))?;
        let code = decode(&normalize(recovery_code), 20)
            .map_err(|e| Error::BadKit(format!("recovery code: {e}")))?;
        let sk: [u8; 16] = sk
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadKit("Secret Key: wrong length".into()))?;
        let code: [u8; 20] = code
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadKit("recovery code: wrong length".into()))?;
        Ok(Self {
            profile_id,
            secret_key: SecretKey(SecretBox::new(Box::new(sk))),
            recovery_code: RecoveryCode(SecretBox::new(Box::new(code))),
        })
    }

    /// The profile the kit belongs to.
    pub fn profile_id(&self) -> Id {
        self.profile_id
    }

    /// The Secret Key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// The Secret Key as printed: `A1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
    pub fn secret_key_text(&self) -> String {
        let raw = encode(self.secret_key.expose());
        format!(
            "{SECRET_KEY_PREFIX}-{}-{}-{}-{}-{}",
            &raw[..5],
            &raw[5..10],
            &raw[10..15],
            &raw[15..20],
            &raw[20..]
        )
    }

    /// The recovery code as printed: 8 groups of 4.
    pub fn recovery_code_text(&self) -> String {
        let raw = encode(self.recovery_code.0.expose_secret());
        raw.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// The key the recovery code rebuilds, stretched with the profile's
    /// signed parameters and salted with the profile id.
    pub fn kit_key(&self, params: &Argon2Params) -> Result<KitKey> {
        let mut salt = Zeroizing::new(KIT_SALT_INFO.to_vec());
        salt.extend_from_slice(self.profile_id.as_bytes());
        let out = stretch(self.recovery_code.0.expose_secret(), &salt, params)?;
        Ok(KitKey::from_bytes(*out))
    }
}

impl fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryKit(profile {}, …)", self.profile_id)
    }
}

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

fn decode(text: &str, len: usize) -> std::result::Result<Vec<u8>, String> {
    let want = (len * 8).div_ceil(5);
    if text.len() != want {
        return Err(format!("expected {want} characters, got {}", text.len()));
    }
    let mut out = Vec::with_capacity(len);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let Some(v) = ALPHABET.iter().position(|&a| a == c) else {
            return Err(format!("'{}' isn't a valid character", c as char));
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 255) as u8);
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return Err("the last character is wrong".into());
    }
    out.truncate(len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_text_round_trips_and_forgives_typing() {
        let kit = RecoveryKit::generate(Id::new()).unwrap();
        let sk = kit.secret_key_text();
        let code = kit.recovery_code_text();
        assert_eq!(sk.len(), 2 + 1 + 26 + 4, "{sk}");
        assert_eq!(code.len(), 32 + 7, "{code}");
        let typed_sk = sk
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        let back =
            RecoveryKit::from_text(kit.profile_id(), &typed_sk, &code.to_lowercase()).unwrap();
        assert_eq!(back.secret_key().expose(), kit.secret_key().expose());
        assert_eq!(
            back.kit_key(&crate::kdf::FLOOR_TEST).unwrap().expose(),
            kit.kit_key(&crate::kdf::FLOOR_TEST).unwrap().expose()
        );
        assert!(RecoveryKit::from_text(kit.profile_id(), &sk[..10], &code).is_err());
        assert!(
            RecoveryKit::from_text(kit.profile_id(), &sk, &format!("{}U", &code[..38])).is_err()
        );
    }
}

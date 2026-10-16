//! Password stretching and key derivation.
//!
//! - Argon2id turns the recovery code (and, in the local stub, a password)
//!   into a key. Parameters are chosen on the device, stored signed in the
//!   profile, and refused below a floor (spec §3, 04-security §4).
//! - HKDF-SHA-512 derives the Account Unlock Key (04-security §3) and the
//!   sub-keys that hang off the IRK and the Persona Keys.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::keys::{AccountUnlockKey, SymmetricKey};
use crate::records::Id;
use crate::{Error, Result};

/// Argon2id parameters. Memory is in KiB; `t_cost` is passes; `p_cost` is lanes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Passes over the memory.
    pub t_cost: u32,
    /// Lanes (parallelism).
    pub p_cost: u32,
}

impl Argon2Params {
    /// Whether every parameter is at or above the floor's.
    pub fn meets(&self, floor: &Argon2Params) -> bool {
        self.m_cost_kib >= floor.m_cost_kib
            && self.t_cost >= floor.t_cost
            && self.p_cost >= floor.p_cost
    }

    /// The higher of two parameter sets, taken per parameter. Used so a
    /// recalibration can only raise what is already there.
    pub fn max(&self, other: &Argon2Params) -> Argon2Params {
        Argon2Params {
            m_cost_kib: self.m_cost_kib.max(other.m_cost_kib),
            t_cost: self.t_cost.max(other.t_cost),
            p_cost: self.p_cost.max(other.p_cost),
        }
    }

    /// Refuses parameters below this build's floor.
    pub fn check_floor(&self) -> Result<()> {
        if self.meets(&floor()) {
            Ok(())
        } else {
            Err(Error::KdfBelowFloor(self.to_string()))
        }
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| Error::Invalid(format!("bad Argon2id parameters: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl std::fmt::Display for Argon2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} MiB, {} passes, {} lanes",
            self.m_cost_kib / 1024,
            self.t_cost,
            self.p_cost
        )
    }
}

/// Desktop floor: 64 MiB, 3 passes, 4 lanes (spec §3).
pub const FLOOR_DESKTOP: Argon2Params = Argon2Params {
    m_cost_kib: 64 * 1024,
    t_cost: 3,
    p_cost: 4,
};
/// Mobile floor: 32 MiB, 3 passes, 2 lanes (04-security §4, marked uncertain there).
pub const FLOOR_MOBILE: Argon2Params = Argon2Params {
    m_cost_kib: 32 * 1024,
    t_cost: 3,
    p_cost: 2,
};
/// Browser (WASM) floor: 32 MiB, 3 passes, 1 lane (04-security §4, marked uncertain there).
pub const FLOOR_WASM: Argon2Params = Argon2Params {
    m_cost_kib: 32 * 1024,
    t_cost: 3,
    p_cost: 1,
};
/// The floor tests run at, so a debug build finishes in milliseconds. Only
/// in effect under `cfg(test)` or the `insecure-test-kdf` feature.
pub const FLOOR_TEST: Argon2Params = Argon2Params {
    m_cost_kib: 256,
    t_cost: 1,
    p_cost: 1,
};

/// The floor for the platform this binary was built for.
pub fn platform_floor() -> Argon2Params {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        FLOOR_MOBILE
    } else if cfg!(target_family = "wasm") {
        FLOOR_WASM
    } else {
        FLOOR_DESKTOP
    }
}

/// The floor this build enforces: the platform floor, or [`FLOOR_TEST`] in
/// the crate's own tests.
pub fn floor() -> Argon2Params {
    if cfg!(any(test, feature = "insecure-test-kdf")) {
        FLOOR_TEST
    } else {
        platform_floor()
    }
}

/// Picks parameters for this device: the floor, with passes added until one
/// stretch takes about `target`. Parameters never go below the floor and the
/// pass count stops at ten, so a slow device gets a slow unlock rather than
/// a weak one.
pub fn calibrate(target: Duration) -> Result<Argon2Params> {
    calibrate_at_least(&floor(), target)
}

/// Like [`calibrate`], but never returns anything below `previous` in any
/// parameter: calibration may only raise what a profile already carries
/// (04-security §4, D26). Starts from the higher of `previous` and the floor.
pub fn calibrate_at_least(previous: &Argon2Params, target: Duration) -> Result<Argon2Params> {
    let mut params = previous.max(&floor());
    loop {
        let started = Instant::now();
        stretch(b"calibration", b"calibration-salt", &params)?;
        if started.elapsed() >= target || params.t_cost >= 10 {
            return Ok(params);
        }
        params.t_cost += 1;
    }
}

/// Argon2id over `secret` with `salt`, refusing parameters below the floor.
pub fn stretch(secret: &[u8], salt: &[u8], params: &Argon2Params) -> Result<Zeroizing<[u8; 32]>> {
    params.check_floor()?;
    let mut out = Zeroizing::new([0u8; 32]);
    params
        .to_argon2()?
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| Error::Invalid(format!("Argon2id failed: {e}")))?;
    Ok(out)
}

/// HKDF-SHA-512: `out` is filled from `ikm`, `salt`, and `info`.
pub fn hkdf_sha512(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha512>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| Error::Invalid("HKDF output too long".into()))
}

/// A 256-bit sub-key of `ikm` for `info`, with no salt. Used for the keys
/// that are derived rather than stored: the ISK from the IRK, a persona's
/// receiving key from its Persona Key.
pub fn subkey(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_sha512(ikm, None, info, out.as_mut())?;
    Ok(out)
}

/// The `info` string for the Account Unlock Key, as 04-security §3 writes it.
pub const AUK_INFO: &[u8] = b"lockdown/auk/v1";

/// `AUK = HKDF-SHA-512(ikm = export_key ‖ SK, salt = profile_id, info = AUK_INFO)`
/// (04-security §3 step 4). With the Secret Key opted out the `SK` part is
/// empty and the format stays one.
pub fn account_unlock_key(
    export_key: &[u8; 64],
    secret_key: Option<&[u8; 16]>,
    profile_id: &Id,
) -> Result<AccountUnlockKey> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(80));
    ikm.extend_from_slice(export_key);
    if let Some(sk) = secret_key {
        ikm.extend_from_slice(sk);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_sha512(&ikm, Some(profile_id.as_bytes()), AUK_INFO, out.as_mut())?;
    Ok(AccountUnlockKey::from_bytes(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_is_enforced() {
        let weak = Argon2Params {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        };
        assert!(
            !weak.meets(&FLOOR_DESKTOP),
            "OWASP's server number is below the desktop floor"
        );
        assert!(FLOOR_DESKTOP.meets(&FLOOR_DESKTOP));
        assert!(
            Argon2Params {
                m_cost_kib: 128 * 1024,
                ..FLOOR_DESKTOP
            }
            .meets(&FLOOR_DESKTOP)
        );
        let below_test_floor = Argon2Params {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(matches!(
            stretch(b"x", b"salt-salt", &below_test_floor),
            Err(Error::KdfBelowFloor(_))
        ));
        assert!(stretch(b"x", b"salt-salt", &FLOOR_TEST).is_ok());
    }

    #[test]
    fn auk_changes_with_every_input() {
        let ek = [7u8; 64];
        let sk = [9u8; 16];
        let p = Id::new();
        let a = account_unlock_key(&ek, Some(&sk), &p).unwrap();
        assert_eq!(
            a.expose(),
            account_unlock_key(&ek, Some(&sk), &p).unwrap().expose()
        );
        assert_ne!(
            a.expose(),
            account_unlock_key(&ek, None, &p).unwrap().expose()
        );
        assert_ne!(
            a.expose(),
            account_unlock_key(&ek, Some(&sk), &Id::new())
                .unwrap()
                .expose()
        );
    }
}

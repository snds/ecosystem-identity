//! Who is on the other end of the channel (03-architecture §7, D4). A
//! verifier turns what the transport knows about the peer process into a
//! yes with an app name, or [`Error::PeerUntrusted`]. Both sides run one
//! before any key material moves.
//!
//! | Platform | What the real verifier does |
//! |---|---|
//! | macOS / iOS | audit token of the connecting process → `SecCode` → signing identity and team against an allow-list ([`CodeSignatureVerifier`], not built yet) |
//! | Windows | `GetNamedPipeClientProcessId` → open the process → Authenticode signature and, where packaged, the MSIX package family ([`CodeSignatureVerifier`], not built yet) |
//! | Linux | `SO_PEERCRED` → same user → `/proc/<pid>/exe` → path and binary hash against the installed manifest ([`ProcessIdentityVerifier`], built) |
//! | Android | Binder calling UID → package signature must match the ecosystem signing key (not built yet) |
//!
//! Linux is the weakest of the four, which is why the handshake also shows
//! a short authentication string and asks the person on the running app.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{PeerIdentity, PeerVerifier, TrustedPeer};
use crate::{Error, Result};

/// Trusts every peer. For tests and for a build that has no verifier on
/// its platform yet and says so to the person.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl PeerVerifier for AllowAll {
    fn verify(&self, _peer: &PeerIdentity) -> Result<TrustedPeer> {
        Ok(TrustedPeer {
            app: "allow-all".into(),
        })
    }
}

/// Answers from a script, in order: `Ok(app)` trusts the next peer as that
/// app, `Err(reason)` refuses it. When the script runs out, every peer is
/// refused. For tests.
#[derive(Debug, Default)]
pub struct Scripted {
    answers: Mutex<VecDeque<std::result::Result<String, String>>>,
}

impl Scripted {
    /// A verifier that gives these answers, first to last.
    pub fn new<I>(answers: I) -> Self
    where
        I: IntoIterator<Item = std::result::Result<String, String>>,
    {
        Self {
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }

    /// A verifier that trusts the next `n` peers as `app`.
    pub fn trusting(app: &str, n: usize) -> Self {
        Self::new(std::iter::repeat_n(Ok(app.to_string()), n))
    }

    /// A verifier that refuses the next `n` peers with `reason`.
    pub fn refusing(reason: &str, n: usize) -> Self {
        Self::new(std::iter::repeat_n(Err(reason.to_string()), n))
    }
}

impl PeerVerifier for Scripted {
    fn verify(&self, _peer: &PeerIdentity) -> Result<TrustedPeer> {
        let next = self
            .answers
            .lock()
            .map_err(|_| Error::PeerUntrusted("the scripted verifier is poisoned".into()))?
            .pop_front();
        match next {
            Some(Ok(app)) => Ok(TrustedPeer { app }),
            Some(Err(reason)) => Err(Error::PeerUntrusted(reason)),
            None => Err(Error::PeerUntrusted(
                "the scripted verifier has no answer left".into(),
            )),
        }
    }
}

/// A signing identity the code-signature verifier would accept.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningIdentity {
    /// The app id this identity stands for.
    pub app: String,
    /// Apple: the Team ID; Windows: the certificate's subject or the MSIX
    /// package family name.
    pub signer: String,
    /// Apple: the bundle id; Windows: the package name. `None` accepts any
    /// binary by that signer.
    pub identifier: Option<String>,
}

/// Code-signature verification for Apple and Windows. Not built yet: every
/// peer is refused with a message that says so.
///
/// What it must do on macOS and iOS: take the connecting process's audit
/// token from the XPC connection, make a `SecCode` from it
/// (`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit`),
/// check it with `SecCodeCheckValidity` against a requirement of the form
/// `anchor apple generic and certificate leaf[subject.OU] = "<team>"`, and
/// read the signing identifier for the bundle id. On Windows: take the
/// client's process id from the pipe (`GetNamedPipeClientProcessId`), open
/// the process, get its image path, verify the Authenticode signature with
/// `WinVerifyTrust`, and compare the signer; for a packaged app also read
/// the package family name (`GetPackageFamilyName`). Both must hold the
/// process open for the whole check so the binary cannot be swapped.
#[derive(Clone, Debug, Default)]
pub struct CodeSignatureVerifier {
    allowed: Vec<SigningIdentity>,
}

impl CodeSignatureVerifier {
    /// A verifier that would accept these identities.
    pub fn new(allowed: Vec<SigningIdentity>) -> Self {
        Self { allowed }
    }

    /// The identities it would accept.
    pub fn allowed(&self) -> &[SigningIdentity] {
        &self.allowed
    }
}

impl PeerVerifier for CodeSignatureVerifier {
    fn verify(&self, _peer: &PeerIdentity) -> Result<TrustedPeer> {
        Err(Error::PeerUntrusted(
            if cfg!(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "windows"
            )) {
                "code-signature verification isn't built yet on this platform, so no app can be trusted over the local channel"
                .into()
            } else {
                "code-signature verification doesn't apply on this platform; use process identity"
                    .into()
            },
        ))
    }
}

/// A binary the process-identity verifier accepts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AllowedBinary {
    /// The app id this binary is.
    pub app: String,
    /// Where it is installed. Compared after resolving symlinks.
    pub path: PathBuf,
    /// SHA-256 of the binary, when the installed manifest has one. `None`
    /// trusts the path alone (weaker; fine for a development build).
    pub sha256: Option<[u8; 32]>,
}

/// Process-identity verification for Linux (03-architecture §7): the peer
/// must run as the same user, and its executable (read through
/// `/proc/<pid>/exe`, which names the running image even after an upgrade
/// replaces the file) must be one of the allowed binaries by path and, when
/// a hash is given, by content. The hash is read through the same `/proc`
/// link, so it covers the image that is running.
///
/// On other platforms it refuses every peer: Apple and Windows use
/// [`CodeSignatureVerifier`]; Android checks the calling UID's package
/// signature in the shell.
#[derive(Clone, Debug, Default)]
pub struct ProcessIdentityVerifier {
    allowed: Vec<AllowedBinary>,
}

impl ProcessIdentityVerifier {
    /// A verifier that accepts these binaries.
    pub fn new(allowed: Vec<AllowedBinary>) -> Self {
        Self { allowed }
    }

    /// The binaries it accepts.
    pub fn allowed(&self) -> &[AllowedBinary] {
        &self.allowed
    }

    /// SHA-256 of a binary on disk, for building an [`AllowedBinary`].
    pub fn hash_of(path: &Path) -> Result<[u8; 32]> {
        Ok(crate::store::sha256(&std::fs::read(path)?))
    }
}

impl PeerVerifier for ProcessIdentityVerifier {
    fn verify(&self, peer: &PeerIdentity) -> Result<TrustedPeer> {
        let PeerIdentity::Unix { pid, uid, exe, .. } = peer else {
            return Err(Error::PeerUntrusted(
                "the channel didn't say which process is on the other end".into(),
            ));
        };
        if *uid != current_uid()? {
            return Err(Error::PeerUntrusted(
                "the app on the other end runs as another user".into(),
            ));
        }
        let Some(exe) = exe else {
            return Err(Error::PeerUntrusted(
                "the other app's executable couldn't be read".into(),
            ));
        };
        let exe = exe.canonicalize().unwrap_or_else(|_| exe.clone());
        let Some(allowed) = self.allowed.iter().find(|a| {
            a.path
                .canonicalize()
                .map(|p| p == exe)
                .unwrap_or(a.path == exe)
        }) else {
            return Err(Error::PeerUntrusted(format!(
                "{} isn't an installed ecosystem app",
                exe.display()
            )));
        };
        if let Some(want) = allowed.sha256 {
            let image = match pid {
                Some(pid) if cfg!(target_os = "linux") => PathBuf::from(format!("/proc/{pid}/exe")),
                _ => exe.clone(),
            };
            let have = Self::hash_of(&image).map_err(|_| {
                Error::PeerUntrusted("the other app's executable couldn't be hashed".into())
            })?;
            if have != want {
                return Err(Error::PeerUntrusted(format!(
                    "{} isn't the binary the ecosystem installed",
                    exe.display()
                )));
            }
        }
        Ok(TrustedPeer {
            app: allowed.app.clone(),
        })
    }
}

#[cfg(unix)]
fn current_uid() -> Result<u32> {
    // SAFETY: getuid takes no arguments, cannot fail, and touches no memory.
    Ok(unsafe { libc::getuid() })
}

#[cfg(not(unix))]
fn current_uid() -> Result<u32> {
    Err(Error::PeerUntrusted(
        "process identity isn't available on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_answers_in_order_then_refuses() {
        let v = Scripted::new([Ok("mailbird".to_string()), Err("unsigned".to_string())]);
        assert_eq!(v.verify(&PeerIdentity::InProcess).unwrap().app, "mailbird");
        assert!(matches!(
            v.verify(&PeerIdentity::InProcess),
            Err(Error::PeerUntrusted(r)) if r == "unsigned"
        ));
        assert!(matches!(
            v.verify(&PeerIdentity::InProcess),
            Err(Error::PeerUntrusted(_))
        ));
        assert!(matches!(
            CodeSignatureVerifier::default().verify(&PeerIdentity::InProcess),
            Err(Error::PeerUntrusted(_))
        ));
        assert!(matches!(
            ProcessIdentityVerifier::default().verify(&PeerIdentity::InProcess),
            Err(Error::PeerUntrusted(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn process_identity_checks_user_path_and_hash() {
        let exe = std::env::current_exe().unwrap();
        let me = PeerIdentity::Unix {
            pid: Some(std::process::id() as i32),
            uid: current_uid().unwrap(),
            gid: 0,
            exe: Some(exe.clone()),
        };
        let hash = ProcessIdentityVerifier::hash_of(&exe).unwrap();
        let good = ProcessIdentityVerifier::new(vec![AllowedBinary {
            app: "test".into(),
            path: exe.clone(),
            sha256: Some(hash),
        }]);
        assert_eq!(good.verify(&me).unwrap().app, "test");
        let other_user = PeerIdentity::Unix {
            pid: Some(1),
            uid: current_uid().unwrap().wrapping_add(1),
            gid: 0,
            exe: Some(exe.clone()),
        };
        assert!(matches!(
            good.verify(&other_user),
            Err(Error::PeerUntrusted(_))
        ));
        let wrong_path = ProcessIdentityVerifier::new(vec![AllowedBinary {
            app: "test".into(),
            path: PathBuf::from("/nonexistent/app"),
            sha256: None,
        }]);
        assert!(matches!(
            wrong_path.verify(&me),
            Err(Error::PeerUntrusted(_))
        ));
        let wrong_hash = ProcessIdentityVerifier::new(vec![AllowedBinary {
            app: "test".into(),
            path: exe,
            sha256: Some([0; 32]),
        }]);
        assert!(matches!(
            wrong_hash.verify(&me),
            Err(Error::PeerUntrusted(_))
        ));
    }
}

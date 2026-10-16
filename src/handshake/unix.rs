//! The first real transport: a Unix domain socket inside the identity root
//! (spec §6 step 3, "Unix socket on Linux"). The root is created `0700`, and
//! the socket file is set to `0600`, so only the same user can connect. Who
//! that process is comes from `SO_PEERCRED` (Linux) or `getpeereid` (other
//! Unix) and goes to the verifier.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::wire::{read_frame, write_frame};
use super::{PeerChannel, PeerIdentity, PeerTransport};
use crate::{Error, Result};

/// The socket's file name inside the identity root.
pub const SOCKET_NAME: &str = "handshake.sock";

/// The longest socket path we will try to bind. `sun_path` is 104 bytes on
/// macOS and the BSDs (103 usable) and 108 on Linux; 100 leaves room for the
/// terminator on every platform.
const MAX_SOCKET_PATH: usize = 100;

/// Where the handshake socket for `root` lives: inside the root when that
/// fits the platform's socket-path limit, otherwise a short, deterministic
/// path under the user's runtime or temp directory, in a `0700` directory
/// named after the user, with the file named by a hash of the root.
pub fn socket_path_for(root: &Path) -> PathBuf {
    let inside = root.join(SOCKET_NAME);
    if inside.as_os_str().len() <= MAX_SOCKET_PATH {
        return inside;
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!("snds-identity-{uid}"))
        .join(format!("{short}.sock"))
}

/// A Unix-socket transport at one path. The running app calls `accept`,
/// which binds the socket on first use; the new app calls `connect`. The
/// socket file is removed when the listening side is dropped.
pub struct UnixSocketTransport {
    path: PathBuf,
    listener: Mutex<Option<UnixListener>>,
}

impl UnixSocketTransport {
    /// The transport for the identity at `root`: the socket is
    /// `<root>/handshake.sock` (D33). A Unix socket path is limited to about
    /// 104 bytes on macOS and the BSDs and 108 on Linux, and `bind` fails
    /// with `EINVAL` or `ENAMETOOLONG` past that. When the root is too deep
    /// for that, both sides fall back to the same short path derived from
    /// the root (`socket_path_for`), so a requester and a responder that
    /// share a root always agree on where to meet.
    pub fn for_root(root: &Path) -> Self {
        Self::at(&socket_path_for(root))
    }

    /// A transport at an explicit socket path, for a shell that keeps its
    /// sockets elsewhere (a runtime directory, say).
    pub fn at(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            listener: Mutex::new(None),
        }
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Binds the socket now, so a requester that connects before the first
    /// `accept` is queued rather than refused. `accept` does this on its
    /// own if nobody called it.
    pub fn listen(&self) -> Result<()> {
        let mut guard = self
            .listener
            .lock()
            .map_err(|_| Error::Handshake("the socket listener is poisoned".into()))?;
        if guard.is_some() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        // A socket file left by a crashed app would make bind fail; nobody
        // can be listening on it if connect is refused.
        if self.path.exists() && UnixStream::connect(&self.path).is_err() {
            std::fs::remove_file(&self.path)?;
        }
        let listener = UnixListener::bind(&self.path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        listener.set_nonblocking(true)?;
        *guard = Some(listener);
        Ok(())
    }
}

impl std::fmt::Debug for UnixSocketTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnixSocketTransport({})", self.path.display())
    }
}

impl Drop for UnixSocketTransport {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.listener.lock()
            && guard.take().is_some()
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// One connection over the socket.
pub struct UnixChannel {
    stream: UnixStream,
    peer: PeerIdentity,
}

impl UnixChannel {
    fn new(stream: UnixStream, timeout: Duration) -> Result<Self> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let peer = peer_identity(&stream);
        Ok(Self { stream, peer })
    }
}

impl std::fmt::Debug for UnixChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnixChannel({:?})", self.peer)
    }
}

impl PeerTransport for UnixSocketTransport {
    type Channel = UnixChannel;

    fn connect(&self, timeout: Duration) -> Result<UnixChannel> {
        let stream = UnixStream::connect(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::ConnectionRefused
            {
                Error::Handshake("no ecosystem app is listening on this device".into())
            } else {
                Error::Io(e)
            }
        })?;
        UnixChannel::new(stream, timeout)
    }

    fn accept(&self, timeout: Duration) -> Result<UnixChannel> {
        self.listen()?;
        let deadline = Instant::now() + timeout;
        loop {
            let accepted = {
                let guard = self
                    .listener
                    .lock()
                    .map_err(|_| Error::Handshake("the socket listener is poisoned".into()))?;
                let listener = guard
                    .as_ref()
                    .ok_or_else(|| Error::Handshake("the socket isn't listening".into()))?;
                listener.accept()
            };
            match accepted {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false)?;
                    return UnixChannel::new(stream, timeout);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }
}

impl PeerChannel for UnixChannel {
    fn send(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.stream, payload)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        self.stream.set_read_timeout(Some(timeout))?;
        read_frame(&mut self.stream)
    }

    fn peer(&self) -> PeerIdentity {
        self.peer.clone()
    }
}

/// What the kernel says about the process on the other end.
#[cfg(target_os = "linux")]
fn peer_identity(stream: &UnixStream) -> PeerIdentity {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a valid, writable `ucred` and `len` is its size;
    // getsockopt writes at most `len` bytes into it and updates `len`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return PeerIdentity::Unknown;
    }
    PeerIdentity::Unix {
        pid: Some(cred.pid),
        uid: cred.uid,
        gid: cred.gid,
        exe: std::fs::read_link(format!("/proc/{}/exe", cred.pid)).ok(),
    }
}

/// What the kernel says about the process on the other end: user and group
/// only. macOS also offers `LOCAL_PEERPID`; the audit token the real
/// verifier needs comes from XPC, not from a plain socket.
#[cfg(all(unix, not(target_os = "linux")))]
fn peer_identity(stream: &UnixStream) -> PeerIdentity {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: both out-pointers are valid for the duration of the call.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return PeerIdentity::Unknown;
    }
    PeerIdentity::Unix {
        pid: None,
        uid,
        gid,
        exe: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_root_keeps_the_socket_inside_it() {
        let root = Path::new("/tmp/id");
        assert_eq!(socket_path_for(root), root.join(SOCKET_NAME));
    }

    #[test]
    fn a_deep_root_gets_the_same_short_path_on_both_sides() {
        let deep = Path::new("/").join("x".repeat(120));
        let a = socket_path_for(&deep);
        let b = socket_path_for(&deep);
        assert_eq!(a, b);
        assert!(a.as_os_str().len() <= MAX_SOCKET_PATH, "{a:?}");
        assert_ne!(a, deep.join(SOCKET_NAME));
        assert_ne!(a, socket_path_for(&Path::new("/").join("y".repeat(120))));
    }
}

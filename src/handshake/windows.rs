//! The Windows transport: a named pipe (spec §6 step 3, "a named pipe on
//! Windows"; 03-architecture §7), the counterpart of [`super::unix`].
//!
//! - **Name**: `\\.\pipe\snds-identity-handshake-<16 hex>`, the hex being
//!   the first eight bytes of SHA-256 over the identity root's path
//!   ([`pipe_name_for`]), so both apps that share a root meet at the same
//!   pipe and two roots never share one.
//! - **Server** ([`NamedPipeTransport::listen`], `accept`): `CreateNamedPipeW`
//!   with `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance, so the
//!   running app refuses to listen on a name another program already holds;
//!   a protected DACL that grants this user and nobody else
//!   (`D:P(A;;GA;;;<user SID>)`), which is what the `0600` socket inside the
//!   `0700` root is on Unix; `PIPE_REJECT_REMOTE_CLIENTS`; byte mode; and
//!   overlapped I/O, so every wait has a timeout. A new instance is made as
//!   soon as one is taken, so a client that comes while another is served
//!   finds one waiting.
//! - **Client** (`connect`): `CreateFileW` with
//!   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the server can
//!   learn who the client is but never act as it.
//! - **Peer**: `GetNamedPipeClientProcessId` (server side) or
//!   `GetNamedPipeServerProcessId` (client side); the process is opened with
//!   `PROCESS_QUERY_LIMITED_INFORMATION` and held open for the channel's
//!   life, so its id cannot be reused by another process while the verifier
//!   looks at it; its token's user (`GetTokenInformation(TokenUser)`) and its
//!   image path (`QueryFullProcessImageNameW`) become
//!   [`PeerIdentity::Windows`]. [`super::verify::ProcessIdentityVerifier`]
//!   decides, by the same rules as on Linux and macOS.
//! - **Frames**: the same 4-byte big-endian length and 64 KiB limit as the
//!   Unix socket ([`super::wire`]).

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
};

use super::wire::{MAX_FRAME, encode_frame};
use super::{PeerChannel, PeerIdentity, PeerTransport};
use crate::{Error, Result};

/// The prefix of every handshake pipe's name.
pub const PIPE_PREFIX: &str = r"\\.\pipe\snds-identity-handshake-";

/// Each instance's buffers: one whole frame and its length.
const BUFFER: u32 = (MAX_FRAME + 4) as u32;

/// How long a client keeps trying when no instance exists yet (the moment
/// between the server taking one instance and making the next), before it
/// says nobody is listening. Short, so a requester with no running app
/// hears so at once, as it does from a refused Unix socket.
const NOT_FOUND_GRACE: Duration = Duration::from_millis(500);

/// How long one write may take before the peer counts as gone.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The handshake pipe for the identity at `root`: [`PIPE_PREFIX`] and the
/// first 16 hex digits of SHA-256 over the root's path, lower-cased first
/// because Windows paths compare without case. Deterministic, so the two
/// apps agree without telling each other, and far below the 256-character
/// limit on pipe names.
pub fn pipe_name_for(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    let path = root.as_os_str().to_string_lossy().to_lowercase();
    let digest = Sha256::digest(path.as_bytes());
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{PIPE_PREFIX}{short}")
}

fn last_error() -> u32 {
    // SAFETY: GetLastError reads this thread's last-error value.
    unsafe { GetLastError() }
}

fn os_error(call: &'static str, code: u32) -> Error {
    let e = std::io::Error::from_raw_os_error(code as i32);
    Error::Io(std::io::Error::new(e.kind(), format!("{call}: {e}")))
}

fn closed() -> Error {
    Error::Handshake("the other app closed the channel".into())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn millis(d: Duration) -> u32 {
    // INFINITE is u32::MAX; stay below it so every wait ends.
    u32::try_from(d.as_millis())
        .unwrap_or(u32::MAX - 1)
        .min(u32::MAX - 1)
}

/// An owned kernel handle, closed on drop.
struct Owned(HANDLE);

// SAFETY: a kernel handle may be used and closed from any thread; the
// wrappers below never share one between threads without `&mut` or a lock.
unsafe impl Send for Owned {}
// SAFETY: as above; `&Owned` is only ever passed to thread-safe calls.
unsafe impl Sync for Owned {}

impl Owned {
    fn new(h: HANDLE) -> Option<Self> {
        (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(Self(h))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid handle this wrapper owns.
        unsafe { CloseHandle(self.0) };
    }
}

/// An overlapped operation's state: the OVERLAPPED block (boxed, so its
/// address stays put while the kernel holds it) and its manual-reset event.
struct Io {
    ov: Box<OVERLAPPED>,
    _event: Owned,
}

// SAFETY: the OVERLAPPED block is only touched by the thread that owns the
// `Io` (through `&mut`), and its event handle is thread-safe.
unsafe impl Send for Io {}

impl Io {
    fn new() -> Result<Self> {
        // SAFETY: no attributes, manual reset, not signalled, no name.
        let event = Owned::new(unsafe { CreateEventW(null(), 1, 0, null()) })
            .ok_or_else(|| os_error("CreateEventW", last_error()))?;
        let mut ov: Box<OVERLAPPED> = Box::default();
        ov.hEvent = event.0;
        Ok(Self { ov, _event: event })
    }

    fn ptr(&mut self) -> *mut OVERLAPPED {
        &raw mut *self.ov
    }

    /// Waits up to `timeout` for the operation started on `handle`, and
    /// leaves it in flight when it has not finished (`None`).
    fn poll(&mut self, handle: HANDLE, timeout: Duration) -> Option<std::result::Result<u32, u32>> {
        let ov = self.ptr();
        // SAFETY: hEvent is the live event this block was made with.
        let waited = unsafe { WaitForSingleObject((*ov).hEvent, millis(timeout)) };
        if waited == WAIT_TIMEOUT {
            return None;
        }
        let mut moved = 0u32;
        // SAFETY: the operation on `handle` with this block has completed
        // (or the wait failed, which GetOverlappedResult then reports).
        Some(
            if unsafe { GetOverlappedResult(handle, ov, &raw mut moved, 0) } != 0 {
                Ok(moved)
            } else {
                Err(last_error())
            },
        )
    }

    /// Waits up to `timeout` for the operation started on `handle` to
    /// finish; answers the bytes moved. On timeout the operation is
    /// cancelled and waited out, so the block is free again; if it finished
    /// in that moment anyway, its result stands.
    fn finish(&mut self, handle: HANDLE, timeout: Duration) -> std::result::Result<u32, u32> {
        let ov = self.ptr();
        // SAFETY: hEvent is the live event this block was made with.
        let waited = unsafe { WaitForSingleObject((*ov).hEvent, millis(timeout)) };
        let mut moved = 0u32;
        if waited == WAIT_OBJECT_0 {
            // SAFETY: the operation on `handle` with this block completed.
            return if unsafe { GetOverlappedResult(handle, ov, &raw mut moved, 0) } != 0 {
                Ok(moved)
            } else {
                Err(last_error())
            };
        }
        // SAFETY: cancels only the operation that uses this block.
        unsafe { CancelIoEx(handle, ov) };
        // SAFETY: as above; bWait = TRUE returns once the kernel lets go.
        if unsafe { GetOverlappedResult(handle, ov, &raw mut moved, 1) } != 0 {
            return Ok(moved);
        }
        Err(if waited == WAIT_TIMEOUT {
            WAIT_TIMEOUT
        } else {
            last_error()
        })
    }
}

/// A process's user, as its token reports it.
struct UserSid {
    /// u64 words keep the TOKEN_USER block aligned.
    buf: Vec<u64>,
}

impl UserSid {
    /// The user of `process` (a handle with query rights).
    fn of(process: HANDLE) -> Option<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `process` is a valid process handle; `token` receives a
        // new handle, owned below.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
            return None;
        }
        let token = Owned::new(token)?;
        let mut need = 0u32;
        // SAFETY: a size query: no buffer, `need` receives the length.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut need) };
        if need == 0 {
            return None;
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: `buf` is at least `need` bytes and suitably aligned.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &raw mut need,
            )
        };
        (ok != 0).then_some(Self { buf })
    }

    fn mine() -> Option<Self> {
        // SAFETY: the pseudo-handle for this process; never closed.
        Self::of(unsafe { GetCurrentProcess() })
    }

    fn psid(&self) -> *mut core::ffi::c_void {
        let user = self.buf.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: `buf` holds a TOKEN_USER written by GetTokenInformation;
        // its SID pointer points into the same buffer.
        unsafe { (*user).User.Sid }
    }

    /// The SID in its string form (`S-1-5-21-…`). Two SIDs are equal
    /// exactly when these strings are.
    fn string(&self) -> Option<String> {
        let mut out: *mut u16 = null_mut();
        // SAFETY: the SID is valid; `out` receives a LocalAlloc'd string.
        if unsafe { ConvertSidToStringSidW(self.psid(), &raw mut out) } == 0 || out.is_null() {
            return None;
        }
        // SAFETY: `out` is NUL-terminated; read up to the NUL, then free it.
        let s = unsafe {
            let mut len = 0;
            while *out.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
            LocalFree(out.cast());
            s
        };
        Some(s)
    }
}

/// This process's user SID in string form, for the verifier's same-user
/// check.
pub(crate) fn current_user_sid() -> Option<String> {
    UserSid::mine().and_then(|s| s.string())
}

/// The process at the other end, held open for the channel's life so its
/// id cannot be reused.
struct Peer {
    _process: Option<Owned>,
    identity: PeerIdentity,
}

impl Peer {
    fn learn(pid: Option<u32>) -> Self {
        let Some(pid) = pid.filter(|p| *p != 0) else {
            return Self {
                _process: None,
                identity: PeerIdentity::Unknown,
            };
        };
        // SAFETY: opens the process for limited queries; owned below.
        let process = Owned::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        let Some(process) = process else {
            return Self {
                _process: None,
                identity: PeerIdentity::Windows {
                    pid,
                    sid: None,
                    exe: None,
                },
            };
        };
        let sid = UserSid::of(process.0).and_then(|s| s.string());
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` UTF-16 units; `len` receives the length.
        let exe = (unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &raw mut len,
            )
        } != 0)
            .then(|| PathBuf::from(OsString::from_wide(&buf[..len as usize])));
        Self {
            _process: Some(process),
            identity: PeerIdentity::Windows { pid, sid, exe },
        }
    }
}

/// One connection over the pipe. Dropping it closes the handle and never
/// calls `DisconnectNamedPipe`, which would throw away what the other end
/// has not read yet (a last refusal, say); each instance serves one
/// connection, so there is nothing to reuse.
pub struct PipeChannel {
    pipe: Owned,
    server: bool,
    read: Io,
    write: Io,
    peer: Peer,
}

impl std::fmt::Debug for PipeChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeChannel")
            .field("server", &self.server)
            .field("peer", &self.peer.identity)
            .finish_non_exhaustive()
    }
}

impl PipeChannel {
    fn new(pipe: Owned, server: bool) -> Result<Self> {
        let mut pid = 0u32;
        // SAFETY: `pipe` is a connected pipe handle; `pid` receives the id.
        let ok = unsafe {
            if server {
                GetNamedPipeClientProcessId(pipe.0, &raw mut pid)
            } else {
                GetNamedPipeServerProcessId(pipe.0, &raw mut pid)
            }
        };
        let peer = Peer::learn((ok != 0).then_some(pid));
        Ok(Self {
            pipe,
            server,
            read: Io::new()?,
            write: Io::new()?,
            peer,
        })
    }

    fn read_exact(&mut self, buf: &mut [u8], deadline: Instant) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout);
            }
            let want = u32::try_from(buf.len() - done).unwrap_or(u32::MAX);
            let ov = self.read.ptr();
            // SAFETY: the buffer outlives the operation, which `finish`
            // waits out before returning, and the block is free.
            let started =
                unsafe { ReadFile(self.pipe.0, buf[done..].as_mut_ptr(), want, null_mut(), ov) };
            if started == 0 {
                let code = last_error();
                if code != ERROR_IO_PENDING {
                    return Err(match code {
                        ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => closed(),
                        c => os_error("ReadFile", c),
                    });
                }
            }
            match self.read.finish(self.pipe.0, left) {
                Ok(0) => return Err(closed()),
                Ok(n) => done += n as usize,
                Err(WAIT_TIMEOUT) => return Err(Error::Timeout),
                Err(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => {
                    return Err(closed());
                }
                Err(c) => return Err(os_error("ReadFile", c)),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let deadline = Instant::now() + WRITE_TIMEOUT;
        let mut done = 0usize;
        while done < bytes.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout);
            }
            let want = u32::try_from(bytes.len() - done).unwrap_or(u32::MAX);
            let ov = self.write.ptr();
            // SAFETY: as in read_exact; the bytes outlive the operation.
            let started =
                unsafe { WriteFile(self.pipe.0, bytes[done..].as_ptr(), want, null_mut(), ov) };
            if started == 0 {
                let code = last_error();
                if code != ERROR_IO_PENDING {
                    return Err(match code {
                        ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => closed(),
                        c => os_error("WriteFile", c),
                    });
                }
            }
            match self.write.finish(self.pipe.0, left) {
                Ok(0) => return Err(closed()),
                Ok(n) => done += n as usize,
                Err(WAIT_TIMEOUT) => return Err(Error::Timeout),
                Err(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => {
                    return Err(closed());
                }
                Err(c) => return Err(os_error("WriteFile", c)),
            }
        }
        Ok(())
    }
}

impl PeerChannel for PipeChannel {
    fn send(&mut self, payload: &[u8]) -> Result<()> {
        let frame = encode_frame(payload)?;
        self.write_all(&frame)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut head = [0u8; 4];
        self.read_exact(&mut head, deadline)?;
        let len = u32::from_be_bytes(head) as usize;
        if len > MAX_FRAME {
            return Err(Error::Handshake(format!(
                "the other app announced a {len}-byte message, larger than the channel allows"
            )));
        }
        let mut body = vec![0u8; len];
        // A frame that has begun arrives whole or not at all: the rest gets
        // the same deadline.
        self.read_exact(&mut body, deadline)?;
        Ok(body)
    }

    /// [`PeerIdentity::Windows`] with the process id, its user's SID and
    /// its image path; `Unknown` when the pipe did not name a process.
    fn peer(&self) -> PeerIdentity {
        self.peer.identity.clone()
    }
}

/// A server instance waiting for a client, with its connect in flight.
struct Waiting {
    /// `None` once handed to a channel.
    pipe: Option<Owned>,
    io: Io,
    /// A client is connected (the connect finished, or the client came
    /// before `ConnectNamedPipe` was called); nothing is in flight.
    ready: bool,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if let (Some(pipe), false) = (&self.pipe, self.ready) {
            let ov = self.io.ptr();
            let mut moved = 0;
            // SAFETY: cancels this instance's pending connect and waits for
            // the kernel to release the block before it is freed.
            unsafe {
                CancelIoEx(pipe.0, ov);
                GetOverlappedResult(pipe.0, ov, &raw mut moved, 1);
            }
        }
    }
}

/// The pipe's security descriptor: this user only.
struct Descriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable once made and only read by
// CreateNamedPipeW.
unsafe impl Send for Descriptor {}
// SAFETY: as above.
unsafe impl Sync for Descriptor {}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

impl Descriptor {
    fn user_only() -> Result<Self> {
        let sid = current_user_sid()
            .ok_or_else(|| Error::Handshake("couldn't read this user's SID".into()))?;
        // Protected DACL, one entry: generic all for this user. Nobody else,
        // not even administrators, is granted access; the default
        // integrity label keeps low-integrity processes from writing.
        let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd
        // descriptor, owned by the wrapper.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(os_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                last_error(),
            ));
        }
        Ok(Self(sd))
    }
}

struct Server {
    descriptor: Descriptor,
    made_first: bool,
    waiting: Option<Waiting>,
}

/// A named-pipe transport at one name. The running app calls `listen` (or
/// just `accept`); the new app calls `connect`. Dropping the listening side
/// closes every instance it holds, which removes the pipe.
pub struct NamedPipeTransport {
    name: String,
    wide_name: Vec<u16>,
    server: Mutex<Option<Server>>,
}

impl std::fmt::Debug for NamedPipeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NamedPipeTransport({})", self.name)
    }
}

impl NamedPipeTransport {
    /// The transport for the identity at `root`, at [`pipe_name_for`]`(root)`.
    pub fn for_root(root: &Path) -> Self {
        Self::at(&pipe_name_for(root))
    }

    /// A transport at the pipe `name` (`\\.\pipe\…`), for a shell that
    /// names its pipes itself.
    pub fn at(name: &str) -> Self {
        Self {
            name: name.to_string(),
            wide_name: wide(name),
            server: Mutex::new(None),
        }
    }

    /// The pipe's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<Server>>> {
        self.server
            .lock()
            .map_err(|_| Error::Handshake("the pipe listener is poisoned".into()))
    }

    /// Makes the first instance now, so a requester that connects before
    /// the first `accept` finds it. Refused when another program already
    /// holds this name: the first instance is made with
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`. `accept` does this on its own if
    /// nobody called it.
    pub fn listen(&self) -> Result<()> {
        let mut guard = self.lock()?;
        if guard.is_none() {
            *guard = Some(Server {
                descriptor: Descriptor::user_only()?,
                made_first: false,
                waiting: None,
            });
        }
        let server = guard
            .as_mut()
            .ok_or_else(|| Error::Handshake("the pipe isn't listening".into()))?;
        if server.waiting.is_none() {
            server.waiting = Some(self.instance(server)?);
        }
        Ok(())
    }

    /// A new server instance with its connect started.
    fn instance(&self, server: &mut Server) -> Result<Waiting> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: server.descriptor.0,
            bInheritHandle: 0,
        };
        let first = if server.made_first {
            0
        } else {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        };
        // SAFETY: the name is NUL-terminated and the attributes and their
        // descriptor outlive the call.
        let pipe = Owned::new(unsafe {
            CreateNamedPipeW(
                self.wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER,
                BUFFER,
                0,
                &raw const attributes,
            )
        });
        let Some(pipe) = pipe else {
            let code = last_error();
            return Err(if code == ERROR_ACCESS_DENIED && !server.made_first {
                Error::Handshake(format!(
                    "another program already holds the pipe {}",
                    self.name
                ))
            } else {
                os_error("CreateNamedPipeW", code)
            });
        };
        server.made_first = true;
        let mut io = Io::new()?;
        let ov = io.ptr();
        // SAFETY: the pipe is a fresh server instance and the block is free.
        let ok = unsafe { ConnectNamedPipe(pipe.0, ov) };
        let ready = if ok != 0 {
            false
        } else {
            match last_error() {
                ERROR_IO_PENDING => false,
                ERROR_PIPE_CONNECTED => true,
                c => return Err(os_error("ConnectNamedPipe", c)),
            }
        };
        Ok(Waiting {
            pipe: Some(pipe),
            io,
            ready,
        })
    }
}

impl PeerTransport for NamedPipeTransport {
    type Channel = PipeChannel;

    fn connect(&self, timeout: Duration) -> Result<PipeChannel> {
        let started = Instant::now();
        let deadline = started + timeout;
        loop {
            // SAFETY: the name is NUL-terminated; the handle is owned below.
            let handle = unsafe {
                CreateFileW(
                    self.wide_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            if let Some(pipe) = Owned::new(handle) {
                return PipeChannel::new(pipe, false);
            }
            let code = last_error();
            let left = deadline.saturating_duration_since(Instant::now());
            match code {
                ERROR_PIPE_BUSY if !left.is_zero() => {
                    // SAFETY: the name is NUL-terminated.
                    unsafe { WaitNamedPipeW(self.wide_name.as_ptr(), millis(left).min(1000)) };
                }
                ERROR_FILE_NOT_FOUND if !left.is_zero() && started.elapsed() < NOT_FOUND_GRACE => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                ERROR_FILE_NOT_FOUND => {
                    return Err(Error::Handshake(
                        "no ecosystem app is listening on this device".into(),
                    ));
                }
                ERROR_PIPE_BUSY => return Err(Error::Timeout),
                c => return Err(os_error("CreateFileW", c)),
            }
        }
    }

    fn accept(&self, timeout: Duration) -> Result<PipeChannel> {
        self.listen()?;
        let mut guard = self.lock()?;
        let server = guard
            .as_mut()
            .ok_or_else(|| Error::Handshake("the pipe isn't listening".into()))?;
        let waiting = server
            .waiting
            .as_mut()
            .ok_or_else(|| Error::Handshake("no pipe instance is waiting".into()))?;
        if !waiting.ready {
            let handle = waiting
                .pipe
                .as_ref()
                .map(|p| p.0)
                .ok_or_else(|| Error::Handshake("no pipe instance is waiting".into()))?;
            match waiting.io.poll(handle, timeout) {
                // Still waiting: the connect stays in flight for the next call.
                None => return Err(Error::Timeout),
                Some(Ok(_)) => waiting.ready = true,
                // A client that came and went before we looked: start over
                // with a fresh instance.
                Some(Err(ERROR_NO_DATA | ERROR_BROKEN_PIPE)) => {
                    waiting.ready = true;
                    server.waiting = Some(self.instance(server)?);
                    return Err(Error::Timeout);
                }
                Some(Err(c)) => return Err(os_error("ConnectNamedPipe", c)),
            }
        }
        let mut taken = server
            .waiting
            .take()
            .ok_or_else(|| Error::Handshake("no pipe instance is waiting".into()))?;
        // The next client finds an instance while this one is served.
        server.waiting = Some(self.instance(server)?);
        drop(guard);
        let pipe = taken
            .pipe
            .take()
            .ok_or_else(|| Error::Handshake("no pipe instance is waiting".into()))?;
        PipeChannel::new(pipe, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_root_gets_its_own_short_pipe_name_whatever_its_case() {
        let a = pipe_name_for(Path::new(r"C:\Users\me\AppData\Local\snds\identity"));
        let b = pipe_name_for(Path::new(r"C:\Users\you\AppData\Local\snds\identity"));
        assert!(a.starts_with(PIPE_PREFIX));
        assert_eq!(a.len(), PIPE_PREFIX.len() + 16);
        assert!(a.len() < 256);
        assert_ne!(a, b);
        assert_eq!(
            a,
            pipe_name_for(Path::new(r"c:\users\ME\appdata\local\snds\identity"))
        );
        assert!(current_user_sid().is_some_and(|s| s.starts_with("S-1-")));
    }
}

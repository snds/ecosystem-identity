//! The local handshake (spec §6 step 3, §8 row 1): a second ecosystem app
//! on the same device gets the identity from the one already running, with
//! no kit and no typing.
//!
//! Who does what:
//!
//! - The **running app** holds the identity open ([`Identity`]) and runs a
//!   [`Responder`] on a [`PeerTransport`]. For each connection it checks the
//!   peer through a [`PeerVerifier`], asks the person through
//!   [`ConfirmNewDevice`] (showing a six-digit code, the [`Sas`]), signs and
//!   stores the new device's record, and hands back the root key wrapped to
//!   the new device's receiving key.
//! - The **new app** runs a [`Requester`]: it connects, checks the peer the
//!   same way, sends its device record and a nonce, shows the same code,
//!   opens the envelope with its device's receiving key, writes its own
//!   `device` wrap, and attaches.
//!
//! Transports: [`channel::ChannelTransport`] in memory (tests, one process)
//! and [`unix::UnixSocketTransport`] (Linux, macOS until XPC lands). What
//! the wire carries is in [`wire`]; who may connect is in [`verify`].
//!
//! Guarantees: one request per connection; every step has a timeout; a
//! request nonce is accepted once; the person's "no" writes nothing; the
//! code cannot be steered by whichever side speaks last (commit, then
//! reveal); and the new app refuses a root key that does not derive the
//! profile's signing key.

pub mod channel;
#[cfg(unix)]
pub mod unix;
pub mod verify;
pub mod wire;

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::attach::{Identity, signing_key};
use crate::keys::{self, Irk, SymmetricKey, random_32};
use crate::keystore::DeviceKeystore;
use crate::records::{
    Device, EnrolledBy, Id, KeyRef, KeyRefKind, Purpose, RECORD_V, Record, Timestamp,
};
use crate::store::{Head, Store};
use crate::{Error, Result};
use wire::{
    Grant, HANDSHAKE_V, Hello, Message, Refusal, RefusalReason, Request, Reveal, commitment,
    proof_of_possession_message, short_authentication_string,
};

pub use channel::ChannelTransport;
pub use verify::{AllowAll, CodeSignatureVerifier, ProcessIdentityVerifier, Scripted};

/// How long each step waits by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How many request nonces a responder remembers. Enough that a replay
/// within any plausible session is caught; bounded so memory is too.
pub const REMEMBERED_NONCES: usize = 4096;

/// What a transport knows about the process at the other end of a
/// channel. A [`PeerVerifier`] turns this into trust, or not.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PeerIdentity {
    /// The other end is in this process (the in-memory transport).
    InProcess,
    /// A Unix peer, from `SO_PEERCRED` or `getpeereid`.
    Unix {
        /// Its process id, where the platform reports one.
        pid: Option<i32>,
        /// Its user id.
        uid: u32,
        /// Its group id.
        gid: u32,
        /// Its executable, where the platform lets us read it.
        exe: Option<PathBuf>,
    },
    /// The transport could not say.
    Unknown,
}

/// One connection to a peer: framed messages in both directions. Each
/// `send` is one message; each `recv` returns one whole message.
pub trait PeerChannel {
    /// Sends one message.
    fn send(&mut self, payload: &[u8]) -> Result<()>;
    /// Waits up to `timeout` for the next message; [`Error::Timeout`] if
    /// none comes.
    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>>;
    /// What the transport knows about the other end.
    fn peer(&self) -> PeerIdentity;
}

/// A way to reach the other app on this device: XPC on Apple, a bound
/// service on Android, a named pipe on Windows, a Unix socket on Linux, or
/// memory in tests. The running app accepts; the new app connects.
pub trait PeerTransport {
    /// The connection type.
    type Channel: PeerChannel;
    /// Connects to the running app.
    fn connect(&self, timeout: Duration) -> Result<Self::Channel>;
    /// Waits up to `timeout` for a new app to connect.
    fn accept(&self, timeout: Duration) -> Result<Self::Channel>;
}

/// A peer a verifier accepted, and which app it is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustedPeer {
    /// The app id the verifier matched (for example `mailbird`).
    pub app: String,
}

/// Answers "is the process on the other end an ecosystem app I trust?"
/// (03-architecture §7, D4). Run by both sides before anything moves.
pub trait PeerVerifier {
    /// Trusts the peer as some app, or refuses with [`Error::PeerUntrusted`].
    fn verify(&self, peer: &PeerIdentity) -> Result<TrustedPeer>;
}

/// The six-digit short authentication string both apps show (spec §8).
/// The person compares them; the running app's person confirms.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sas(u32);

impl Sas {
    /// The number behind the digits, below one million.
    pub fn value(self) -> u32 {
        self.0
    }

    /// The six digits, zero-padded.
    pub fn digits(self) -> String {
        format!("{:06}", self.0)
    }
}

impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sas({:06})", self.0)
    }
}

/// What the running app shows the person before it enrols a device.
#[derive(Debug)]
pub struct NewDevice<'a> {
    /// The device as the new app describes it (not yet signed).
    pub device: &'a Device,
    /// The app the verifier says is asking.
    pub peer: &'a TrustedPeer,
    /// The code the new app is showing too.
    pub sas: Sas,
}

/// The person's say on the running app: show the device and the code, and
/// return `Ok(true)` to enrol it. Anything else writes nothing.
pub trait ConfirmNewDevice {
    /// Asks the person.
    fn confirm(&self, new_device: &NewDevice<'_>) -> Result<bool>;
}

/// Says yes to every device and remembers the last code it was shown. For
/// tests.
#[derive(Debug, Default)]
pub struct AutoConfirm {
    seen: std::sync::Mutex<Option<Sas>>,
}

impl AutoConfirm {
    /// A confirmer that has seen nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The last code it confirmed, if any.
    pub fn last_sas(&self) -> Option<Sas> {
        self.seen.lock().ok().and_then(|s| *s)
    }
}

impl ConfirmNewDevice for AutoConfirm {
    fn confirm(&self, new_device: &NewDevice<'_>) -> Result<bool> {
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(new_device.sas);
        }
        Ok(true)
    }
}

/// Says no to every device. For tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct Decline;

impl ConfirmNewDevice for Decline {
    fn confirm(&self, _new_device: &NewDevice<'_>) -> Result<bool> {
        Ok(false)
    }
}

/// Knobs for either side.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeOptions {
    /// How long to wait for a connection and for each message. The
    /// person's confirmation is not timed here; the requester waits
    /// `confirm_timeout` for it.
    pub timeout: Duration,
    /// How long the new app waits for the person on the running app to
    /// confirm or decline.
    pub confirm_timeout: Duration,
}

impl Default for HandshakeOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            confirm_timeout: Duration::from_secs(120),
        }
    }
}

/// What a successful handshake gave the running app.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Enrolled {
    /// The new device's id.
    pub device_id: Id,
    /// The new device's name.
    pub device_name: String,
    /// The app the verifier matched.
    pub app: String,
    /// The code the person confirmed.
    pub sas: Sas,
    /// The store head after the device was added.
    pub head: Head,
}

/// Request nonces seen so far, oldest first.
#[derive(Debug, Default)]
struct SeenNonces {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl SeenNonces {
    /// Remembers `nonce`; `false` if it was already there.
    fn insert(&mut self, nonce: [u8; 32]) -> bool {
        if !self.set.insert(nonce) {
            return false;
        }
        self.order.push_back(nonce);
        while self.order.len() > REMEMBERED_NONCES {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// The running app's side. Keep one for as long as the app listens: it
/// remembers the request nonces it has seen, so a replay is refused. It
/// can move to a background thread, which is why its verifier and
/// confirmer must be `Sync`.
pub struct Responder<'a> {
    verifier: &'a (dyn PeerVerifier + Sync),
    confirm: &'a (dyn ConfirmNewDevice + Sync),
    options: HandshakeOptions,
    seen: SeenNonces,
}

impl fmt::Debug for Responder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Responder")
            .field("options", &self.options)
            .field("seen", &self.seen.order.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Responder<'a> {
    /// A responder that checks peers with `verifier` and asks the person
    /// through `confirm`.
    pub fn new(
        verifier: &'a (dyn PeerVerifier + Sync),
        confirm: &'a (dyn ConfirmNewDevice + Sync),
        options: HandshakeOptions,
    ) -> Self {
        Self {
            verifier,
            confirm,
            options,
            seen: SeenNonces::default(),
        }
    }

    /// Accepts one connection, serves one request on it, and closes it.
    /// On success the new device is in `identity`'s store, signed, and the
    /// manifest has advanced. On any failure nothing was written, except
    /// that a refused nonce stays refused.
    pub fn serve_one<T: PeerTransport>(
        &mut self,
        identity: &mut Identity,
        transport: &T,
    ) -> Result<Enrolled> {
        let timeout = self.options.timeout;
        let mut chan = transport.accept(timeout)?;
        let peer = match self.verifier.verify(&chan.peer()) {
            Ok(peer) => peer,
            Err(e) => {
                let _ = refuse(&mut chan, RefusalReason::Untrusted, &e.to_string());
                return Err(e);
            }
        };
        let own = identity
            .devices()
            .find(|d| d.device_id == identity.device_id())
            .cloned()
            .ok_or_else(|| Error::NotFound("this device's own record".into()))?;
        let profile_id = identity.profile().profile_id;

        let responder_nonce = random_32()?;
        send(
            &mut chan,
            &Message::Hello(Hello {
                v: HANDSHAKE_V,
                profile_id,
                device_id: own.device_id,
                kem_pub: own.kem_pub.clone(),
                commit: commitment(&responder_nonce),
            }),
        )?;

        let request = match recv(&mut chan, timeout)? {
            Message::Request(r) => r,
            Message::Refused(r) => return Err(r.into_error()),
            other => {
                return Err(bad_request(
                    &mut chan,
                    format!("expected a request, got {}", other.name()),
                ));
            }
        };
        if request.v != HANDSHAKE_V {
            return Err(bad_request(
                &mut chan,
                format!("handshake version {} isn't one this app speaks", request.v),
            ));
        }
        if !self.seen.insert(request.nonce) {
            let _ = refuse(
                &mut chan,
                RefusalReason::Replayed,
                "this request was already used",
            );
            return Err(Error::Replayed);
        }
        let device = &request.device;
        if let Err(why) = check_proposed_device(device, own.device_id) {
            return Err(bad_request(&mut chan, why));
        }
        if identity.devices().any(|d| d.device_id == device.device_id) {
            let _ = refuse(
                &mut chan,
                RefusalReason::AlreadyEnrolled,
                "this device is already enrolled",
            );
            return Err(Error::Invalid("this device is already enrolled".into()));
        }
        if let Err(why) =
            check_proof_of_possession(&request, profile_id, &commitment(&responder_nonce))
        {
            return Err(bad_request(&mut chan, why));
        }

        let sas = Sas(short_authentication_string(
            &request.nonce,
            &responder_nonce,
            &device.kem_pub,
            &own.kem_pub,
        ));
        send(
            &mut chan,
            &Message::Reveal(Reveal {
                v: HANDSHAKE_V,
                nonce: responder_nonce,
            }),
        )?;

        let confirmed = self.confirm.confirm(&NewDevice {
            device,
            peer: &peer,
            sas,
        });
        if !matches!(confirmed, Ok(true)) {
            let _ = refuse(
                &mut chan,
                RefusalReason::Declined,
                "the person on the running app declined",
            );
            return Err(match confirmed {
                Err(e) => e,
                _ => Error::Declined,
            });
        }

        // Wrap first, so a receiving key that cannot be used writes nothing.
        let irk_id = identity.irk_id()?;
        let mut envelope = keys::wrap_to_peer(
            identity.irk().expose(),
            &device.kem_pub,
            KeyRef::new(KeyRefKind::Peer, device.device_id),
            &keys::aad(profile_id, None, irk_id, Purpose::Irk),
        )
        .inspect_err(|e| {
            let _ = refuse(&mut chan, RefusalReason::BadRequest, &e.to_string());
        })?;
        envelope.sign(identity.isk())?;
        let mut record = device.clone();
        record.enrolled_at = Timestamp::now();
        record.sign(identity.isk())?;
        identity.add_device(record.clone())?;
        let head = identity.head();
        send(
            &mut chan,
            &Message::Granted(Grant {
                v: HANDSHAKE_V,
                envelope,
                head,
            }),
        )?;
        Ok(Enrolled {
            device_id: record.device_id,
            device_name: record.name,
            app: peer.app,
            sas,
            head,
        })
    }
}

/// The new app's side.
pub struct Requester<'a> {
    app: &'a str,
    device_name: &'a str,
    keystore: &'a dyn DeviceKeystore,
    verifier: &'a dyn PeerVerifier,
    options: HandshakeOptions,
}

impl fmt::Debug for Requester<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Requester")
            .field("app", &self.app)
            .field("device_name", &self.device_name)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl<'a> Requester<'a> {
    /// A requester for `app` on the device `keystore` describes, named
    /// `device_name` in the store, checking the running app with `verifier`.
    pub fn new(
        app: &'a str,
        device_name: &'a str,
        keystore: &'a dyn DeviceKeystore,
        verifier: &'a dyn PeerVerifier,
        options: HandshakeOptions,
    ) -> Self {
        Self {
            app,
            device_name,
            keystore,
            verifier,
            options,
        }
    }

    /// Runs the handshake against the identity at `root` and attaches to
    /// it. `show` is called once with the code to display beside the words
    /// "confirm this on the other app". On success this device is enrolled
    /// and the identity is open.
    pub fn run<T: PeerTransport>(
        &self,
        root: &Path,
        transport: &T,
        show: &mut dyn FnMut(Sas),
    ) -> Result<Identity> {
        let timeout = self.options.timeout;
        // Step 2 of §6: the records are readable before any key is.
        let loaded = Store::at(root).load()?;
        let profile = loaded.contents.profile()?.clone();
        let isk_pub = VerifyingKey::from_bytes(&profile.isk_pub)
            .map_err(|_| Error::BadSignature("profile (its signing key is malformed)".into()))?;

        let mut chan = transport.connect(timeout)?;
        self.verifier.verify(&chan.peer())?;

        let hello = match recv(&mut chan, timeout)? {
            Message::Hello(h) => h,
            Message::Refused(r) => return Err(r.into_error()),
            other => {
                return Err(Error::Handshake(format!(
                    "expected the running app's hello, got {}",
                    other.name()
                )));
            }
        };
        if hello.v != HANDSHAKE_V {
            return Err(Error::Handshake(format!(
                "the running app speaks handshake version {}, which this app doesn't",
                hello.v
            )));
        }
        if hello.profile_id != profile.profile_id {
            return Err(Error::Handshake(
                "the running app holds a different identity than the one on disk".into(),
            ));
        }
        match loaded.contents.devices.get(&hello.device_id) {
            Some(d) if d.revoked_at.is_none() && d.kem_pub == hello.kem_pub => {}
            _ => {
                return Err(Error::Handshake(
                    "the running app isn't an enrolled device of this identity".into(),
                ));
            }
        }

        let nonce = random_32()?;
        let device = Device {
            v: RECORD_V,
            device_id: self.keystore.device_id(),
            name: self.device_name.to_string(),
            platform: self.keystore.platform(),
            attestation: self.keystore.attestation(),
            device_pub: self.keystore.device_pub(),
            kem_pub: self.keystore.kem_pub(),
            enrolled_at: Timestamp::now(),
            enrolled_by: EnrolledBy::Device {
                id: hello.device_id,
            },
            revoked_at: None,
            extra: Default::default(),
            sig: Vec::new(),
        };
        let pop = proof_of_possession(
            self.keystore,
            profile.profile_id,
            &hello.commit,
            &nonce,
            &device,
        )?;
        send(
            &mut chan,
            &Message::Request(Request {
                v: HANDSHAKE_V,
                device: device.clone(),
                nonce,
                pop,
            }),
        )?;

        let reveal = match recv(&mut chan, timeout)? {
            Message::Reveal(r) => r,
            Message::Refused(r) => return Err(r.into_error()),
            other => {
                return Err(Error::Handshake(format!(
                    "expected the running app's nonce, got {}",
                    other.name()
                )));
            }
        };
        if commitment(&reveal.nonce) != hello.commit {
            return Err(Error::Handshake(
                "the running app revealed a nonce it hadn't committed to".into(),
            ));
        }
        let sas = Sas(short_authentication_string(
            &nonce,
            &reveal.nonce,
            &device.kem_pub,
            &hello.kem_pub,
        ));
        show(sas);

        let grant = match recv(&mut chan, self.options.confirm_timeout)? {
            Message::Granted(g) => g,
            Message::Refused(r) => return Err(r.into_error()),
            other => {
                return Err(Error::Handshake(format!(
                    "expected the running app's answer, got {}",
                    other.name()
                )));
            }
        };
        drop(chan);

        let envelope = grant.envelope;
        envelope.verify(&isk_pub)?;
        if envelope.purpose != Purpose::Irk
            || envelope.wrapped_by != KeyRef::new(KeyRefKind::Peer, device.device_id)
        {
            return Err(Error::Handshake(
                "the running app sent an envelope that isn't the root key for this device".into(),
            ));
        }
        let irk: Irk = keys::unwrap_key_from_peer(
            &envelope,
            &self.keystore.kem_secret()?,
            &keys::aad(profile.profile_id, None, envelope.key_id, Purpose::Irk),
        )?;
        if signing_key(&irk)?.verifying_key() != isk_pub {
            return Err(Error::BadSignature(
                "profile (the root key handed over doesn't derive its signing key)".into(),
            ));
        }
        Identity::finish_enrolment(
            root,
            self.app,
            self.keystore,
            irk,
            envelope.key_id,
            grant.head,
        )
    }
}

/// Signs the request transcript with the device key, proving the requester
/// holds the private half of the `device_pub` it sends.
pub fn proof_of_possession(
    keystore: &dyn DeviceKeystore,
    profile_id: Id,
    commit: &[u8; 32],
    nonce: &[u8; 32],
    device: &Device,
) -> Result<Vec<u8>> {
    let message = proof_of_possession_message(profile_id, commit, nonce, device)?;
    Ok(keystore.sign(&message)?.to_vec())
}

fn check_proof_of_possession(
    request: &Request,
    profile_id: Id,
    commit: &[u8; 32],
) -> std::result::Result<(), String> {
    let key = VerifyingKey::from_bytes(&request.device.device_pub)
        .map_err(|_| "the device's signing key is malformed".to_string())?;
    let sig = Signature::from_slice(&request.pop)
        .map_err(|_| "the proof of possession is malformed".to_string())?;
    let message = proof_of_possession_message(profile_id, commit, &request.nonce, &request.device)
        .map_err(|e| e.to_string())?;
    key.verify(&message, &sig)
        .map_err(|_| "the request isn't signed by the device key it names".to_string())
}

fn check_proposed_device(device: &Device, responder: Id) -> std::result::Result<(), String> {
    if device.v != RECORD_V {
        return Err(format!(
            "device record version {} isn't one this app writes",
            device.v
        ));
    }
    if !device.sig.is_empty() {
        return Err("the proposed device record must be unsigned".into());
    }
    if device.revoked_at.is_some() {
        return Err("the proposed device record is already revoked".into());
    }
    if device.enrolled_by != (EnrolledBy::Device { id: responder }) {
        return Err("the proposed device record must name this device as its enroller".into());
    }
    if device.name.trim().is_empty() {
        return Err("the new device needs a name".into());
    }
    Ok(())
}

fn send(chan: &mut dyn PeerChannel, message: &Message) -> Result<()> {
    chan.send(&message.to_bytes()?)
}

fn recv(chan: &mut dyn PeerChannel, timeout: Duration) -> Result<Message> {
    Message::from_bytes(&chan.recv(timeout)?)
}

fn refuse(chan: &mut dyn PeerChannel, reason: RefusalReason, detail: &str) -> Result<()> {
    send(
        chan,
        &Message::Refused(Refusal {
            v: HANDSHAKE_V,
            reason,
            detail: detail.to_string(),
        }),
    )
}

fn bad_request(chan: &mut dyn PeerChannel, why: String) -> Error {
    let _ = refuse(chan, RefusalReason::BadRequest, &why);
    Error::Handshake(why)
}

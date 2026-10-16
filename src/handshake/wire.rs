//! What goes over the local channel (spec §6 step 3): the framing and the
//! four messages, in the order they are sent.
//!
//! ```text
//! running app (responder)                    new app (requester)
//!   Hello { profile, device, kem_pub, commit } ─▶
//!                                         ◀─ Request { device, nonce, pop }
//!   Reveal { nonce } ────────────────────────▶   both show the 6-digit code
//!   Granted { envelope, head } | Refused ────▶
//! ```
//!
//! The responder commits to its nonce before it sees the requester's and
//! reveals it after, so neither side can steer the short authentication
//! string once it knows the other's input. Every message is canonical CBOR
//! in one length-prefixed frame.

use std::io::{Read, Write};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kem::KemPublicKey;
use crate::records::{Device, Id, KeyEnvelope};
use crate::store::Head;
use crate::{Error, Result};

/// The handshake protocol version. A side that sees a higher one refuses.
pub const HANDSHAKE_V: u16 = 1;

/// The largest frame either side accepts: generous for a `Device` with a
/// hybrid public key plus an envelope, and small enough to refuse a flood.
pub const MAX_FRAME: usize = 64 * 1024;

const COMMIT_INFO: &[u8] = b"ecosystem-identity/handshake/v1/commit";
const POP_INFO: &[u8] = b"ecosystem-identity/handshake/v1/request";
const SAS_INFO: &[u8] = b"ecosystem-identity/handshake/v1/sas";

/// First message, from the running app: which identity it holds, which of
/// its devices is speaking, that device's receiving key, and a commitment
/// to the nonce it will reveal later.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Hello {
    /// Protocol version.
    pub v: u16,
    /// The profile the running app holds open.
    pub profile_id: Id,
    /// The running app's device (an enrolled device of that profile).
    pub device_id: Id,
    /// That device's receiving key, as its `Device` record publishes it.
    pub kem_pub: KemPublicKey,
    /// SHA-256 over a label and the responder's nonce.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub commit: [u8; 32],
}

/// Second message, from the new app: the device it wants enrolled, a fresh
/// nonce, and proof that it holds that device's signing key.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Request {
    /// Protocol version.
    pub v: u16,
    /// The new device's record as the requester proposes it: `enrolled_by`
    /// names the responder's device, `sig` is empty. The responder sets
    /// `enrolled_at` and signs.
    pub device: Device,
    /// 32 random bytes. Seen once; a repeat is refused.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub nonce: [u8; 32],
    /// Ed25519 signature by the device key over the request transcript
    /// (see [`proof_of_possession_message`]).
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub pop: Vec<u8>,
}

/// Third message, from the running app: the nonce it committed to.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Reveal {
    /// Protocol version.
    pub v: u16,
    /// The responder's nonce.
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub nonce: [u8; 32],
}

/// Last message when the person said yes: the root key wrapped to the new
/// device's receiving key, and the store head after the device was added.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Grant {
    /// Protocol version.
    pub v: u16,
    /// The IRK, `wrapped_by: peer.<new device id>`, `purpose: irk`, signed
    /// by the ISK. Not stored; the new device writes its own `device` wrap.
    pub envelope: KeyEnvelope,
    /// The manifest head the responder wrote. The requester refuses a store
    /// behind it.
    pub head: Head,
}

/// Why a side stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    /// The peer could not be shown to be an ecosystem app.
    Untrusted,
    /// The person said no.
    Declined,
    /// The request's nonce was seen before.
    Replayed,
    /// The device is already enrolled.
    AlreadyEnrolled,
    /// The message was malformed, out of order, or failed a check.
    BadRequest,
}

/// Last message when something stopped the handshake.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Refusal {
    /// Protocol version.
    pub v: u16,
    /// Why.
    pub reason: RefusalReason,
    /// A sentence for the person, in plain words.
    pub detail: String,
}

/// Any message on the channel.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Message {
    /// Responder → requester, first.
    Hello(Hello),
    /// Requester → responder.
    Request(Request),
    /// Responder → requester.
    Reveal(Reveal),
    /// Responder → requester, last, on success.
    Granted(Grant),
    /// Either side, last, on failure.
    Refused(Refusal),
}

impl Message {
    /// As canonical CBOR (the frame's payload).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        crate::cbor::to_canonical(self)
    }

    /// From a frame's payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        crate::cbor::from_slice(bytes)
            .map_err(|e| Error::Handshake(format!("the other app sent something unreadable ({e})")))
    }

    /// The name of the message, for errors.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::Request(_) => "request",
            Self::Reveal(_) => "reveal",
            Self::Granted(_) => "granted",
            Self::Refused(_) => "refused",
        }
    }
}

impl Refusal {
    /// The error a side reports when it receives this.
    pub fn into_error(self) -> Error {
        match self.reason {
            RefusalReason::Untrusted => Error::PeerUntrusted(self.detail),
            RefusalReason::Declined => Error::Declined,
            RefusalReason::Replayed => Error::Replayed,
            RefusalReason::AlreadyEnrolled | RefusalReason::BadRequest => {
                Error::Handshake(self.detail)
            }
        }
    }
}

/// The commitment the responder sends in `Hello` for the nonce it reveals
/// later: SHA-256 over a fixed label and the nonce.
pub fn commitment(nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_INFO);
    h.update(nonce);
    h.finalize().into()
}

/// The bytes the requester's device key signs: a label, the profile, the
/// responder's commitment, the requester's nonce, and the proposed device
/// record (with `sig` empty). Binding the commitment ties the proof to this
/// one conversation.
pub fn proof_of_possession_message(
    profile_id: Id,
    commit: &[u8; 32],
    nonce: &[u8; 32],
    device: &Device,
) -> Result<Vec<u8>> {
    use crate::records::Record;
    let record = device.signed_bytes()?;
    let mut out = Vec::with_capacity(POP_INFO.len() + 16 + 64 + record.len());
    out.extend_from_slice(POP_INFO);
    out.extend_from_slice(profile_id.as_bytes());
    out.extend_from_slice(commit);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&record);
    Ok(out)
}

/// The short authentication string both sides show (spec §8): six digits
/// from SHA-256 over both nonces and both receiving keys. Either side can
/// compute it once the responder's nonce is revealed.
pub fn short_authentication_string(
    requester_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
    requester_kem_pub: &KemPublicKey,
    responder_kem_pub: &KemPublicKey,
) -> u32 {
    let mut h = Sha256::new();
    h.update(SAS_INFO);
    h.update(requester_nonce);
    h.update(responder_nonce);
    for key in [requester_kem_pub, responder_kem_pub] {
        h.update(
            u32::try_from(key.bytes.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        h.update(&key.bytes);
    }
    let digest = h.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000
}

/// A frame: a 4-byte big-endian length, then that many bytes of payload.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_FRAME {
        return Err(Error::Handshake(format!(
            "a message of {} bytes is larger than the channel allows",
            payload.len()
        )));
    }
    let len =
        u32::try_from(payload.len()).map_err(|_| Error::Handshake("message too large".into()))?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Splits one complete frame back into its payload.
pub fn decode_frame(frame: &[u8]) -> Result<Vec<u8>> {
    let (head, body) = frame
        .split_at_checked(4)
        .ok_or_else(|| Error::Handshake("a frame was shorter than its length prefix".into()))?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    if len > MAX_FRAME || body.len() != len {
        return Err(Error::Handshake(
            "a frame's length prefix doesn't match its contents".into(),
        ));
    }
    Ok(body.to_vec())
}

/// Writes one frame to a byte stream.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let frame = encode_frame(payload)?;
    writer.write_all(&frame).map_err(io_error)?;
    writer.flush().map_err(io_error)
}

/// Reads one frame from a byte stream. A read that times out becomes
/// [`Error::Timeout`]; a closed stream becomes [`Error::Handshake`].
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).map_err(io_error)?;
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME {
        return Err(Error::Handshake(format!(
            "the other app announced a {len}-byte message, larger than the channel allows"
        )));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(io_error)?;
    Ok(body)
}

fn io_error(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::Timeout,
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionReset => {
            Error::Handshake("the other app closed the channel".into())
        }
        _ => Error::Io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_refuse_oversize() {
        let payload = b"hello".to_vec();
        let frame = encode_frame(&payload).unwrap();
        assert_eq!(&frame[..4], &[0, 0, 0, 5]);
        assert_eq!(decode_frame(&frame).unwrap(), payload);
        let mut cursor = std::io::Cursor::new(Vec::new());
        write_frame(&mut cursor, &payload).unwrap();
        cursor.set_position(0);
        assert_eq!(read_frame(&mut cursor).unwrap(), payload);
        assert!(matches!(
            encode_frame(&vec![0; MAX_FRAME + 1]),
            Err(Error::Handshake(_))
        ));
        let mut huge = std::io::Cursor::new((MAX_FRAME as u32 + 1).to_be_bytes().to_vec());
        assert!(matches!(read_frame(&mut huge), Err(Error::Handshake(_))));
        let mut short = std::io::Cursor::new(vec![0, 0, 0, 9, 1]);
        assert!(matches!(read_frame(&mut short), Err(Error::Handshake(_))));
    }

    #[test]
    fn the_short_string_is_six_digits_and_depends_on_every_input() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let k1 = KemPublicKey {
            alg: crate::kem::KemAlg::X25519,
            bytes: vec![3; 32],
        };
        let k2 = KemPublicKey {
            alg: crate::kem::KemAlg::X25519,
            bytes: vec![4; 32],
        };
        let s = short_authentication_string(&a, &b, &k1, &k2);
        assert!(s < 1_000_000);
        assert_ne!(s, short_authentication_string(&b, &a, &k1, &k2));
        assert_ne!(s, short_authentication_string(&a, &b, &k2, &k1));
        assert_ne!(s, short_authentication_string(&a, &a, &k1, &k2));
        assert_ne!(commitment(&a), commitment(&b));
    }
}

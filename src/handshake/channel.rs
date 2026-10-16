//! An in-memory transport for tests and for two halves of one process: the
//! same framing as a socket, no operating system in between.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::wire::{decode_frame, encode_frame};
use super::{PeerChannel, PeerIdentity, PeerTransport};
use crate::{Error, Result};

struct Ends {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

struct Inner {
    pending: Mutex<Receiver<Ends>>,
    connector: Sender<Ends>,
}

/// A transport whose two ends live in one process. Clone it: every clone
/// shares the same listening side, so one clone can `accept` what another
/// `connect`s. Frames go through the same length-prefixed encoding a socket
/// would carry.
#[derive(Clone)]
pub struct ChannelTransport {
    inner: Arc<Inner>,
}

impl Default for ChannelTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelTransport {
    /// A fresh transport with nobody connected.
    pub fn new() -> Self {
        let (connector, pending) = mpsc::channel();
        Self {
            inner: Arc::new(Inner {
                pending: Mutex::new(pending),
                connector,
            }),
        }
    }
}

impl std::fmt::Debug for ChannelTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelTransport")
    }
}

/// One end of an in-memory connection.
pub struct InMemoryChannel {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl std::fmt::Debug for InMemoryChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InMemoryChannel")
    }
}

impl PeerTransport for ChannelTransport {
    type Channel = InMemoryChannel;

    fn connect(&self, _timeout: Duration) -> Result<InMemoryChannel> {
        let (to_server, server_rx) = mpsc::channel();
        let (to_client, client_rx) = mpsc::channel();
        self.inner
            .connector
            .send(Ends {
                tx: to_client,
                rx: server_rx,
            })
            .map_err(|_| Error::Handshake("nobody is listening".into()))?;
        Ok(InMemoryChannel {
            tx: to_server,
            rx: client_rx,
        })
    }

    fn accept(&self, timeout: Duration) -> Result<InMemoryChannel> {
        let pending = self
            .inner
            .pending
            .lock()
            .map_err(|_| Error::Handshake("the in-memory listener is poisoned".into()))?;
        match pending.recv_timeout(timeout) {
            Ok(ends) => Ok(InMemoryChannel {
                tx: ends.tx,
                rx: ends.rx,
            }),
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                Err(Error::Handshake("the in-memory listener is gone".into()))
            }
        }
    }
}

impl PeerChannel for InMemoryChannel {
    fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.tx
            .send(encode_frame(payload)?)
            .map_err(|_| Error::Handshake("the other app closed the channel".into()))
    }

    fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        match self.rx.recv_timeout(timeout) {
            Ok(frame) => decode_frame(&frame),
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                Err(Error::Handshake("the other app closed the channel".into()))
            }
        }
    }

    fn peer(&self) -> PeerIdentity {
        PeerIdentity::InProcess
    }
}
